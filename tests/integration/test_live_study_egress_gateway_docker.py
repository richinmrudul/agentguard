import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Optional

import pytest

from agentguard.evaluation.live_egress_gateway import (
    EgressDestinationRule,
    LiveStudyEgressPolicy,
    LiveStudyEgressTrialRequest,
    build_live_study_egress_docker_plan,
    run_live_study_egress_docker_plan,
    run_live_study_egress_trial,
)
from agentguard.sandbox.docker_runner import docker_available


PLAN_DIGEST = "1" * 64
PROFILE_HASH = "2" * 64
FIXTURE_HASH = "3" * 64
TRIAL_ID = "trial-0123456789abcdef01234567"
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY_302"


def _run(
    argv: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 90,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _require_docker_and_compiler() -> None:
    if not docker_available():
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Docker is required for live study-egress gateway integration coverage")
        pytest.skip("Docker is not available")
    version = _run(["docker", "version", "--format", "{{json .}}"])
    assert version.returncode == 0, version.stderr
    print("live-study-egress docker version:", version.stdout.strip())
    if shutil.which("cc") is None:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("A C compiler is required to build local mock egress images")
        pytest.skip("C compiler is not available")


def _build_image(tmp_path: Path, *, name: str, source: str, binary: str) -> str:
    context = tmp_path / name
    context.mkdir()
    source_path = context / f"{name}.c"
    binary_path = context / binary.lstrip("/")
    source_path.write_text(textwrap.dedent(source), encoding="utf-8")
    compile_result = _run(
        ["cc", "-static", "-O2", "-s", "-o", str(binary_path), str(source_path)],
        timeout=90,
    )
    if compile_result.returncode != 0:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("Failed to compile static local mock image binary: " + compile_result.stderr)
        pytest.skip("Static local mock image compilation is unavailable")
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        f"FROM scratch\nCOPY {binary_path.name} {binary}\nENTRYPOINT [\"{binary}\"]\n",
        encoding="utf-8",
    )
    tag = f"agentguard-local-{name}:issue-302"
    build = _run(["docker", "build", "--network", "none", "-q", "-t", tag, "."], cwd=context)
    assert build.returncode == 0, build.stderr
    image_id = build.stdout.strip().splitlines()[-1]
    assert image_id.startswith("sha256:"), image_id
    inspect = _run(["docker", "image", "inspect", image_id])
    assert inspect.returncode == 0, inspect.stderr
    return image_id


def _gateway_source() -> str:
    return r'''
    #include <arpa/inet.h>
    #include <errno.h>
    #include <netinet/in.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <unistd.h>

    int main(int argc, char **argv) {
      const char *evidence = "/agentguard-egress/gateway-evidence.json";
      for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--crash") == 0) return 7;
        if (strcmp(argv[i], "--evidence") == 0 && i + 1 < argc) evidence = argv[++i];
      }
      int server = socket(AF_INET, SOCK_STREAM, 0);
      if (server < 0) return 10;
      int one = 1;
      setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      struct sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_ANY);
      addr.sin_port = htons(8080);
      if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 11;
      if (listen(server, 1) != 0) return 12;
      int client = accept(server, NULL, NULL);
      if (client >= 0) {
        char buffer[512];
        (void)read(client, buffer, sizeof(buffer));
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        (void)write(client, response, strlen(response));
        close(client);
      }
      FILE *file = fopen(evidence, "w");
      if (!file) return 13;
      fputs("{\"gateway_status\":{\"status\":\"running\",\"evidence_complete\":true},", file);
      fputs("\"events\":[{\"event_type\":\"request\",\"protocol\":\"https\",", file);
      fputs("\"requested\":{\"host\":\"mock-approved.test\",\"port\":443},", file);
      fputs("\"effective\":{\"host\":\"mock-approved.test\",\"port\":443},", file);
      fputs("\"resolved_addresses\":[\"203.0.113.10\"],", file);
      fputs("\"resolution_status\":\"stable\",\"decision\":\"allow\",", file);
      fputs("\"reason\":\"approved_destination\",\"bytes\":{\"in\":2,\"out\":2},", file);
      fputs("\"timestamps\":{\"start\":1.0,\"end\":2.0},", file);
      fputs("\"evidence_complete\":true,\"evidence_truncated\":false}]}\n", file);
      fclose(file);
      close(server);
      return 0;
    }
    '''


def _agent_source() -> str:
    return r'''
    #include <errno.h>
    #include <netdb.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <unistd.h>

    static int connect_host(const char *host, const char *port) {
      struct addrinfo hints;
      struct addrinfo *result = NULL;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      if (getaddrinfo(host, port, &hints, &result) != 0) return -1;
      int fd = -1;
      for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
      }
      freeaddrinfo(result);
      return fd;
    }

    int main(int argc, char **argv) {
      const char *mode = argc > 1 ? argv[1] : "proxy-success";
      const char *credential = getenv("AGENTGUARD_FAKE_API_KEY");
      if (strcmp(mode, "proxy-success") == 0 &&
          (!credential || strcmp(credential, "AGENTGUARD_FAKE_CREDENTIAL_CANARY_302") != 0)) {
        return 25;
      }
      int direct = connect_host("mock-approved.test", "443");
      if (direct >= 0) {
        close(direct);
        return 20;
      }
      if (strcmp(mode, "direct-bypass") == 0) return 0;
      int proxy = -1;
      for (int attempt = 0; attempt < 50; attempt++) {
        proxy = connect_host("agentguard-study-egress-gateway", "8080");
        if (proxy >= 0) break;
        usleep(100000);
      }
      if (proxy < 0) return 21;
      const char *request = "GET / HTTP/1.1\r\nHost: mock-approved.test\r\n\r\n";
      if (write(proxy, request, strlen(request)) < 0) return 22;
      char buffer[128];
      int count = read(proxy, buffer, sizeof(buffer));
      close(proxy);
      if (count <= 0) return 23;
      return strstr(buffer, "200 OK") == NULL ? 24 : 0;
    }
    '''


def _assert_owned_resources_removed(plan) -> None:
    for target in [
        plan.agent_container,
        plan.gateway_container,
        plan.internal_network,
        plan.outbound_network,
    ]:
        kind = "network" if target in {plan.internal_network, plan.outbound_network} else "container"
        inspect = _run(["docker", kind, "inspect", target])
        assert inspect.returncode != 0, json.dumps(
            {"target": target, "stdout": inspect.stdout, "stderr": inspect.stderr},
            sort_keys=True,
        )


@pytest.mark.docker
def test_live_study_egress_gateway_executes_local_mock_success_bypass_crash_and_cleanup(
    tmp_path: Path,
) -> None:
    _require_docker_and_compiler()
    gateway_image = _build_image(
        tmp_path,
        name="egress-gateway",
        source=_gateway_source(),
        binary="/agentguard-live-egress-gateway",
    )
    agent_image = _build_image(
        tmp_path,
        name="egress-agent",
        source=_agent_source(),
        binary="/agent",
    )
    workspace = tmp_path / "workspace"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    policy = LiveStudyEgressPolicy(
        destinations=(EgressDestinationRule("mock-approved.test", 443, test_only=True),)
    )

    result = run_live_study_egress_trial(
        LiveStudyEgressTrialRequest(
            plan_digest=PLAN_DIGEST,
            profile_hash=PROFILE_HASH,
            fixture_hash=FIXTURE_HASH,
            trial_id=TRIAL_ID,
            profile_id="mock-profile",
            fixture_id="mock-fixture",
            workspace=workspace,
            evidence_dir=evidence,
            prompt_path=evidence / "prompt.txt",
            agent_image=agent_image,
            agent_command=["proxy-success"],
            agent_environment={"AGENTGUARD_FAKE_API_KEY": CANARY},
            policy=policy,
            gateway_image=gateway_image,
            platform="linux-docker-engine",
            allow_local_image_id=True,
        )
    )

    assert result.status == "completed", json.dumps(result.manifest, sort_keys=True)
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["completion"]["success_eligible"] is True
    assert manifest["gateway_status"]["evidence_complete"] is True
    assert manifest["cleanup_status"]["overall_complete"] is True
    assert manifest["liveness_status"]["verified"] is True
    assert manifest["events"][0]["decision"] == "allow"
    serialized = json.dumps(manifest, sort_keys=True)
    assert CANARY not in serialized
    assert str(tmp_path) not in serialized

    bypass_plan = build_live_study_egress_docker_plan(
        trial_id=TRIAL_ID,
        agent_image=agent_image,
        gateway_image=gateway_image,
        workspace_host_path=workspace,
        agent_command=["direct-bypass"],
        gateway_command=["--serve"],
        uid=os.getuid() or 1000,
        gid=os.getgid() or 1000,
        run_token="abc123abc123",
        gateway_outbound_aliases=("mock-approved.test",),
        allow_local_image_id=True,
    )
    assert "--internal" in bypass_plan.commands["create_internal_network"]
    assert bypass_plan.outbound_network not in bypass_plan.commands["create_agent"]
    bypass = run_live_study_egress_docker_plan(bypass_plan)
    assert bypass["status"] == "completed", json.dumps(bypass, sort_keys=True)
    _assert_owned_resources_removed(bypass_plan)

    crash_plan = build_live_study_egress_docker_plan(
        trial_id=TRIAL_ID,
        agent_image=agent_image,
        gateway_image=gateway_image,
        workspace_host_path=workspace,
        agent_command=["direct-bypass"],
        gateway_command=["--crash"],
        uid=os.getuid() or 1000,
        gid=os.getgid() or 1000,
        run_token="def456def456",
        gateway_outbound_aliases=("mock-approved.test",),
        allow_local_image_id=True,
    )
    crash = run_live_study_egress_docker_plan(crash_plan)
    assert crash["status"] == "failed"
    assert crash["failure_step"] == "gateway_liveness"
    assert crash["cleanup"]["overall_complete"] is True
    _assert_owned_resources_removed(crash_plan)
