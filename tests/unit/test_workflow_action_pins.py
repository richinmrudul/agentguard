from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_WORKFLOWS = tuple(sorted((ROOT / ".github/workflows").glob("*.yml")))
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/publish.yml"
EXAMPLE_WORKFLOWS = tuple(
    sorted((ROOT / "examples/github-actions").glob("*.yml"))
)
ACTION_DOCUMENTATION = (
    ROOT / "docs/action.md",
    ROOT / "docs/ci-exports.md",
    ROOT / "docs/github-actions.md",
    ROOT / "docs/project-initialization.md",
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REMOTE_USES_LINE = re.compile(
    r"uses:\s*[\"']?(?P<action>[^\"'\s#]+)[\"']?(?:\s+#\s*(?P<comment>\S.*))?"
)
MARKDOWN_YAML_BLOCK = re.compile(
    r"```ya?ml\n(?P<source>.*?)\n```",
    re.S,
)
PINNED_RELEASES = {
    "actions/checkout": (
        "93cb6efe18208431cddfb8368fd83d5badbf9bfd",
        "v5.0.1",
    ),
    "actions/setup-python": (
        "a309ff8b426b58ec0e2a45f0f869d46889d02405",
        "v6.2.0",
    ),
    "actions/setup-node": (
        "249970729cb0ef3589644e2896645e5dc5ba9c38",
        "v6.5.0",
    ),
    "actions/setup-go": (
        "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "v7.0.0",
    ),
    "actions/upload-artifact": (
        "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        "v6.0.0",
    ),
    "actions/download-artifact": (
        "37930b1c2abaa49bbe596cd826c3c89aef350131",
        "v7.0.0",
    ),
    "github/codeql-action/upload-sarif": (
        "6f5948dfacef28e207b48d0905cf90c03365536d",
        "v3",
    ),
    "actions/configure-pages": (
        "45bfe0192ca1faeb007ade9deae92b16b8254a0d",
        "v6.0.0",
    ),
    "actions/upload-pages-artifact": (
        "fc324d3547104276b827a68afc52ff2a11cc49c9",
        "v5.0.0",
    ),
    "actions/deploy-pages": (
        "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128",
        "v5.0.0",
    ),
}
SUPERSEDED_REFS = {
    "actions/checkout@v4",
    "actions/setup-python@v5",
    "actions/upload-artifact@v4",
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "github/codeql-action/upload-sarif@v3",
    "richinmrudul/agentguard/action@main",
}


def _workflow(path: Path) -> dict[str, Any]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _action_documentation_workflow_source() -> str:
    source = (ROOT / "docs/action.md").read_text(encoding="utf-8")
    match = re.search(
        r"```yaml\n(?P<workflow>name: AgentGuard\n.*?)\n```",
        source,
        re.S,
    )
    assert match is not None
    return match.group("workflow")


def _action_documentation_workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(_action_documentation_workflow_source())
    assert isinstance(workflow, dict)
    return workflow


def _maintained_yaml_paths() -> tuple[Path, ...]:
    roots = (
        ROOT / ".github/workflows",
        ROOT / "examples/github-actions",
    )
    return tuple(
        sorted(
            path
            for root in roots
            for pattern in ("*.yml", "*.yaml")
            for path in root.glob(pattern)
        )
    )


def _copyable_markdown_paths() -> tuple[Path, ...]:
    return tuple(
        sorted(
            [
                ROOT / "README.md",
                *list((ROOT / "docs").glob("*.md")),
                *list((ROOT / "examples").glob("**/*.md")),
            ]
        )
    )


def _copyable_content_paths() -> tuple[Path, ...]:
    return (*_maintained_yaml_paths(), *_copyable_markdown_paths())


def _is_local_action(action: str) -> bool:
    return action.startswith(("./", "../"))


def _remote_action_parts(action: str) -> tuple[str, str] | None:
    if _is_local_action(action) or "@" not in action:
        return None
    repository, ref = action.rsplit("@", 1)
    if "/" not in repository or repository.startswith("docker://"):
        return None
    return repository, ref


def _uses_lines(path: Path) -> list[tuple[int, str, str | None]]:
    lines = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = REMOTE_USES_LINE.search(line)
        if match is not None:
            lines.append((lineno, match.group("action"), match.group("comment")))
    return lines


def _markdown_yaml_blocks(path: Path) -> list[str]:
    return [
        match.group("source")
        for match in MARKDOWN_YAML_BLOCK.finditer(path.read_text(encoding="utf-8"))
        if "uses:" in match.group("source")
    ]


def _assert_least_privilege_action_documentation_workflow(
    workflow: dict[str, Any],
) -> None:
    permissions = workflow.get("permissions")
    assert isinstance(permissions, dict), "docs/action.md must declare permissions"
    assert permissions == {"contents": "read"}

    forbidden_write_scopes = {"contents", "id-token", "security-events"}
    for scope, access in permissions.items():
        assert access == "read", f"{scope} grants {access}"
        assert scope not in forbidden_write_scopes or access != "write"


def _uses(workflow: dict[str, Any]) -> list[str]:
    return [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if isinstance(step, dict) and "uses" in step
    ]


def test_active_workflows_pin_every_action_to_a_full_sha() -> None:
    for path in ACTIVE_WORKFLOWS:
        for action in _uses(_workflow(path)):
            repository, ref = action.rsplit("@", 1)
            assert "/" in repository
            assert FULL_SHA.fullmatch(ref), f"{path}: {action}"


def test_copyable_workflow_action_references_are_immutable_and_documented() -> None:
    for path in _copyable_content_paths():
        for lineno, action, comment in _uses_lines(path):
            parts = _remote_action_parts(action)
            if parts is None:
                continue
            repository, ref = parts
            assert FULL_SHA.fullmatch(ref), f"{path}:{lineno}: {action}"
            assert comment, f"{path}:{lineno}: {repository} pin needs a comment"


def test_local_actions_are_not_treated_as_remote_pins() -> None:
    assert _remote_action_parts("./action") is None
    assert _remote_action_parts("../actions/build") is None
    assert _remote_action_parts("actions/checkout@v5") == (
        "actions/checkout",
        "v5",
    )


def test_affected_action_comments_match_verified_stable_releases() -> None:
    for path in (*ACTIVE_WORKFLOWS, *EXAMPLE_WORKFLOWS, *ACTION_DOCUMENTATION):
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            match = re.search(r"uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(\S+)", line)
            if match is None or match.group(1) not in PINNED_RELEASES:
                continue
            expected_sha, expected_version = PINNED_RELEASES[match.group(1)]
            assert (match.group(2), match.group(3)) == (
                expected_sha,
                expected_version,
            )


def test_markdown_workflow_snippets_parse_as_yaml() -> None:
    for path in _copyable_markdown_paths():
        for source in _markdown_yaml_blocks(path):
            parsed = yaml.safe_load(source)
            assert parsed is not None, f"{path} has an empty workflow snippet"


def test_deprecated_node20_action_references_are_absent_from_workflows() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in _copyable_content_paths()
    )
    for reference in SUPERSEDED_REFS:
        assert reference not in sources


def test_active_workflow_triggers_and_validation_modes_are_unchanged() -> None:
    ci = _workflow(CI_WORKFLOW)
    publish = _workflow(PUBLISH_WORKFLOW)
    ci_triggers = ci.get("on", ci.get(True))
    publish_triggers = publish.get("on", publish.get(True))

    assert ci_triggers == {"push": None, "pull_request": None}
    assert publish_triggers == {"release": {"types": ["published"]}}
    assert "--ordinary-ci" in str(ci["jobs"]["package"])
    assert "--strict-release-tag" not in str(ci["jobs"]["package"])
    assert "--strict-release-tag" in str(publish["jobs"]["build"])
    assert "--ordinary-ci" not in str(publish)


def test_action_documentation_workflow_parses_with_read_only_permissions() -> None:
    workflow = _action_documentation_workflow()

    triggers = workflow.get("on", workflow.get(True))
    assert triggers == {"pull_request": None, "push": None}
    _assert_least_privilege_action_documentation_workflow(workflow)


def test_action_documentation_workflow_rejects_omitted_broad_or_write_permissions() -> None:
    workflow = _action_documentation_workflow()

    omitted = dict(workflow)
    omitted.pop("permissions")
    try:
        _assert_least_privilege_action_documentation_workflow(omitted)
    except AssertionError:
        pass
    else:
        raise AssertionError("omitted permissions should be rejected")

    for permissions in (
        "read-all",
        "write-all",
        {"contents": "read", "actions": "read"},
        {"contents": "write"},
        {"contents": "read", "id-token": "write"},
        {"contents": "read", "security-events": "write"},
        {"contents": "read", "actions": "write"},
    ):
        mutated = dict(workflow)
        mutated["permissions"] = permissions
        try:
            _assert_least_privilege_action_documentation_workflow(mutated)
        except AssertionError:
            continue
        raise AssertionError(
            f"broad or write-capable permissions accepted: {permissions}"
        )


def test_action_documentation_workflow_preserves_checkout_and_command_sequence() -> None:
    workflow = _action_documentation_workflow()
    steps = workflow["jobs"]["agentguard"]["steps"]

    checkout, setup_python, install, agentguard = steps
    assert checkout["uses"] == (
        "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
    )
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    assert setup_python["uses"] == (
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
    )
    assert setup_python["with"]["python-version"] == "3.11"
    assert install["name"] == "Install AgentGuard"
    assert install["run"] == 'python -m pip install -e ".[dev]"'
    assert agentguard["uses"] == (
        "richinmrudul/agentguard/action@"
        "5e93b179f8add85bd4e8d5fa330f97ae1212c109"
    )
    assert agentguard["with"] == {
        "config": "agentguard.yaml",
        "base": "origin/main",
        "head": "HEAD",
        "github-summary": "true",
    }


def test_action_documentation_uses_reviewed_agentguard_source_revision() -> None:
    action_ref = _action_documentation_workflow()["jobs"]["agentguard"]["steps"][3][
        "uses"
    ]
    repository, ref = action_ref.rsplit("@", 1)

    assert repository == "richinmrudul/agentguard/action"
    assert ref == "5e93b179f8add85bd4e8d5fa330f97ae1212c109"
    assert FULL_SHA.fullmatch(ref)
    assert (
        ROOT / "docs/action.md"
    ).read_text(encoding="utf-8").count("automated Action updates") == 1
    assert _git_commit_contains_path(ref, "action/action.yml")


def _git_commit_contains_path(commit: str, path: str) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}:{path}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def test_publication_permissions_and_artifact_handoff_are_unchanged() -> None:
    publish = _workflow(PUBLISH_WORKFLOW)
    build = publish["jobs"]["build"]
    publication = publish["jobs"]["publish"]

    assert publish["permissions"] == {"contents": "read"}
    assert build["permissions"] == {"contents": "read"}
    assert publication["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert publication["environment"]["name"] == "pypi"
    assert publication["needs"] == "build"
    assert sum("build_release.sh" in str(step) for step in build["steps"]) == 1
    assert not any("build_release.sh" in str(step) for step in publication["steps"])

    upload = next(
        step for step in build["steps"] if step.get("uses", "").startswith(
            "actions/upload-artifact@"
        )
    )
    download = next(
        step for step in publication["steps"] if step.get("uses", "").startswith(
            "actions/download-artifact@"
        )
    )
    assert upload["with"]["name"] == download["with"]["name"]
