"""B1 Docker proof entrypoint; deliberately has no live credential resolver."""

from __future__ import annotations

import os
from http.server import ThreadingHTTPServer
from pathlib import Path

from agentguard.evaluation.stage1_live_session import LiveMeteringSession
from agentguard.evaluation.stage1_live_transport import LocalTestTLSTransport
from agentguard.evaluation.stage1_metering import MeteringError, parse_json
from agentguard.evaluation.stage1_metering_gateway import handler_for
from agentguard.evaluation.stage1_study_ledger import LedgerScope, StudyLedger


def main() -> None:
    if os.environ.get("STAGE1_B1_MOCK_ONLY") != "true":
        raise SystemExit("B1 gateway has no live execution mode")
    config = parse_json(Path("/stage1-config/config.json").read_bytes())
    if set(config) != {"scope", "output_cap"} or not isinstance(config["scope"], dict):
        raise SystemExit("B1 mock configuration is malformed")
    if not isinstance(config["scope"].get("trial_ids"), list):
        raise SystemExit("B1 mock trial set is malformed")
    config["scope"]["trial_ids"] = tuple(config["scope"]["trial_ids"])
    scope = LedgerScope(**config["scope"])
    if scope.trial_ids != (
        "docker-mock-trial", "docker-contender-a", "docker-contender-b",
    ):
        raise SystemExit("B1 mock trial set differs")
    output_cap = config["output_cap"]
    if type(output_cap) is not int or not 0 < output_cap <= 4096:
        raise SystemExit("B1 mock output cap differs")
    evidence = Path("/stage1-metering/evidence.json")
    if evidence.exists():
        raise SystemExit("stale B1 evidence is forbidden")
    token = os.environ.get("STAGE1_B1_SYNTHETIC_TOKEN", "")
    fake_upstream = os.environ.get("STAGE1_B1_FAKE_UPSTREAM_TOKEN", "")
    if not token or not fake_upstream or token == fake_upstream:
        raise SystemExit("B1 mock tokens are missing or confused")
    ledger = StudyLedger(Path("/stage1-ledger"), scope)
    session = LiveMeteringSession(
        ledger, scope.trial_ids[0], token, fake_upstream,
        LocalTestTLSTransport("/stage1-config/ca.pem", 8443, docker_alias=True),
        output_cap,
    )
    try:
        server = ThreadingHTTPServer(("0.0.0.0", 8080), handler_for(session, evidence))
        server.serve_forever(poll_interval=0.1)
    except MeteringError as error:
        raise SystemExit("B1 mock gateway rejected its configuration") from error


if __name__ == "__main__":
    main()
