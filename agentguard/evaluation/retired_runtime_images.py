"""Fail-closed boundary for the retired Stage 1 byte-forwarding gateway."""

from __future__ import annotations

import json
from pathlib import Path


RETIRED_GATEWAY_REPOSITORY = "ghcr.io/richinmrudul/agentguard/stage1-gateway"
RETIRED_GATEWAY_DIGEST = "sha256:39256ba5b6c25c741c49fd65b964cb254b642a416d67e045db20899660178ede"


def is_retired_gateway_reference(value: str) -> bool:
    """Reject every tag and digest of the retired package, not only known subjects."""
    return isinstance(value, str) and (
        value == RETIRED_GATEWAY_REPOSITORY
        or value.startswith(RETIRED_GATEWAY_REPOSITORY + "@")
        or value.startswith(RETIRED_GATEWAY_REPOSITORY + ":")
    )


def validate_retirement_record(path: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("retired runtime record is missing or malformed") from error
    expected = {
        "schema": "agentguard.retired-runtime-subjects",
        "schema_version": 1,
        "subjects": [{
            "repository": RETIRED_GATEWAY_REPOSITORY,
            "digest": RETIRED_GATEWAY_DIGEST,
            "status": "retired",
            "eligible_for_new_study": False,
            "reason": "historically published byte-forwarding gateway cannot enforce authoritative Stage 1 metering",
        }],
    }
    if data != expected:
        raise ValueError("retired runtime record differs from reviewed subjects")
