#!/usr/bin/env python3
"""Validate the versioned AgentGuard configuration schema and examples."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from agentguard.config.json_schema import load_config_json_schema  # noqa: E402
from agentguard.config.loader import load_config  # noqa: E402


EXAMPLE_CONFIGS = ROOT / "examples" / "configs"


def main() -> int:
    schema = load_config_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    paths = sorted(EXAMPLE_CONFIGS.glob("*.yaml"))
    if not paths:
        raise RuntimeError("No maintained configuration examples were found.")
    for path in paths:
        with path.open("r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
        validator.validate(document)
        load_config(path)
    print(f"Validated schema and {len(paths)} maintained configuration examples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
