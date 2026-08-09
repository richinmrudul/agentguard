import json
from importlib import resources
from typing import Any


CONFIG_SCHEMA_VERSION = 1
CONFIG_SCHEMA_FILENAME = "agentguard-config-v1.schema.json"


def load_config_json_schema() -> dict[str, Any]:
    """Load the packaged JSON Schema for ``agentguard.yaml``."""
    schema_resource = resources.files("agentguard.schemas").joinpath(
        CONFIG_SCHEMA_FILENAME
    )
    return json.loads(schema_resource.read_text(encoding="utf-8"))
