# Configuration JSON Schema

AgentGuard publishes a versioned JSON Schema for `agentguard.yaml`. It provides
editor validation and completion for the same public fields consumed by the
production `load_config` path.

The canonical v1 schema is
[`agentguard-config-v1.schema.json`](https://raw.githubusercontent.com/richinmrudul/agentguard/main/agentguard/schemas/agentguard-config-v1.schema.json).
It uses JSON Schema Draft 2020-12 and ships inside the `agentguard-evals`
wheel and source distribution as
`agentguard/schemas/agentguard-config-v1.schema.json`.

## Source of truth and drift checks

The production loader remains authoritative because it also performs checks
that a data-only JSON Schema cannot perform, including resolving repository and
prompt-file paths, checking prompt-file existence and size, normalizing guard
ignore paths, comparing cross-field and aggregate limits, and validating the
complete Docker image grammar.

The checked-in JSON file is the canonical editor schema. CI runs
`python scripts/validate_config_schema.py`, which:

1. checks the schema itself with a Draft 2020-12 validator;
2. validates every maintained file under `examples/configs/` against it; and
3. loads those same files through production `load_config`.

Focused contract tests additionally compare the schema's top-level fields,
policy names, enums, built-in detector IDs, required fields, and
unknown-property behavior with loader constants. Changes to either side must
therefore update the contract and examples together. The production loader is
still the final validation authority at execution time.

## VS Code

Install the [YAML extension by Red Hat](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml),
then add a repository setting in `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "https://raw.githubusercontent.com/richinmrudul/agentguard/main/agentguard/schemas/agentguard-config-v1.schema.json": "agentguard.yaml"
  }
}
```

Pin a released schema by replacing `main` with a release tag that contains the
schema. A repository may also use a relative path to a vendored copy.

## YAML Language Server modeline

YAML Language Server users can associate one file without editor settings:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/richinmrudul/agentguard/main/agentguard/schemas/agentguard-config-v1.schema.json
task_id: pr_safety_check
description: Validate this pull request after tests run.
mode: ci
test_command: pytest
expected_modified_files:
  min: 0
  max: 25
```

The schema improves editing but does not replace `agentguard ci --config
agentguard.yaml`. AgentGuard CI performs post-execution validation; neither the
schema nor the CI configuration contains an untrusted coding agent.
