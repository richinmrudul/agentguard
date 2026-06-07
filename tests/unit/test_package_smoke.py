from pathlib import Path


SCRIPT_PATH = Path("scripts/package_smoke.sh")


def test_package_smoke_script_covers_installed_cli_workflow() -> None:
    assert SCRIPT_PATH.exists()

    script = SCRIPT_PATH.read_text(encoding="utf-8")
    required_fragments = [
        "set -euo pipefail",
        "python3 -m venv",
        "pip wheel",
        "pip install build",
        '"$PYTHON" -m build --sdist',
        'pip install "${WHEEL_PATH}[dev]"',
        'cp -R "$ROOT_DIR/examples"',
        '"$AGENTGUARD" --version',
        '"$AGENTGUARD" --help',
        '"$AGENTGUARD" benchmarks list',
        '"$AGENTGUARD" reports list',
        '"$AGENTGUARD" run examples/configs/fix_auth_bug.yaml --agent mock-safe',
        '"$AGENTGUARD" history stats',
    ]

    for fragment in required_fragments:
        assert fragment in script
