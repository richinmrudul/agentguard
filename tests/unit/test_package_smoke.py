from pathlib import Path


SCRIPT_PATH = Path("scripts/package_smoke.sh")


def test_package_smoke_script_covers_installed_cli_workflow() -> None:
    assert SCRIPT_PATH.exists()

    script = SCRIPT_PATH.read_text(encoding="utf-8")
    required_fragments = [
        "set -euo pipefail",
        "python3 -m venv",
        'rm -rf "$ROOT_DIR/build"',
        "pip install build",
        '"setuptools>=77"',
        "--no-isolation",
        "--wheel",
        "--sdist",
        'pip install "$WHEEL_PATH"',
        "Verify installed package isolation",
        "agentguard module path:",
        "Expected benchmarks list to require repository examples before copy.",
        'cp -R "$ROOT_DIR/examples"',
        '"$AGENTGUARD" --version',
        '"$AGENTGUARD" --help',
        '"$AGENTGUARD" benchmarks list',
        '"$AGENTGUARD" reports list',
        "examples/configs/fix_auth_bug_local_command_safe.yaml",
        "--agent local-command",
        '"$AGENTGUARD" history stats',
    ]

    for fragment in required_fragments:
        assert fragment in script
