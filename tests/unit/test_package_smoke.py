from pathlib import Path


SCRIPT_PATH = Path("scripts/package_smoke.sh")


def test_package_smoke_script_covers_installed_cli_workflow() -> None:
    assert SCRIPT_PATH.exists()

    script = SCRIPT_PATH.read_text(encoding="utf-8")
    required_fragments = [
        "set -euo pipefail",
        'BASE_PYTHON=${PYTHON:-python3}',
        '"$BASE_PYTHON" -m venv',
        'rm -rf "$ROOT_DIR/build"',
        "PREBUILT_DIST_DIR=${1:-}",
        "Install locked build toolchain",
        "requirements/release-build-toolchain.txt",
        "validate_release_toolchain.py",
        "--require-hashes",
        "--only-binary=:all:",
        "release-build-toolchain.json",
        "--no-isolation",
        "--wheel",
        "--sdist",
        "Use prebuilt wheel and source distribution",
        "validate_release_artifacts.py",
        'pip install "$WHEEL_PATH"',
        "Verify installed distribution metadata",
        'distribution("agentguard-evals")',
        'installed.version != "0.3.0"',
        'distribution("agentguard")',
        "Verify installed package isolation",
        "agentguard module path:",
        "Expected benchmarks list to require repository examples before copy.",
        'cp -R "$ROOT_DIR/examples"',
        '"$AGENTGUARD" --version',
        '"$AGENTGUARD" --help',
        '"$AGENTGUARD" presets list',
        '"$AGENTGUARD" presets show recommended --format json',
        '"$AGENTGUARD" benchmarks list',
        '"$AGENTGUARD" reports list',
        "examples/configs/fix_auth_bug_local_command_safe.yaml",
        "--agent local-command",
        '"$AGENTGUARD" history stats',
    ]

    for fragment in required_fragments:
        assert fragment in script
