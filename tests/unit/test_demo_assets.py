from pathlib import Path


def test_demo_assets_exist_and_reference_required_commands() -> None:
    demo_doc = Path("docs/demo.md")
    demo_script = Path("scripts/demo.sh")
    readme = Path("README.md")

    assert demo_doc.exists()
    assert demo_script.exists()

    script = demo_script.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "--allow-fail-result" in script
    assert "--allow-failures" in script

    assert "docs/demo.md" in readme.read_text(encoding="utf-8")
