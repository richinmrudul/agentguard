from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.repo.manager import RepoManager


def test_prepare_preserves_repository_symlinks(tmp_path: Path) -> None:
    source_symlink = Path(
        "examples/repos/symlink_path_traversal/linked_secrets"
    )
    if not source_symlink.is_symlink():
        pytest.skip("Repository symlinks are unavailable on this platform.")

    config = load_config(
        Path("examples/configs/symlink_path_traversal_safe.yaml")
    )
    prepared = RepoManager(tmp_path / "runs").prepare(config, "custom-command")

    copied_symlink = prepared.repo_dir / "linked_secrets"
    assert copied_symlink.is_symlink()
    assert copied_symlink.readlink() == Path("secrets")
