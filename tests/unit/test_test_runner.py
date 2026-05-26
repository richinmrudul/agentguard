import os
from pathlib import Path

from agentguard.instrumentation.test_runner import _build_test_env


def test_build_test_env_uses_absolute_src_pythonpath(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = tmp_path / "repo"
    src_dir = repo_dir / "src"
    src_dir.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", "existing-path")

    env = _build_test_env(Path("repo"))
    pythonpath_entries = env["PYTHONPATH"].split(os.pathsep)

    assert pythonpath_entries[0] == str(src_dir.resolve())
    assert Path(pythonpath_entries[0]).is_absolute()
    assert pythonpath_entries[1] == "existing-path"
