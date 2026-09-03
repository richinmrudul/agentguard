from dataclasses import asdict, is_dataclass
from pathlib import Path, PurePath
from typing import Any, Mapping, Optional, Union

from agentguard.provenance.portable_paths import portable_value


def artifact_roots(
    *,
    repository_root: Optional[Path] = None,
    run_root: Optional[Path] = None,
    config_path: Optional[Path] = None,
    agentguard_root: Optional[Path] = None,
) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    agentguard = agentguard_root if agentguard_root is not None else Path.cwd()
    if repository_root is not None:
        roots["REPOSITORY_ROOT"] = repository_root
    if run_root is not None:
        roots["RUN_ROOT"] = run_root
    if config_path is not None:
        config_root = config_path.parent if config_path.suffix else config_path
        if not _contained_by(config_root, agentguard):
            roots["CONFIG_ROOT"] = config_root
    roots["AGENTGUARD_ROOT"] = agentguard
    return roots


def portable_artifact_value(
    value: Any,
    roots: Mapping[str, Union[PurePath, str]],
) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return portable_artifact_value(asdict(value), roots)
    if isinstance(value, PurePath):
        return portable_value(value, roots)
    if isinstance(value, str):
        return portable_value(value, roots)
    if isinstance(value, tuple):
        return [portable_artifact_value(item, roots) for item in value]
    if isinstance(value, list):
        return [portable_artifact_value(item, roots) for item in value]
    if isinstance(value, dict):
        return {
            key: portable_artifact_value(item, roots)
            for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
        }
    return value


def _contained_by(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
    except (OSError, ValueError):
        return False
    return True
