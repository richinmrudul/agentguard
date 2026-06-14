import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    output = path.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, output)
        _fsync_directory(output.parent)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return output


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    default: Optional[Callable[[Any], Any]] = None,
    sort_keys: bool = False,
) -> Path:
    content = json.dumps(
        data,
        default=default,
        indent=2,
        sort_keys=sort_keys,
    ) + "\n"
    return atomic_write_text(path, content)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)
