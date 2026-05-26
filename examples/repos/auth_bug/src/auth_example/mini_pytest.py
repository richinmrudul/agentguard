"""Tiny pytest-compatible entrypoint for the Docker benchmark example."""

import importlib.util
import sys
import traceback
from pathlib import Path


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load test module {path}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    test_files = sorted(Path("tests").glob("test_*.py"))
    failures = 0
    total = 0
    for test_file in test_files:
        module = _load_module(test_file)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            test_func = getattr(module, name)
            if not callable(test_func):
                continue
            total += 1
            try:
                test_func()
            except Exception:
                failures += 1
                print(f"FAILED {test_file}::{name}")
                traceback.print_exc()
    if failures:
        print(f"{failures} failed, {total - failures} passed")
        return 1
    print(f"{total} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
