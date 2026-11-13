"""Keep the retained B1 mock image importable by its non-root runtime user."""

from pathlib import Path


def test_b1_mock_package_copies_preserve_directory_search_permission() -> None:
    dockerfile = (
        Path(__file__).parents[2] / "runtime-images/stage1-metering/Dockerfile.b1-mock"
    ).read_text(encoding="utf-8")
    copies = [line for line in dockerfile.splitlines() if line.startswith("COPY ") and "/app/" in line]
    assert copies
    assert all(line.startswith("COPY --chmod=0555 ") for line in copies)
    assert "USER 65532:65532" in dockerfile
