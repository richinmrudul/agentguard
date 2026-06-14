import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import agentguard.core.benchmark as benchmark_module
import agentguard.core.ci as ci_module
import agentguard.core.suite as suite_module
from agentguard.io import atomic_write_text


class _FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 6, 13, 12, 0, 0, tzinfo=tz or timezone.utc)


@pytest.mark.parametrize(
    ("module", "builder", "args"),
    [
        (
            benchmark_module,
            benchmark_module._summary_dir,
            ("task", Path("benchmarks")),
        ),
        (
            suite_module,
            suite_module._suite_dir,
            ("suite", Path("suites")),
        ),
        (
            ci_module,
            ci_module._run_dir,
            ("task", Path("repo"), Path("ci")),
        ),
    ],
)
def test_aggregate_ids_resist_same_timestamp_collisions(
    monkeypatch,
    module,
    builder,
    args,
) -> None:
    values = iter(
        [
            SimpleNamespace(hex="11111111aaaaaaaa"),
            SimpleNamespace(hex="22222222bbbbbbbb"),
        ]
    )
    monkeypatch.setattr(module, "datetime", _FixedDatetime)
    monkeypatch.setattr(module, "uuid4", lambda: next(values))

    first = builder(*args)
    second = builder(*args)

    assert first != second
    assert first.name.endswith("-11111111")
    assert second.name.endswith("-22222222")


def test_atomic_write_preserves_existing_file_when_replace_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("old\n", encoding="utf-8")

    def fail_replace(source, destination) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("agentguard.io.os.replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        atomic_write_text(output, "new\n")

    assert output.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_release_candidate_results_are_sanitized_and_checklist_is_manual() -> None:
    result_path = Path("docs/results/release-candidate.json")
    checklist_path = Path("docs/release-checklist.md")

    data = json.loads(result_path.read_text(encoding="utf-8"))
    serialized = json.dumps(data)
    checklist = checklist_path.read_text(encoding="utf-8")

    assert data["schema"] == "agentguard.release-candidate-summary"
    assert data["tests"]["passed"] == 467
    assert data["package_validation"]["published"] is False
    assert "/Users/" not in serialized
    assert "/tmp/" not in serialized
    assert "PyPI publication remains separate and manual" in checklist
    assert "Rollback And Revocation" in checklist
