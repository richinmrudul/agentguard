"""Keep the reviewed mock-only protocol cases tied to executable tests."""

import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[2]
MATRIX = ROOT / "docs/stage1-metering-protocol-v1.md"
RUST_TESTS = ROOT / "runtime-images/stage1-metering-rust/tests/strict_protocol.rs"
DOCKER_TEST = ROOT / "tests/integration/test_stage1_rust_metering_docker.py"
LEDGER_TESTS = ROOT / "runtime-images/stage1-metering-rust/src/ledger.rs"
CASE_MATRIX = ROOT / "docs/stage1-metering-protocol-cases-v1.json"


def test_protocol_matrix_case_ids_and_test_bindings() -> None:
    matrix = MATRIX.read_text(encoding="utf-8")
    names = RUST_TESTS.read_text(encoding="utf-8") + DOCKER_TEST.read_text(
        encoding="utf-8"
    )
    required = (
        "H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08", "H09", "H10", "H11", "H12",
        "S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13",
    )
    rows = {
        fields[1].strip(): fields
        for line in matrix.splitlines()
        if line.startswith("| H") or line.startswith("| S")
        if len(fields := line.split("|")) == 6
    }
    assert set(rows) == set(required)
    for case in required:
        assert matrix.count(f"| {case} |") == 1
        tests = re.findall(r"`([A-Za-z_][A-Za-z_0-9]*)`", rows[case][4])
        assert tests, case
        for test in tests:
            assert f"fn {test}" in names or f"def {test}" in names, (case, test)


def test_complete_protocol_case_dispositions_and_executable_bindings() -> None:
    matrix = json.loads(CASE_MATRIX.read_text(encoding="utf-8"))
    assert matrix["schema"] == "agentguard.stage1-metering-protocol-cases"
    assert matrix["schema_version"] == 1
    assert matrix["scope"] == "mock-only-prepublication"
    assert matrix["deferred_issue"] == 327
    cases = matrix["cases"]
    expected = {f"H{number:02d}" for number in range(1, 21)}
    expected.update(f"S{number:02d}" for number in range(1, 21))
    assert len(cases) == len(expected)
    assert {case["id"] for case in cases} == expected
    source = (
        RUST_TESTS.read_text(encoding="utf-8")
        + LEDGER_TESTS.read_text(encoding="utf-8")
    )
    docker = DOCKER_TEST.read_text(encoding="utf-8")
    required_fields = {
        "id", "threat", "parser_result", "accounting_certainty",
        "reservation", "replay_eligibility", "evidence_class", "test_level",
        "test_name",
    }
    for case in cases:
        assert required_fields <= case.keys(), case["id"]
        assert all(case[field] for field in required_fields), case["id"]
        if case["test_level"] == "image":
            assert set(case) == required_fields | {"image_scenario"}, case["id"]
            assert f"def {case['test_name']}" in docker, case["id"]
            assert f'"{case["image_scenario"]}"' in docker, case["id"]
        else:
            assert case["test_level"] == "unit" and set(case) == required_fields
            assert f"fn {case['test_name']}" in source, case["id"]
