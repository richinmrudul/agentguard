"""Keep the reviewed mock-only protocol cases tied to executable tests."""

from pathlib import Path


ROOT = Path(__file__).parents[2]
MATRIX = ROOT / "docs/stage1-metering-protocol-v1.md"
RUST_TESTS = ROOT / "runtime-images/stage1-metering-rust/tests/strict_protocol.rs"
DOCKER_TEST = ROOT / "tests/integration/test_stage1_rust_metering_docker.py"


def test_protocol_matrix_case_ids_and_test_bindings() -> None:
    matrix = MATRIX.read_text(encoding="utf-8")
    names = RUST_TESTS.read_text(encoding="utf-8") + DOCKER_TEST.read_text(
        encoding="utf-8"
    )
    for case in (
        "H01", "H02", "H03", "H04", "H05", "H06", "H07",
        "S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08",
    ):
        assert matrix.count(f"| {case} |") == 1
    for test in (
        "http_framing_and_routing_reject_ambiguity",
        "sse_exact_lifecycle_and_completed_only_rejection",
        "sse_identity_order_replay_and_terminal_usage_fail_closed",
        "test_compiled_gateway_with_patched_codex_tls_and_ledger",
    ):
        assert f"fn {test}" in names or f"def {test}" in names
        assert f"`{test}`" in matrix
