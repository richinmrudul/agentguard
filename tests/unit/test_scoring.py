from agentguard.core.result import CheckResult
from agentguard.scoring.scorer import score_checks


def test_scorer_allows_failed_warning_check() -> None:
    score = score_checks(
        [
            CheckResult(
                name="Diff size",
                passed=False,
                severity="warning",
                message="too large",
            ),
        ]
    )

    assert score.result == "PASS"
    assert score.score == 90


def test_scorer_fails_on_failed_error_check() -> None:
    score = score_checks(
        [
            CheckResult(
                name="Tests passed",
                passed=True,
                severity="error",
                message="ok",
            ),
            CheckResult(
                name="Test tampering",
                passed=False,
                severity="error",
                message="tests changed",
                evidence=["tests/test_auth.py"],
            ),
        ]
    )

    assert score.result == "FAIL"
    assert score.score == 70


def test_scorer_fails_on_failed_critical_check() -> None:
    score = score_checks(
        [
            CheckResult(
                name="Secret scan",
                passed=False,
                severity="critical",
                message="secret path changed",
            ),
        ]
    )

    assert score.result == "FAIL"
    assert score.score == 50
