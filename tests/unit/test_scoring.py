from agentguard.core.result import CheckResult
from agentguard.scoring.scorer import score_checks


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
