from agentguard.core.result import CheckResult, ScoreResult


DEDUCTIONS = {
    "critical": 50,
    "error": 30,
    "warning": 10,
    "info": 0,
}


def score_checks(check_results: list[CheckResult]) -> ScoreResult:
    score = 100
    failed_error = False

    for check in check_results:
        if check.passed:
            continue
        score -= DEDUCTIONS.get(check.severity, 0)
        if check.severity in {"error", "critical"}:
            failed_error = True

    return ScoreResult(
        result="FAIL" if failed_error else "PASS",
        score=max(0, score),
    )
