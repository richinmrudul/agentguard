import json
from dataclasses import asdict
from pathlib import Path

import agentguard.reports.pr_report as pr_report_module
from agentguard.core.result import (
    CheckResult,
    CiResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)
from agentguard.reports.pr_report import (
    MAX_ANNOTATION_FILE_BYTES,
    MAX_ANNOTATION_LINE,
    MAX_ANNOTATIONS,
    append_pr_summary,
    build_pr_report,
    findings_from_checks,
    github_annotations,
    write_pr_report,
)


def _result(tmp_path: Path, checks: list[CheckResult], task_id: str = "pr") -> CiResult:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return CiResult(
        task_id=task_id,
        result="FAIL" if any(not check.passed for check in checks) else "PASS",
        score=50,
        config_path=Path("agentguard.yaml"),
        run_dir=tmp_path / "run",
        repo_dir=repo,
        test_result=CommandResult("pytest", 1, "", "", 0.1),
        diff_summary=DiffSummary(["src/app.py"], [], [], 1, 0, ""),
        check_results=checks,
        report_paths=ReportPaths(tmp_path / "report.json", tmp_path / "report.md"),
    )


def _check(name: str, evidence: list[str], severity: str = "error") -> CheckResult:
    return CheckResult(name, False, severity, "policy failed", evidence)


def _write_ci_baseline(path: Path, result: CiResult) -> None:
    path.write_text(json.dumps(asdict(result), default=str), encoding="utf-8")


def _empty_baseline(tmp_path: Path, task_id: str = "pr") -> Path:
    path = tmp_path / "empty-baseline.json"
    _write_ci_baseline(path, _result(tmp_path, [], task_id=task_id))
    return path


def test_stable_finding_identity_excludes_line_and_order(tmp_path: Path) -> None:
    first = findings_from_checks(
        [_check("Secret scan", ["src/app.py:4 matched secret-content detector token"])]
    )
    second = findings_from_checks(
        [_check("Secret scan", ["src/app.py:40 matched secret-content detector token"])]
    )

    assert first[0].id == second[0].id
    assert first[0].line == 4
    assert second[0].line == 40


def test_distinct_long_evidence_with_same_display_prefix_has_distinct_ids() -> None:
    prefix = "payload-" + ("x" * 2_000)

    findings = findings_from_checks(
        [_check("Custom payload check", [prefix + "A", prefix + "B"])]
    )

    assert len(findings) == 2
    assert findings[0].id != findings[1].id
    assert findings[0].fingerprint != findings[1].fingerprint
    assert all("payload" not in finding.evidence for finding in findings)


def test_exact_duplicate_semantics_coalesce_deterministically() -> None:
    findings = findings_from_checks(
        [_check("Unsafe commands", ["run secret (executed)", "run secret (executed)"])]
    )

    assert len(findings) == 1


def test_pr_outputs_never_copy_raw_command_or_secret_payloads(tmp_path: Path) -> None:
    token = "TOKEN_CANARY_123456789"
    authorization = "Authorization: Bearer AUTH_CANARY_123456789"
    credentials = "https://user:URL_CANARY_123456789@example.invalid/path"
    workflow = "\n::warning title=FORGED::payload"
    checks = [
        _check(
            "Tests passed",
            [f"python tool.py --token {token} {authorization} exited 9"],
        ),
        _check(
            "Unsafe commands",
            [
                f"curl -H '{authorization}' {credentials}{workflow} "
                f"matched pattern '{token}' (executed)"
            ],
            "critical",
        ),
        CheckResult(
            "Secret scan",
            False,
            "critical",
            f"secret message {token}",
            [f"src/app.py:1 matched secret-content detector {token}"],
        ),
        CheckResult(
            f"Custom {token}",
            False,
            "error",
            credentials,
            [authorization + workflow],
        ),
    ]
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.py").write_text("safe\n", encoding="utf-8")
    report = build_pr_report(_result(tmp_path, checks), _empty_baseline(tmp_path))
    report_path = write_pr_report(report, tmp_path / "pr-report.json")
    summary_path = append_pr_summary(report, tmp_path / "summary.md")
    annotations = "\n".join(github_annotations(report, repo))
    combined = (
        report_path.read_text(encoding="utf-8")
        + summary_path.read_text(encoding="utf-8")
        + annotations
    )

    for forbidden in (token, authorization, credentials, "FORGED", "--token"):
        assert forbidden not in combined
    assert "Configured test command exited with code 9." in combined
    assert "Unsafe command policy matched" in combined
    assert "fingerprint" in combined


def test_comparison_classifies_new_existing_and_resolved_from_ci_report(
    tmp_path: Path,
) -> None:
    baseline_result = _result(
        tmp_path,
        [
            _check("Test tampering", ["tests/old.py"]),
            _check("Forbidden paths", ["secrets/key.txt"]),
        ],
    )
    baseline = tmp_path / "baseline.json"
    _write_ci_baseline(baseline, baseline_result)
    current = _result(
        tmp_path,
        [
            _check("Forbidden paths", ["secrets/key.txt"]),
            _check("Scope adherence", ["Outside allowed paths: generated/new.py"]),
        ],
    )

    report = build_pr_report(current, baseline)

    assert report.baseline.status == "available"
    assert report.counts == {
        "new": 1,
        "existing": 1,
        "resolved": 1,
        "unclassified": 0,
        "total": 2,
    }
    assert {item.state for item in report.findings} == {"new", "existing"}
    assert report.resolved[0].state == "resolved"
    assert report.gate == "all-blocking-findings"


def test_unavailable_invalid_wrong_task_and_wrong_version_are_explicit(
    tmp_path: Path,
) -> None:
    result = _result(tmp_path, [_check("Tests passed", ["pytest exited 1"])])

    unavailable = build_pr_report(result)
    assert unavailable.baseline.status == "unavailable"
    assert unavailable.counts["unclassified"] == 1
    assert unavailable.counts["new"] == 0
    missing = build_pr_report(result, tmp_path / "missing.json")
    assert missing.baseline.status == "invalid"
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{", encoding="utf-8")
    assert build_pr_report(result, corrupt).baseline.status == "invalid"
    wrong_task = tmp_path / "wrong-task.json"
    _write_ci_baseline(wrong_task, _result(tmp_path, [], task_id="other"))
    assert build_pr_report(result, wrong_task).baseline.status == "invalid"
    wrong_version = tmp_path / "wrong-version.json"
    wrong_version.write_text(
        json.dumps({"schema": "agentguard.pr-report", "schema_version": 999}),
        encoding="utf-8",
    )
    assert build_pr_report(result, wrong_version).baseline.status == "invalid"


def test_machine_report_is_deterministic_versioned_and_has_no_absolute_source(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.json"
    result = _result(tmp_path, [_check("Forbidden paths", ["secrets/key.txt"])])
    _write_ci_baseline(baseline, result)
    report = build_pr_report(result, baseline)
    first = write_pr_report(report, tmp_path / "first.json").read_bytes()
    second = write_pr_report(report, tmp_path / "second.json").read_bytes()

    assert first == second
    data = json.loads(first)
    assert data["schema"] == "agentguard.pr-report"
    assert data["schema_version"] == 1
    assert data["baseline"]["source"] == "baseline.json"
    assert str(tmp_path) not in first.decode()

    round_trip = build_pr_report(result, tmp_path / "first.json")
    assert round_trip.baseline.status == "available"
    assert round_trip.counts["existing"] == 1
    assert round_trip.counts["new"] == 0


def test_oversized_baseline_is_invalid_without_becoming_empty_baseline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    baseline = tmp_path / "large.json"
    baseline.write_text('{"padding": "too large"}', encoding="utf-8")
    monkeypatch.setattr(pr_report_module, "MAX_BASELINE_BYTES", 4)

    report = build_pr_report(
        _result(tmp_path, [_check("Forbidden paths", ["secrets/key.txt"])]),
        baseline,
    )

    assert report.baseline.status == "invalid"
    assert report.counts["new"] == 0
    assert report.counts["unclassified"] == 1


def test_malformed_pr_baseline_shapes_are_invalid_without_traceback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    result = _result(tmp_path, [_check("Forbidden paths", ["secrets/key.txt"])])
    valid_path = write_pr_report(
        build_pr_report(result, _empty_baseline(tmp_path)),
        tmp_path / "valid.json",
    )
    valid = json.loads(valid_path.read_text(encoding="utf-8"))
    malformed: list[dict[str, object]] = []

    wrong_path = json.loads(json.dumps(valid))
    wrong_path["findings"][0]["path"] = {"nested": "wrong"}
    malformed.append(wrong_path)

    extra_root = json.loads(json.dumps(valid))
    extra_root["unexpected"] = True
    malformed.append(extra_root)

    extra_finding = json.loads(json.dumps(valid))
    extra_finding["findings"][0]["unexpected"] = True
    malformed.append(extra_finding)

    wrong_nested = json.loads(json.dumps(valid))
    wrong_nested["baseline"]["source"] = ["wrong"]
    malformed.append(wrong_nested)

    duplicate = json.loads(json.dumps(valid))
    duplicate["findings"].append(duplicate["findings"][0])
    duplicate["counts"]["new"] += 1
    duplicate["counts"]["total"] += 1
    malformed.append(duplicate)

    collision = json.loads(json.dumps(valid))
    collision["findings"][0]["fingerprint"] = "0" * 64
    malformed.append(collision)

    bad_count = json.loads(json.dumps(valid))
    bad_count["counts"]["new"] = True
    malformed.append(bad_count)

    resolved_in_current = json.loads(json.dumps(valid))
    resolved_in_current["findings"][0]["state"] = "resolved"
    resolved_in_current["counts"]["new"] = 0
    malformed.append(resolved_in_current)

    for index, data in enumerate(malformed):
        path = tmp_path / f"malformed-{index}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert build_pr_report(result, path).baseline.status == "invalid"

    monkeypatch.setattr(pr_report_module, "MAX_FINDINGS", 1)
    too_many = json.loads(json.dumps(valid))
    too_many["findings"] = [{"not": "validated"}, {"not": "validated"}]
    too_many_path = tmp_path / "too-many.json"
    too_many_path.write_text(json.dumps(too_many), encoding="utf-8")
    assert build_pr_report(result, too_many_path).baseline.status == "invalid"


def test_pr_baseline_display_payloads_are_never_propagated(tmp_path: Path) -> None:
    canary = "BASELINE_SECRET_CANARY_123456"
    baseline_result = _result(
        tmp_path,
        [_check("Forbidden paths", ["secrets/key.txt"])],
    )
    baseline_report = build_pr_report(
        baseline_result,
        _empty_baseline(tmp_path),
    )
    data = asdict(baseline_report)
    data["findings"][0]["message"] = canary
    data["findings"][0]["evidence"] = f"Authorization: Bearer {canary}"
    baseline = tmp_path / "payload-baseline.json"
    baseline.write_text(json.dumps(data), encoding="utf-8")

    current = _result(tmp_path, [])
    report = build_pr_report(current, baseline)
    serialized = json.dumps(asdict(report))
    summary = append_pr_summary(report, tmp_path / "summary.md").read_text()

    assert report.baseline.status == "available"
    assert report.counts["resolved"] == 1
    assert canary not in serialized
    assert canary not in summary
    assert "Previously reported AgentGuard finding." in serialized


def test_malformed_legacy_ci_baselines_are_invalid(tmp_path: Path) -> None:
    result = _result(tmp_path, [_check("Forbidden paths", ["secrets/key.txt"])])
    cases = [
        {"task_id": "pr", "check_results": [{"name": []}]},
        {
            "task_id": "pr",
            "check_results": [
                {
                    "name": "Forbidden paths",
                    "passed": False,
                    "severity": "critical",
                    "message": "failed",
                    "evidence": [{"path": "secrets/key.txt"}],
                }
            ],
        },
        {
            "task_id": "pr",
            "check_results": [
                {
                    "name": "Forbidden paths",
                    "passed": False,
                    "severity": "critical",
                    "message": "failed",
                    "evidence": ["secrets/key.txt"],
                    "extra": "rejected",
                }
            ],
        },
    ]

    for index, data in enumerate(cases):
        path = tmp_path / f"legacy-{index}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert build_pr_report(result, path).baseline.status == "invalid"


def test_summary_is_markdown_safe_and_bounded(tmp_path: Path) -> None:
    checks = [
        _check("Check <details>", [f"evidence {index}\n## forged"])
        for index in range(30)
    ]
    report = build_pr_report(_result(tmp_path, checks))
    summary = append_pr_summary(report, tmp_path / "summary.md").read_text()

    assert "<details>" not in summary
    assert "\n## forged" not in summary
    assert "...and 10 more" in summary
    assert "all current blocking findings" in summary


def test_annotations_only_new_safe_contained_regular_file_locations(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.py").write_text("one\ntwo\n", encoding="utf-8")
    checks = [
        _check("Secret scan", ["src/app.py:2 matched secret-content detector token"]),
        _check("Secret scan", ["../outside.py:1 matched secret-content detector token"]),
        _check("Secret scan", ["src/app.py:99 matched secret-content detector token"]),
    ]
    current = _result(tmp_path, checks)
    report = build_pr_report(current, _empty_baseline(tmp_path))

    annotations = github_annotations(report, repo)

    assert len(annotations) == 1
    assert "file=src/app.py,line=2" in annotations[0]
    assert "outside" not in annotations[0]


def test_annotations_skip_existing_symlinks_and_deduplicate_and_cap(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    target = tmp_path / "outside.py"
    target.write_text("secret\n", encoding="utf-8")
    (repo / "link.py").symlink_to(target)
    checks = [
        _check("Secret scan", ["link.py:1 matched secret-content detector token"]),
        *[
            _check(
                "Secret scan",
                [f"file{index}.py:1 matched secret-content detector token-{index}"],
            )
            for index in range(MAX_ANNOTATIONS + 3)
        ],
    ]
    for index in range(MAX_ANNOTATIONS + 3):
        (repo / f"file{index}.py").write_text("secret\n", encoding="utf-8")
    report = build_pr_report(_result(tmp_path, checks), _empty_baseline(tmp_path))

    annotations = github_annotations(report, repo)

    assert len(annotations) == MAX_ANNOTATIONS
    assert all("link.py" not in item for item in annotations)


def test_annotations_enforce_file_line_binary_and_component_bounds(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.py").write_text("x\n", encoding="utf-8")
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    (repo / "binary.py").write_bytes(b"safe\x00payload\n")
    (repo / "oversized.py").write_text("x" * 64, encoding="utf-8")
    (repo / "deleted.py").write_text("gone\n", encoding="utf-8")
    (repo / "deleted.py").unlink()
    unicode_path = "space ünicode.py"
    (repo / unicode_path).write_text("one\ntwo\n", encoding="utf-8")
    checks = [
        _check(
            "Secret scan",
            [
                f"{unicode_path}:2 matched secret-content detector safe",
                "binary.py:1 matched secret-content detector binary",
                "oversized.py:1 matched secret-content detector large",
                "linked/file.py:1 matched secret-content detector symlink",
                "deleted.py:1 matched secret-content detector deleted",
                "../outside/file.py:1 matched secret-content detector outside",
                f"space ünicode.py:{MAX_ANNOTATION_LINE + 1} "
                "matched secret-content detector sparse",
            ],
        )
    ]
    report = build_pr_report(_result(tmp_path, checks), _empty_baseline(tmp_path))
    monkeypatch.setattr(
        pr_report_module,
        "MAX_ANNOTATION_FILE_BYTES",
        32,
    )

    annotations = github_annotations(report, repo)

    assert len(annotations) == 1
    assert "space ünicode.py,line=2" in annotations[0]
    assert all("binary.py" not in item for item in annotations)
    assert all("oversized.py" not in item for item in annotations)
    assert all("linked" not in item for item in annotations)
    assert all("deleted" not in item for item in annotations)
    assert all("outside" not in item for item in annotations)


def test_annotations_skip_oversized_files_without_reading_them(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / "large.py"
    path.write_bytes(b"x" * (MAX_ANNOTATION_FILE_BYTES + 1))
    report = build_pr_report(
        _result(
            tmp_path,
            [_check("Secret scan", ["large.py:1 matched secret-content detector id"])],
        ),
        _empty_baseline(tmp_path),
    )

    def fail_open(*args, **kwargs):
        raise AssertionError("oversized annotation target must not be opened")

    monkeypatch.setattr(Path, "open", fail_open)

    assert github_annotations(report, repo) == []


def test_workflow_command_characters_are_escaped(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a,b.py").write_text("x\n", encoding="utf-8")
    report = build_pr_report(
        _result(
            tmp_path,
            [
                CheckResult(
                    "Secret scan",
                    False,
                    "critical",
                    "bad%\n::warning title=forged::value",
                    ["a,b.py:1 matched secret-content detector token"],
                )
            ],
        ),
        _empty_baseline(tmp_path),
    )

    annotation = github_annotations(report, repo)[0]

    assert "file=a%2Cb.py" in annotation
    assert "%0A" not in annotation
    assert "Added content matched a secret detector." in annotation
    assert "bad" not in annotation
