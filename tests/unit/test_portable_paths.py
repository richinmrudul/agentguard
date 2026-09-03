from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from agentguard.provenance.portable_paths import (
    PortablePathError,
    portable_reference,
    portable_text,
    portable_value,
    resolve_portable,
    resolve_portable_reference,
    resolve_portable_text,
)


def test_bare_nested_and_text_round_trip_after_roots_move(tmp_path: Path) -> None:
    original_repo = tmp_path / "original" / "repo"
    original_run = tmp_path / "original" / "run"
    original_config = tmp_path / "original" / "config"
    original_agentguard = tmp_path / "original" / "agentguard"
    original_roots = {
        "REPOSITORY_ROOT": original_repo,
        "RUN_ROOT": original_run,
        "CONFIG_ROOT": original_config,
        "AGENTGUARD_ROOT": original_agentguard,
    }
    moved_roots = {
        "REPOSITORY_ROOT": tmp_path / "moved" / "repo",
        "RUN_ROOT": tmp_path / "moved" / "run",
        "CONFIG_ROOT": tmp_path / "moved" / "config",
        "AGENTGUARD_ROOT": tmp_path / "moved" / "agentguard",
    }

    bare = portable_reference(original_repo, original_roots)
    nested = portable_reference(original_repo / "src" / "app.py", original_roots)
    text = portable_text(
        f"read {original_repo / 'src' / 'app.py'} then write "
        f"{original_run / 'reports' / 'report.json'}",
        original_roots,
    )

    assert bare == "${REPOSITORY_ROOT}"
    assert nested == "${REPOSITORY_ROOT}/src/app.py"
    assert text == (
        "read ${REPOSITORY_ROOT}/src/app.py then write "
        "${RUN_ROOT}/reports/report.json"
    )
    assert resolve_portable_reference(bare, moved_roots) == moved_roots[
        "REPOSITORY_ROOT"
    ]
    assert resolve_portable_reference(nested, moved_roots) == (
        moved_roots["REPOSITORY_ROOT"] / "src" / "app.py"
    )
    assert resolve_portable_text(text, moved_roots) == (
        f"read {moved_roots['REPOSITORY_ROOT'] / 'src' / 'app.py'} then write "
        f"{moved_roots['RUN_ROOT'] / 'reports' / 'report.json'}"
    )


def test_portable_value_round_trips_nested_structures(tmp_path: Path) -> None:
    roots = {
        "repository": tmp_path / "repo",
        "run": tmp_path / "run",
    }
    moved = {
        "repository": tmp_path / "relocated" / "repo",
        "run": tmp_path / "relocated" / "run",
    }

    portable = portable_value(
        {
            "path": roots["repository"] / "tests" / "test_app.py",
            "logs": [f"{roots['run'] / 'logs' / 'agent.log'}"],
            "unchanged": "plain text",
        },
        roots,
    )

    assert portable == {
        "logs": ["${RUN_ROOT}/logs/agent.log"],
        "path": "${REPOSITORY_ROOT}/tests/test_app.py",
        "unchanged": "plain text",
    }
    assert resolve_portable(portable, moved) == {
        "logs": [moved["run"] / "logs" / "agent.log"],
        "path": moved["repository"] / "tests" / "test_app.py",
        "unchanged": "plain text",
    }


def test_prose_punctuation_after_reference_is_preserved(tmp_path: Path) -> None:
    roots = {"REPOSITORY_ROOT": tmp_path / "repo"}

    assert resolve_portable_text(
        "see ${REPOSITORY_ROOT}/src/app.py.",
        roots,
    ) == f"see {tmp_path / 'repo' / 'src' / 'app.py'}."
    assert resolve_portable(
        "${REPOSITORY_ROOT}/src/app.py.",
        roots,
    ) == f"{tmp_path / 'repo' / 'src' / 'app.py'}."


def test_multiple_references_with_prose_punctuation_round_trip(
    tmp_path: Path,
) -> None:
    roots = {
        "REPOSITORY_ROOT": tmp_path / "repo",
        "RUN_ROOT": tmp_path / "run",
    }

    assert resolve_portable_text(
        "(${REPOSITORY_ROOT}/src/app.py), ${RUN_ROOT}/logs/out.txt;",
        roots,
    ) == (
        f"({tmp_path / 'repo' / 'src' / 'app.py'}), "
        f"{tmp_path / 'run' / 'logs' / 'out.txt'};"
    )


def test_missing_root_fails_closed_without_path_disclosure(tmp_path: Path) -> None:
    trusted_roots = {"REPOSITORY_ROOT": tmp_path / "repo"}

    with pytest.raises(PortablePathError) as raised:
        resolve_portable_reference("${RUN_ROOT}/private/secret.txt", trusted_roots)

    assert "missing" in str(raised.value)
    assert "private" not in str(raised.value)
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("entrypoint", ["forward", "inverse"])
def test_alias_collisions_are_rejected_without_path_disclosure(
    tmp_path: Path,
    entrypoint: str,
) -> None:
    roots = {
        "repo": tmp_path / "trusted" / "repo-a",
        "REPOSITORY_ROOT": tmp_path / "trusted" / "repo-b",
    }

    with pytest.raises(PortablePathError) as raised:
        if entrypoint == "forward":
            portable_reference(tmp_path / "trusted" / "repo-a" / "src.py", roots)
        else:
            resolve_portable_reference("${REPOSITORY_ROOT}/src.py", roots)

    message = str(raised.value)
    assert "ambiguous" in message
    assert "repo-a" not in message
    assert "repo-b" not in message
    assert str(tmp_path) not in message


@pytest.mark.parametrize(
    "reference",
    [
        "${UNKNOWN_ROOT}/file.txt",
        "${REPOSITORY_ROOT",
        "${REPOSITORY_ROOT}file.txt",
        "${REPOSITORY_ROOT}/",
        "${REPOSITORY_ROOT}//file.txt",
        "${REPOSITORY_ROOT}/./file.txt",
        "${REPOSITORY_ROOT}/nested\x00file.txt",
    ],
)
def test_unknown_and_malformed_references_are_rejected(
    tmp_path: Path,
    reference: str,
) -> None:
    with pytest.raises(PortablePathError):
        resolve_portable_reference(reference, {"REPOSITORY_ROOT": tmp_path / "repo"})


@pytest.mark.parametrize(
    "value",
    [
        "see ${REPOSITORY_ROOT}src/app.py",
        "see ${REPOSITORY_ROOT}/src/${RUN_ROOT}/out.txt",
    ],
)
def test_malformed_text_references_are_rejected(
    tmp_path: Path,
    value: str,
) -> None:
    with pytest.raises(PortablePathError):
        resolve_portable_text(
            value,
            {
                "REPOSITORY_ROOT": tmp_path / "repo",
                "RUN_ROOT": tmp_path / "run",
            },
        )


@pytest.mark.parametrize(
    "reference",
    [
        "${REPOSITORY_ROOT}/../secret.txt",
        "${REPOSITORY_ROOT}/src/../../secret.txt",
        "${REPOSITORY_ROOT}/C:/secret.txt",
        "/etc/passwd",
        "C:/Users/example/secret.txt",
        r"\\server\share\secret.txt",
    ],
)
def test_escaping_traversal_drive_and_unc_references_are_rejected_safely(
    tmp_path: Path,
    reference: str,
) -> None:
    with pytest.raises(PortablePathError) as raised:
        resolve_portable(reference, {"REPOSITORY_ROOT": tmp_path / "repo"})

    message = str(raised.value)
    assert "secret" not in message
    assert "passwd" not in message
    assert "server" not in message


def test_ambiguous_references_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(PortablePathError, match="ambiguous"):
        resolve_portable_reference(
            "${REPOSITORY_ROOT}/${RUN_ROOT}/report.json",
            {
                "REPOSITORY_ROOT": tmp_path / "repo",
                "RUN_ROOT": tmp_path / "run",
            },
        )


def test_prefix_collisions_are_not_portabilized(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    sibling = tmp_path / "repository"
    roots = {"REPOSITORY_ROOT": repo}

    portable = portable_text(
        f"{repo / 'src' / 'app.py'} {sibling / 'src' / 'app.py'} {repo}suffix",
        roots,
    )

    assert portable.startswith("${REPOSITORY_ROOT}/src/app.py ")
    assert str(sibling / "src" / "app.py") in portable
    assert f"{repo}suffix" in portable


def test_synthetic_posix_paths_round_trip_with_moved_roots() -> None:
    roots = {"REPOSITORY_ROOT": PurePosixPath("/workspace/repo")}
    moved = {"REPOSITORY_ROOT": PurePosixPath("/mnt/agent/repo")}

    reference = portable_reference(
        PurePosixPath("/workspace/repo/src/app.py"),
        roots,
    )

    assert reference == "${REPOSITORY_ROOT}/src/app.py"
    assert resolve_portable_reference(reference, moved) == PurePosixPath(
        "/mnt/agent/repo/src/app.py"
    )


def test_synthetic_windows_drive_paths_round_trip_with_moved_roots() -> None:
    roots = {"REPOSITORY_ROOT": PureWindowsPath("C:/workspace/repo")}
    moved = {"REPOSITORY_ROOT": PureWindowsPath("D:/agent/repo")}

    reference = portable_reference(
        PureWindowsPath("C:/workspace/repo/src/app.py"),
        roots,
    )
    text = resolve_portable_text(
        r"run ${REPOSITORY_ROOT}\src\app.py",
        moved,
    )

    assert reference == "${REPOSITORY_ROOT}/src/app.py"
    assert resolve_portable_reference(reference, moved) == PureWindowsPath(
        "D:/agent/repo/src/app.py"
    )
    assert text == r"run D:\agent\repo\src\app.py"
