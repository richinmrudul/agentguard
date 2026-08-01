import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_WORKFLOWS = tuple(sorted((ROOT / ".github/workflows").glob("*.yml")))
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/publish.yml"
EXAMPLE_WORKFLOWS = tuple(
    sorted((ROOT / "examples/github-actions").glob("*.yml"))
)
ACTION_DOCUMENTATION = (
    ROOT / "docs/action.md",
    ROOT / "docs/ci-exports.md",
    ROOT / "docs/github-actions.md",
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
PINNED_RELEASES = {
    "actions/checkout": (
        "93cb6efe18208431cddfb8368fd83d5badbf9bfd",
        "v5.0.1",
    ),
    "actions/setup-python": (
        "a309ff8b426b58ec0e2a45f0f869d46889d02405",
        "v6.2.0",
    ),
    "actions/upload-artifact": (
        "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        "v6.0.0",
    ),
    "actions/download-artifact": (
        "37930b1c2abaa49bbe596cd826c3c89aef350131",
        "v7.0.0",
    ),
    "actions/configure-pages": (
        "45bfe0192ca1faeb007ade9deae92b16b8254a0d",
        "v6.0.0",
    ),
    "actions/upload-pages-artifact": (
        "fc324d3547104276b827a68afc52ff2a11cc49c9",
        "v5.0.0",
    ),
    "actions/deploy-pages": (
        "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128",
        "v5.0.0",
    ),
}
SUPERSEDED_REFS = {
    "actions/checkout@v4",
    "actions/setup-python@v5",
    "actions/upload-artifact@v4",
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
}


def _workflow(path: Path) -> dict[str, Any]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _uses(workflow: dict[str, Any]) -> list[str]:
    return [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if isinstance(step, dict) and "uses" in step
    ]


def test_active_workflows_pin_every_action_to_a_full_sha() -> None:
    for path in ACTIVE_WORKFLOWS:
        for action in _uses(_workflow(path)):
            repository, ref = action.rsplit("@", 1)
            assert "/" in repository
            assert FULL_SHA.fullmatch(ref), f"{path}: {action}"


def test_affected_action_comments_match_verified_stable_releases() -> None:
    for path in (*ACTIVE_WORKFLOWS, *EXAMPLE_WORKFLOWS, *ACTION_DOCUMENTATION):
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            match = re.search(r"uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(\S+)", line)
            if match is None or match.group(1) not in PINNED_RELEASES:
                continue
            expected_sha, expected_version = PINNED_RELEASES[match.group(1)]
            assert (match.group(2), match.group(3)) == (
                expected_sha,
                expected_version,
            )


def test_deprecated_node20_action_references_are_absent_from_workflows() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (*ACTIVE_WORKFLOWS, *EXAMPLE_WORKFLOWS, *ACTION_DOCUMENTATION)
    )
    for reference in SUPERSEDED_REFS:
        assert reference not in sources


def test_active_workflow_triggers_and_validation_modes_are_unchanged() -> None:
    ci = _workflow(CI_WORKFLOW)
    publish = _workflow(PUBLISH_WORKFLOW)
    ci_triggers = ci.get("on", ci.get(True))
    publish_triggers = publish.get("on", publish.get(True))

    assert ci_triggers == {"push": None, "pull_request": None}
    assert publish_triggers == {"release": {"types": ["published"]}}
    assert "--ordinary-ci" in str(ci["jobs"]["package"])
    assert "--strict-release-tag" not in str(ci["jobs"]["package"])
    assert "--strict-release-tag" in str(publish["jobs"]["build"])
    assert "--ordinary-ci" not in str(publish)


def test_publication_permissions_and_artifact_handoff_are_unchanged() -> None:
    publish = _workflow(PUBLISH_WORKFLOW)
    build = publish["jobs"]["build"]
    publication = publish["jobs"]["publish"]

    assert publish["permissions"] == {"contents": "read"}
    assert build["permissions"] == {"contents": "read"}
    assert publication["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert publication["environment"]["name"] == "pypi"
    assert publication["needs"] == "build"
    assert sum("build_release.sh" in str(step) for step in build["steps"]) == 1
    assert not any("build_release.sh" in str(step) for step in publication["steps"])

    upload = next(
        step for step in build["steps"] if step.get("uses", "").startswith(
            "actions/upload-artifact@"
        )
    )
    download = next(
        step for step in publication["steps"] if step.get("uses", "").startswith(
            "actions/download-artifact@"
        )
    )
    assert upload["with"]["name"] == download["with"]["name"]
