import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/publish.yml"
RELEASE_DOC = ROOT / "docs/release.md"
RELEASE_CHECKLIST = ROOT / "docs/release-checklist.md"
README = ROOT / "README.md"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflow() -> dict:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _triggers(workflow: dict) -> dict:
    # PyYAML 1.1 treats the unquoted YAML key "on" as boolean true.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _uses(job: dict) -> list[str]:
    return [
        step["uses"]
        for step in job["steps"]
        if isinstance(step, dict) and "uses" in step
    ]


def test_publish_workflow_has_only_the_release_trigger() -> None:
    assert WORKFLOW_PATH.is_file()
    workflow = _workflow()
    triggers = _triggers(workflow)

    assert set(triggers) == {"release"}
    assert triggers["release"] == {"types": ["published"]}
    assert "pull_request" not in triggers
    assert "push" not in triggers
    assert "workflow_dispatch" not in triggers


def test_publish_workflow_builds_once_and_reuses_validated_artifact() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    build = jobs["build"]
    publish = jobs["publish"]
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert source.count(
        "bash scripts/build_release.sh --strict-release-tag"
    ) == 1
    assert "--ordinary-ci" not in source
    assert 'bash scripts/package_smoke.sh "$GITHUB_WORKSPACE/dist"' in source
    assert publish["needs"] == "build"
    assert not any("checkout" in action for action in _uses(publish))
    assert "build_release.sh" not in str(publish)

    build_steps = [step.get("name") for step in build["steps"]]
    assert build_steps.index("Build wheel and source distribution once") < (
        build_steps.index("Upload exact validated distributions")
    )
    assert build_steps.index("Validate artifact metadata and release version") < (
        build_steps.index("Run clean installed-wheel package smoke")
    )
    assert build_steps.index("Run clean installed-wheel package smoke") < (
        build_steps.index("Upload exact validated distributions")
    )

    upload = next(step for step in build["steps"] if "upload-artifact" in step.get("uses", ""))
    download = next(
        step for step in publish["steps"] if "download-artifact" in step.get("uses", "")
    )
    assert upload["with"]["name"] == download["with"]["name"]
    assert "validated-distributions" in upload["with"]["name"]
    assert download["with"]["path"] == "validated-dist"
    assert publish["steps"][-1]["with"]["packages-dir"] == "validated-dist/"
    assert "dist/release-build-toolchain.json" in upload["with"]["path"]
    verify_download = publish["steps"][-2]["run"]
    assert "test -f validated-dist/release-build-toolchain.json" in verify_download
    assert "rm SHA256SUMS release-build-toolchain.json" in verify_download
    assert 'test "$(find validated-dist -maxdepth 1 -type f | wc -l | tr -d \' \')" = "2"' in verify_download


def test_publish_workflow_enforces_release_version_and_protected_oidc() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    build = jobs["build"]
    publish = jobs["publish"]
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert workflow["permissions"] == {"contents": "read"}
    assert "id-token" not in workflow["permissions"]
    assert build["permissions"] == {"contents": "read"}
    assert "id-token" not in build["permissions"]
    assert publish["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert publish["environment"]["name"] == "pypi"
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert "release.tag_name" in workflow["concurrency"]["group"]

    for job in (build, publish):
        condition = job["if"]
        assert "github.event_name == 'release'" in condition
        assert "github.event.action == 'published'" in condition
        assert "github.event.release.prerelease == false" in condition
        assert "github.event.release.tag_name == 'v0.3.0'" in condition

    for required_check in (
        'test "$GITHUB_REF_TYPE" = "tag"',
        'test "$GITHUB_REF_NAME" = "$RELEASE_TAG"',
        'test "$RELEASE_TAG" = "v${EXPECTED_VERSION}"',
        'test "v${package_version}" = "$RELEASE_TAG"',
        'EXPECTED_DISTRIBUTION: "agentguard-evals"',
        'wheel_metadata.get("Name")',
        'sdist_metadata.get("Name")',
        "names != {expected_name}",
        "wheel_metadata.get(\"Version\")",
        "sdist_metadata.get(\"Version\")",
        'test "$RELEASE_TAG" = "v0.3.0"',
        "agentguard_evals-0.3.0-py3-none-any.whl",
        "agentguard_evals-0.3.0.tar.gz",
        "release-build-toolchain.json",
    ):
        assert required_check in source

    lowered = source.lower()
    assert "testpypi" not in lowered
    assert "password:" not in lowered
    assert "repository-url" not in lowered
    assert "pypa/gh-action-pypi-publish@" in source
    publish_action = publish["steps"][-1]
    assert set(publish_action["with"]) == {"packages-dir", "verbose"}


def test_all_publish_workflow_actions_use_immutable_sha_pins() -> None:
    workflow = _workflow()
    actions = [
        action
        for job in workflow["jobs"].values()
        for action in _uses(job)
    ]

    assert actions
    for action in actions:
        repository, ref = action.rsplit("@", 1)
        assert "/" in repository
        assert FULL_SHA.fullmatch(ref), action


def test_release_docs_record_active_publisher_and_recovery() -> None:
    release_doc = RELEASE_DOC.read_text(encoding="utf-8")
    checklist = RELEASE_CHECKLIST.read_text(encoding="utf-8")
    combined = f"{release_doc}\n{checklist}"

    for required in (
        "TestPyPI Is Not Used",
        "belongs to an unrelated project",
        "independent project ownership",
        "clean environment",
        "Production PyPI publisher",
        "active production project publisher",
        "`agentguard-evals`",
        "`richinmrudul`",
        "`agentguard`",
        "`publish.yml`",
        "`pypi`",
        "manual approval",
        "Environment approval rejected or not granted",
        "Publication job fails before upload",
        "Version already used",
        "Tag/version/name mismatch",
        "Production package-name race",
        "GitHub release exists but PyPI publication failed",
        "Historical v0.2.1 Publication Incident",
        "cannot be\noverwritten",
        "new package version",
        "selected-tag deployment rule",
        "allows only `v0.3.0`",
        "byte-identical",
        "release-build-toolchain.txt",
        "release-build-toolchain.json",
        "controlled toolchain-lock update",
    ):
        assert required in combined

    assert "pipx install" in release_doc
    assert 'pip install "agentguard-evals==0.3.0"' in release_doc
    assert 'pipx install "agentguard-evals==0.3.0"' in release_doc
    assert "--index-url https://pypi.org/simple" in release_doc
    assert "RELEASE_TAG" in release_doc
    assert "unzip -l" in release_doc
    assert "tar -tzf" in release_doc


def test_readme_documents_current_production_pypi_availability() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "Current release:" in readme
    assert "`v0.3.0`" in readme
    assert "production PyPI" in readme
    assert "pip install agentguard-evals" in readme
    assert "pipx install agentguard-evals" in readme
    assert "Python import | `agentguard`" in readme
    assert "Terminal command | `agentguard`" in readme
    assert (
        "https://pypi.org/project/agentguard-evals/0.3.0/"
        in readme
    )
    assert (
        "https://github.com/richinmrudul/agentguard/releases/tag/v0.3.0"
        in readme
    )
    assert "docs/results/release-v0.3.0.md" in readme
    assert "PyPI publication remains deferred" not in readme
    assert "v0.3.0 source candidate" not in readme
    assert "pip install agentguard\n" not in readme
    assert "pipx install agentguard\n" not in readme
    assert "test.pypi.org" not in readme.lower()
    assert "TestPyPI project is unrelated" in readme
    assert "img.shields.io/pypi/v/agentguard-evals" in readme
    assert "img.shields.io/pypi/pyversions/agentguard-evals" in readme


def test_historical_release_artifacts_keep_original_identities() -> None:
    v010 = (ROOT / "docs/results/release-candidate-v0.1.0.json").read_text(
        encoding="utf-8"
    )
    v020 = (ROOT / "docs/results/release-candidate-v0.2.0.json").read_text(
        encoding="utf-8"
    )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "dist/agentguard-0.1.0-py3-none-any.whl" in v010
    assert "dist/agentguard-0.2.0-py3-none-any.whl" in v020
    assert "## v0.1.0 - Released" in changelog
    assert "## v0.2.0 - 2026-07-17" in changelog
    assert "## v0.2.1 - 2026-07-27" in changelog
