import pytest

from agentguard.config.schema import ContainedEnvironmentEntry
from agentguard.sandbox.contained_environment import (
    SAFE_RUNTIME_ENVIRONMENT,
    resolve_contained_environment,
)


def test_default_contained_environment_has_only_fixed_runtime_defaults(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_SECRET_CANARY_HOST_ENV", "must-not-enter")

    resolved = resolve_contained_environment([])

    assert resolved.values == dict(sorted(SAFE_RUNTIME_ENVIRONMENT.items()))
    assert "AGENTGUARD_SECRET_CANARY_HOST_ENV" not in resolved.values
    assert resolved.diagnostics.defaults == sorted(SAFE_RUNTIME_ENVIRONMENT)
    assert resolved.diagnostics.supplied == []


def test_one_and_multiple_allowed_values_are_sorted() -> None:
    entries = [
        ContainedEnvironmentEntry(name="ZED", value="last"),
        ContainedEnvironmentEntry(name="ALPHA", value="first"),
    ]

    resolved = resolve_contained_environment(entries)

    assert list(resolved.values) == [
        "ALPHA",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "ZED",
    ]
    assert resolved.values["ALPHA"] == "first"
    assert resolved.values["ZED"] == "last"
    assert resolved.diagnostics.supplied == ["ALPHA", "ZED"]


def test_host_sourced_value_reads_only_requested_name(monkeypatch) -> None:
    monkeypatch.setenv("ALLOWED_VALUE", "present")
    monkeypatch.setenv("UNRELATED_SECRET", "absent")

    resolved = resolve_contained_environment(
        [ContainedEnvironmentEntry(name="ALLOWED_VALUE", source="host")]
    )

    assert resolved.values["ALLOWED_VALUE"] == "present"
    assert "UNRELATED_SECRET" not in resolved.values


def test_absent_optional_host_value_is_deterministically_recorded() -> None:
    resolved = resolve_contained_environment(
        [ContainedEnvironmentEntry(name="OPTIONAL_VALUE", source="host")]
    )

    assert "OPTIONAL_VALUE" not in resolved.values
    assert resolved.diagnostics.missing == ["OPTIONAL_VALUE"]


def test_absent_required_host_value_fails_without_value_echo() -> None:
    with pytest.raises(ValueError, match="REQUIRED_VALUE"):
        resolve_contained_environment(
            [
                ContainedEnvironmentEntry(
                    name="REQUIRED_VALUE",
                    source="host",
                    required=True,
                )
            ]
        )


def test_sensitive_value_enters_redaction_set_only_when_explicit() -> None:
    resolved = resolve_contained_environment(
        [
            ContainedEnvironmentEntry(
                name="API_TOKEN",
                value="secret-token-value",
                sensitive=True,
                allow_sensitive=True,
            )
        ]
    )

    assert resolved.values["API_TOKEN"] == "secret-token-value"
    assert resolved.sensitive_values == ["secret-token-value"]
    assert resolved.diagnostics.sensitive == ["API_TOKEN"]


@pytest.mark.parametrize("value", ["x" * 4097, "bad\nvalue", "bad\tvalue"])
def test_host_sourced_values_are_bounded_and_control_checked(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="Contained environment value"):
        resolve_contained_environment(
            [ContainedEnvironmentEntry(name="ALLOWED_VALUE", source="host")],
            host_environment={"ALLOWED_VALUE": value},
        )
