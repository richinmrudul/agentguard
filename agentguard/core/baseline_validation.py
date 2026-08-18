import json
import math
from pathlib import Path
from typing import Any, Iterable, Optional


MAX_BASELINE_BYTES = 5_000_000
MAX_BASELINE_ITEMS = 10_000
MAX_BASELINE_DEPTH = 32


def _reject_constant(value: str) -> None:
    raise ValueError("Baseline contains a non-finite number.")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Baseline contains a duplicate object field.")
        result[key] = value
    return result


def _validate_shape(value: Any, depth: int = 0) -> None:
    if depth > MAX_BASELINE_DEPTH:
        raise ValueError(
            f"Baseline exceeds the maximum nesting depth of {MAX_BASELINE_DEPTH}."
        )
    if isinstance(value, dict):
        if len(value) > MAX_BASELINE_ITEMS:
            raise ValueError(
                f"Baseline object exceeds the {MAX_BASELINE_ITEMS}-item limit."
            )
        for item in value.values():
            _validate_shape(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_BASELINE_ITEMS:
            raise ValueError(
                f"Baseline array exceeds the {MAX_BASELINE_ITEMS}-item limit."
            )
        for item in value:
            _validate_shape(item, depth + 1)


def load_baseline_json(path: Path, label: str) -> Any:
    try:
        with path.expanduser().open("rb") as file:
            content = file.read(MAX_BASELINE_BYTES + 1)
    except OSError as error:
        raise ValueError(f"Could not read {label}.") from error
    if len(content) > MAX_BASELINE_BYTES:
        raise ValueError(
            f"{label.capitalize()} exceeds the {MAX_BASELINE_BYTES}-byte limit."
        )
    if not content.strip():
        raise ValueError(f"{label.capitalize()} is empty.")
    try:
        text = content.decode("utf-8")
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label.capitalize()} is not valid JSON.") from error
    _validate_shape(value)
    return value


def require_fields(
    data: dict[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    label: str,
) -> None:
    required_fields = set(required)
    allowed_fields = required_fields | set(optional)
    missing = sorted(required_fields - data.keys())
    if missing:
        raise ValueError(f"{label} is missing field '{missing[0]}'.")
    unexpected = sorted(data.keys() - allowed_fields)
    if unexpected:
        raise ValueError(f"{label} contains an unexpected field.")


def require_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{label} must be {qualifier}.")
    return value


def require_int(
    value: Any,
    label: str,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer.")
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be at most {maximum}.")
    return value


def require_number(
    value: Any,
    label: str,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{label} must be finite.")
    if minimum is not None and number < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    if maximum is not None and number > maximum:
        raise ValueError(f"{label} must be at most {maximum}.")
    return number


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean.")
    return value
