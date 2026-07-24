import difflib
from typing import Any, TextIO

import yaml


class StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: StrictSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml(stream: TextIO) -> Any:
    return yaml.load(stream, Loader=StrictSafeLoader)


def reject_unknown_keys(
    mapping: dict[str, Any],
    allowed: set[str],
    field_name: str = "",
) -> None:
    unknown = sorted((key for key in mapping if key not in allowed), key=str)
    if not unknown:
        return
    key = unknown[0]
    path = f"{field_name}.{key}" if field_name else str(key)
    message = f"Unknown config field '{path}'."
    if isinstance(key, str):
        matches = difflib.get_close_matches(key, sorted(allowed), n=1, cutoff=0.6)
        if matches:
            suggestion = (
                f"{field_name}.{matches[0]}" if field_name else matches[0]
            )
            message += f" Did you mean '{suggestion}'?"
    raise ValueError(message)
