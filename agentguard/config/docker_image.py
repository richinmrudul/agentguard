import re


_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_REGISTRY_HOST = (
    rf"(?:localhost|{_HOST_LABEL}(?:\.{_HOST_LABEL})*|\[[0-9A-Fa-f:.]+\])"
    r"(?::[1-9][0-9]{0,4})?"
)
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"sha256:[0-9A-Fa-f]{64}"
DOCKER_IMAGE_REFERENCE = re.compile(
    rf"^(?:(?:{_REGISTRY_HOST})/)?"
    rf"{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*"
    rf"(?::{_TAG})?(?:@{_DIGEST})?$"
)


def validate_docker_image_reference(image: str) -> None:
    if image.startswith("-"):
        raise ValueError("Config field 'sandbox.image' must not begin with '-'.")
    if any(ord(character) < 32 or ord(character) == 127 for character in image):
        raise ValueError(
            "Config field 'sandbox.image' must not contain control characters."
        )
    if DOCKER_IMAGE_REFERENCE.fullmatch(image) is None:
        raise ValueError(
            "Config field 'sandbox.image' must be a valid Docker image reference."
        )
    name_and_tag = image.split("@", 1)[0]
    first_component, separator, _ = name_and_tag.partition("/")
    if separator and not first_component.startswith("[") and ":" in first_component:
        port = int(first_component.rsplit(":", 1)[1])
        if port > 65535:
            raise ValueError(
                "Config field 'sandbox.image' registry port must be at most 65535."
            )
    if separator and first_component.startswith("[") and "]:" in first_component:
        port = int(first_component.rsplit(":", 1)[1])
        if port > 65535:
            raise ValueError(
                "Config field 'sandbox.image' registry port must be at most 65535."
            )
