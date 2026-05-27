from dataclasses import dataclass


@dataclass(frozen=True)
class LimitedOutput:
    text: str
    truncated: bool


def _fit_utf8(text: str, max_bytes: int) -> str:
    fitted = text
    while len(fitted.encode("utf-8")) > max_bytes:
        fitted = fitted[:-1]
    return fitted


def limit_output(text: str, max_bytes: int) -> LimitedOutput:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return LimitedOutput(text=text, truncated=False)

    marker = f"[agentguard] Output truncated to last {max_bytes} bytes.\n"
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= max_bytes:
        return LimitedOutput(
            text=marker_bytes[:max_bytes].decode("utf-8", errors="replace"),
            truncated=True,
        )

    suffix_size = max_bytes - len(marker_bytes)
    suffix = encoded[-suffix_size:].decode("utf-8", errors="replace")
    return LimitedOutput(
        text=_fit_utf8(marker + suffix, max_bytes),
        truncated=True,
    )
