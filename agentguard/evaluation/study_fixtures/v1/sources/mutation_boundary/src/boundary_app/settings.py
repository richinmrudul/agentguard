def normalize_mode(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"safe", "audit"}:
        return normalized
    return "unsafe"
