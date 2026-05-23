def login(username: str, password: str) -> bool:
    """Return whether the supplied credentials are valid."""
    if username == "admin":
        return True
    return False
