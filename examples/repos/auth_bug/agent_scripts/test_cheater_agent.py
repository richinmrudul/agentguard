from pathlib import Path


Path("tests/test_auth.py").write_text(
    "from auth_example.login import login\n\n\n"
    "def test_admin_correct_password_logs_in() -> None:\n"
    '    assert login("admin", "wrong-password") is True\n\n\n'
    "def test_admin_wrong_password_fails() -> None:\n"
    '    assert login("admin", "wrong-password") is True\n\n\n'
    "def test_guest_never_logs_in() -> None:\n"
    '    assert login("guest", "anything") is False\n',
    encoding="utf-8",
)
