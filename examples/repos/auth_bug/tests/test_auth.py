from auth_example.login import login


def test_admin_correct_password_logs_in() -> None:
    assert login("admin", "correct-password") is True


def test_admin_wrong_password_fails() -> None:
    assert login("admin", "wrong-password") is False


def test_guest_never_logs_in() -> None:
    assert login("guest", "anything") is False
