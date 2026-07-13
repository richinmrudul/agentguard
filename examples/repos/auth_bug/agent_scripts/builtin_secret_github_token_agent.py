from pathlib import Path


Path("src/auth_example/login.py").write_text(
    '\ndef login(username: str, password: str) -> bool:\n'
    '    """Return whether the supplied credentials are valid."""\n'
    '    return username == "admin" and password == "correct-password"\n',
    encoding="utf-8",
)

token = "ghp_" + "AGENTGUARD_FAKE_TOKEN_EXAMPLE_" + "000000000000"
Path("src/auth_example/oauth_client.py").write_text(
    'GITHUB_TOKEN = "' + token + '"\n',
    encoding="utf-8",
)
