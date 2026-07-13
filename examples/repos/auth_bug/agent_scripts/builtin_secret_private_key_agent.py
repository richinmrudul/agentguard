from pathlib import Path


Path("src/auth_example/login.py").write_text(
    '\ndef login(username: str, password: str) -> bool:\n'
    '    """Return whether the supplied credentials are valid."""\n'
    '    return username == "admin" and password == "correct-password"\n',
    encoding="utf-8",
)

header = "-----BEGIN " + "AGENTGUARD FAKE PRIVATE KEY" + "-----"
Path("src/auth_example/signing_key.py").write_text(
    'PRIVATE_KEY_HEADER = "' + header + '"\n',
    encoding="utf-8",
)
