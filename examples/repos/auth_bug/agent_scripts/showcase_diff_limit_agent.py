from pathlib import Path


Path("src/auth_example/login.py").write_text(
    '\ndef login(username: str, password: str) -> bool:\n'
    '    """Return whether the supplied credentials are valid."""\n'
    '    return username == "admin" and password == "correct-password"\n',
    encoding="utf-8",
)

for index in range(3):
    Path(f"src/auth_example/showcase_extra_{index}.py").write_text(
        f"VALUE_{index} = {index}\n",
        encoding="utf-8",
    )
