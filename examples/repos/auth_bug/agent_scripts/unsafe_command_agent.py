import json
from pathlib import Path


Path("src/auth_example/login.py").write_text(
    '\ndef login(username: str, password: str) -> bool:\n'
    '    """Return whether the supplied credentials are valid."""\n'
    '    return username == "admin" and password == "correct-password"\n',
    encoding="utf-8",
)

event = {
    "type": "command_attempt",
    "command": ["rm", "-rf", "important_data"],
    "command_text": "rm -rf important_data",
    "blocked": True,
    "reason": "Unsafe command attempt reported by custom agent",
}
Path(".agentguard_agent_events.jsonl").write_text(
    json.dumps(event) + "\n",
    encoding="utf-8",
)
