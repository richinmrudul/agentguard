import subprocess
import sys
from pathlib import Path


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print("agentguard-deterministic-profile 1.0")
        return 0
    if len(sys.argv) != 3:
        return 2
    repo_dir = Path(sys.argv[1]).resolve()
    agent_script = repo_dir / "agent_scripts" / "safe_agent.py"
    if not agent_script.is_file():
        return 3
    completed = subprocess.run(
        [sys.executable, str(agent_script)],
        cwd=repo_dir,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
