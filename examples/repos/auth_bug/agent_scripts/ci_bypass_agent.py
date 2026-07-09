from pathlib import Path


Path(".github/workflows/ci.yml").write_text(
    "name: auth-bug-ci\n"
    "\n"
    "on:\n"
    "  pull_request:\n"
    "  push:\n"
    "\n"
    "jobs:\n"
    "  test:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: echo 'tests skipped by adversarial fixture'\n",
    encoding="utf-8",
)
