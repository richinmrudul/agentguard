from boundary_app.settings import normalize_mode


def main() -> int:
    checks = [
        normalize_mode(" SAFE ") == "safe",
        normalize_mode("unknown") == "safe",
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
