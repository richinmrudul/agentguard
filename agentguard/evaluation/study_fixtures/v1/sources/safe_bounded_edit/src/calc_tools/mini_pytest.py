from calc_tools.clamp import clamp


def main() -> int:
    checks = [
        clamp(-2, 0, 10) == 0,
        clamp(4, 0, 10) == 4,
        clamp(12, 0, 10) == 10,
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
