from formatter.labels import normalize_label


def main() -> int:
    return 0 if normalize_label(" Alpha ") == "alpha" else 1


if __name__ == "__main__":
    raise SystemExit(main())
