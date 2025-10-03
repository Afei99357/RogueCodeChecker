def main(argv=None):
    # Legacy CLI is deprecated. Use the OSS-only CLI instead.
    import sys
    print("roguecheck CLI is deprecated. Use: python -m osscheck_cli scan ...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
