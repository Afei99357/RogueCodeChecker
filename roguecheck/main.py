import argparse
import sys

from .policy import Policy
from .scanner import SEV_ORDER, Scanner
try:
    # Optional OSS engine (Semgrep). Imported lazily when selected.
    from .oss_semgrep import scan_with_semgrep
except Exception:
    scan_with_semgrep = None  # type: ignore

FORMATS = {"md": "markdown", "json": "json", "sarif": "sarif"}


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="roguecheck", description="Scan for rogue code patterns"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="Scan a path")
    sp.add_argument("--path", default=".", help="root path to scan")
    sp.add_argument("--policy", default="policy.yaml", help="policy file")
    sp.add_argument("--allowlists", default="allowlists.yaml", help="allowlists file")
    sp.add_argument("--format", choices=list(FORMATS.keys()), default="md")
    sp.add_argument(
        "--engine",
        choices=["builtin", "oss"],
        default="builtin",
        help="Select scanning engine: builtin rules or OSS tools (Semgrep)",
    )
    sp.add_argument(
        "--semgrep-config",
        default="auto",
        help="Semgrep config (path/URL/registry), used when --engine=oss",
    )
    sp.add_argument(
        "--paths-from",
        help="Path to a text file listing files to scan (one per line)",
    )
    sp.add_argument(
        "--fail-on", choices=["low", "medium", "high", "critical"], default="high"
    )
    sp.add_argument("--out", help="write report to file instead of stdout")

    args = p.parse_args(argv)

    if args.cmd == "scan":
        pol = Policy.load(args.policy, args.allowlists)
        # Optional file list
        file_list = None
        if args.paths_from:
            try:
                with open(args.paths_from, "r", encoding="utf-8") as fl:
                    file_list = [
                        ln.strip() for ln in fl.read().splitlines() if ln.strip()
                    ]
            except Exception as e:
                print(f"Failed to read --paths-from: {e}", file=sys.stderr)
                sys.exit(2)

        if args.engine == "oss":
            if scan_with_semgrep is None:
                print(
                    "[oss] Semgrep engine unavailable. Ensure dependencies are installed.",
                    file=sys.stderr,
                )
                findings = []
            else:
                findings = scan_with_semgrep(
                    root=args.path,
                    policy=pol,
                    semgrep_config=args.semgrep_config,
                    files=file_list,
                )
        else:
            sc = Scanner(args.path, pol)
            if file_list:
                findings = sc.scan_files(file_list)
            else:
                findings = sc.scan()

        if args.format == "md":
            out = Scanner.to_markdown(findings)
        elif args.format == "json":
            out = Scanner.to_json(findings)
        else:
            out = Scanner.to_sarif(findings)

        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)

        worst = max([SEV_ORDER.get(f.severity, 0) for f in findings], default=0)
        if worst >= SEV_ORDER[args.fail_on]:
            sys.exit(1)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
