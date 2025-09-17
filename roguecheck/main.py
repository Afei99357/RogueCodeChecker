import argparse
import sys

from .policy import Policy
from .scanner import SEV_ORDER, Scanner

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
        "--fail-on", choices=["low", "medium", "high", "critical"], default="high"
    )
    sp.add_argument("--out", help="write report to file instead of stdout")

    args = p.parse_args(argv)

    if args.cmd == "scan":
        pol = Policy.load(args.policy, args.allowlists)
        sc = Scanner(args.path, pol)
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
