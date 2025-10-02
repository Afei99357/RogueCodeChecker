import argparse
import sys

from core.models import Finding
from core.policy import Policy
from core.report import SEV_ORDER, to_markdown, to_json, to_sarif
from roguecheck.oss_semgrep import scan_with_semgrep

FORMATS = {"md": "markdown", "json": "json", "sarif": "sarif"}


def _render(findings: list[Finding], fmt: str) -> str:
    if fmt == "md":
        return to_markdown(findings)
    if fmt == "json":
        return to_json(findings)
    return to_sarif(findings)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="osscheck", description="Scan using open-source tools (Semgrep)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="Scan a path or file list with Semgrep")
    sp.add_argument("--path", default=".", help="root path to scan")
    sp.add_argument("--format", choices=list(FORMATS.keys()), default="md")
    sp.add_argument(
        "--semgrep-config",
        default="semgrep_rules,auto",
        help="Semgrep config (comma-separated: dirs/files/registry or 'auto')",
    )
    sp.add_argument(
        "--tools",
        default="semgrep,detect-secrets,sqlfluff",
        help="Comma-separated list of tools to run",
    )
    sp.add_argument("--paths-from", help="File listing files to scan (one per line)")
    sp.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
    )
    sp.add_argument("--out", help="write report to file instead of stdout")

    args = p.parse_args(argv)

    if args.cmd == "scan":
        pol = Policy.load()  # policy is not enforced by OSS tools but kept for future use

        # Optional explicit file list
        files = None
        if args.paths_from:
            try:
                with open(args.paths_from, "r", encoding="utf-8") as fl:
                    files = [ln.strip() for ln in fl.read().splitlines() if ln.strip()]
            except Exception as e:
                print(f"Failed to read --paths-from: {e}", file=sys.stderr)
                return 2

        selected = [t.strip() for t in str(args.tools).split(",") if t.strip()]
        from core.oss_runner import run_oss_tools

        findings = run_oss_tools(
            root=args.path,
            policy=pol,
            tools=selected,
            semgrep_config=args.semgrep_config,
            files=files,
        )

        out = _render(findings, args.format)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)

        worst = max([SEV_ORDER.get(f.severity, 0) for f in findings], default=0)
        if worst >= SEV_ORDER[args.fail_on]:
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
