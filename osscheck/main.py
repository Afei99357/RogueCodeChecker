import argparse
import os
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
        default="p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql",
        help="Semgrep config (comma-separated: registry packs like p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql, or 'auto')",
    )
    sp.add_argument(
        "--tools",
        default="semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict",
        help="Comma-separated list of tools to run",
    )
    sp.add_argument(
        "--no-sql-strict",
        action="store_true",
        help="Disable strict raw .sql checks (enabled by default)",
    )
    sp.add_argument("--paths-from", help="File listing files to scan (one per line)")
    sp.add_argument(
        "--per-file-out-dir",
        help="Directory to write one report per input file (e.g., name_report.md)",
    )
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
        # Ensure strict SQL is enabled by default unless explicitly disabled
        if args.no_sql_strict:
            selected = [t for t in selected if t != "sql-strict"]
        elif "sql-strict" not in selected:
            selected.append("sql-strict")
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

        # Optional per-file reports
        if args.per_file_out_dir:
            os.makedirs(args.per_file_out_dir, exist_ok=True)
            # group findings by file path
            by_file: dict[str, list[Finding]] = {}
            for f in findings:
                by_file.setdefault(f.path, []).append(f)

            # Determine input files to ensure every input gets a report, even with no findings
            input_files_rel: list[str] = []
            if args.paths_from:
                # Respect explicit list; normalize relative to root path
                tmp: list[str] = []
                try:
                    with open(args.paths_from, "r", encoding="utf-8") as fl:
                        tmp = [ln.strip() for ln in fl.read().splitlines() if ln.strip()]
                except Exception:
                    tmp = []
                for pth in tmp:
                    ap = pth if os.path.isabs(pth) else os.path.abspath(os.path.join(args.path, pth))
                    try:
                        rp = os.path.relpath(ap, args.path if os.path.isdir(args.path) else os.path.dirname(os.path.abspath(args.path)))
                    except Exception:
                        rp = os.path.basename(ap)
                    input_files_rel.append(rp)
            elif os.path.isdir(args.path):
                for dirpath, _, filenames in os.walk(args.path):
                    for fn in filenames:
                        full = os.path.join(dirpath, fn)
                        try:
                            rp = os.path.relpath(full, args.path)
                        except Exception:
                            rp = fn
                        input_files_rel.append(rp)
            elif os.path.isfile(args.path):
                # Single file: just use its basename
                input_files_rel.append(os.path.basename(args.path))

            # Write one report per input file
            ext = {"md": ".md", "json": ".json", "sarif": ".sarif"}[args.format]
            written = []
            for rel in sorted(set(input_files_rel)):
                fs = by_file.get(rel, [])
                base = os.path.splitext(os.path.basename(rel))[0]
                out_path = os.path.join(args.per_file_out_dir, f"{base}_report{ext}")
                content = _render(fs, args.format)
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                written.append(out_path)
            if written:
                print(f"Wrote per-file reports: {len(written)} files", file=sys.stderr)

        worst = max([SEV_ORDER.get(f.severity, 0) for f in findings], default=0)
        if worst >= SEV_ORDER[args.fail_on]:
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
