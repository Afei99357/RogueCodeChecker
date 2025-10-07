import os
from typing import List, Optional

from .models import Finding, Position
from .utils import read_text, relpath, safe_snippet


def scan_with_sqlcheck(root: str, files: Optional[List[str]] = None) -> List[Finding]:
    """
    Use the sqlcheck Python library to analyze SQL files for anti-patterns.
    Only runs on .sql targets. If the library is unavailable, returns a low-sev
    informative finding.
    """
    findings: List[Finding] = []
    try:
        # sqlcheck 1.x provides `from sqlcheck.core import check_string`
        from sqlcheck.core import check_string  # type: ignore
    except Exception:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_SQLCHECK",
                severity="low",
                message="sqlcheck is not installed or not importable.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install sqlcheck (pip install sqlcheck) or remove from tool list.",
            )
        )
        return findings

    targets: List[str] = []
    if files:
        targets = [
            (f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f)))
            for f in files
            if os.path.splitext(f)[1].lower() == ".sql"
        ]
    else:
        # walk root
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith(".sql"):
                    targets.append(os.path.join(dirpath, fn))

    for path in targets:
        try:
            sql_text = read_text(path)
        except Exception:
            continue
        try:
            # returns list of tuples: (line_no, message)
            issues = check_string(sql_text)
        except Exception:
            issues = []
        for line_no, msg in issues or []:
            snippet = safe_snippet(sql_text, int(line_no) if line_no else 1)
            findings.append(
                Finding(
                    rule_id="SQLCHECK_FINDING",
                    severity="medium",
                    message=str(msg),
                    path=relpath(path, root),
                    position=Position(int(line_no) if line_no else 1, 1),
                    snippet=snippet,
                    recommendation="Revise query to avoid known SQL anti-pattern.",
                    meta={"engine": "sqlcheck"},
                )
            )

    return findings
