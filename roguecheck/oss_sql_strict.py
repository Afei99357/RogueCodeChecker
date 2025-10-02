import os
import re
from typing import List, Optional

from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet


GRANT_ALL_RE = re.compile(r"\bGRANT\s+ALL\b", re.IGNORECASE)
DROP_TABLE_RE = re.compile(r"\bDROP\s+TABLE\b(?!\s+IF\s+EXISTS\s+temp)", re.IGNORECASE)
DELETE_STMT_RE = re.compile(r"\bDELETE\s+FROM\s+([A-Za-z0-9_.\"]+)(.*?);", re.IGNORECASE | re.DOTALL)


def _line_from_index(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_strict_sql(root: str, policy: Policy, files: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []

    # Collect targets
    targets: List[str] = []
    if files:
        for f in files:
            p = f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f))
            if p.lower().endswith(".sql"):
                targets.append(p)
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith(".sql"):
                    targets.append(os.path.join(dirpath, fn))

    for path in targets:
        try:
            text = read_text(path)
        except Exception:
            continue

        # GRANT ALL
        for m in GRANT_ALL_RE.finditer(text):
            findings.append(
                Finding(
                    rule_id="SQL_STRICT_GRANT_ALL",
                    severity="high",
                    message="Broad GRANT ALL detected.",
                    path=relpath(path, root),
                    position=Position(_line_from_index(text, m.start()), 1),
                    snippet=safe_snippet(text, _line_from_index(text, m.start())),
                    recommendation="Use least-privilege GRANTs on specific objects.",
                )
            )

        # DROP TABLE (non-temp)
        for m in DROP_TABLE_RE.finditer(text):
            findings.append(
                Finding(
                    rule_id="SQL_STRICT_DROP_TABLE",
                    severity="medium",
                    message="Potential destructive DROP TABLE.",
                    path=relpath(path, root),
                    position=Position(_line_from_index(text, m.start()), 1),
                    snippet=safe_snippet(text, _line_from_index(text, m.start())),
                    recommendation="Avoid DROP outside migrations/tests or guard with IF EXISTS and temp scope.",
                )
            )

        # DELETE without WHERE
        for m in DELETE_STMT_RE.finditer(text):
            stmt = m.group(0)
            if re.search(r"\bWHERE\b", stmt, re.IGNORECASE) is None:
                findings.append(
                    Finding(
                        rule_id="SQL_STRICT_DELETE_ALL",
                        severity="high",
                        message="DELETE statement without WHERE clause.",
                        path=relpath(path, root),
                        position=Position(_line_from_index(text, m.start()), 1),
                        snippet=safe_snippet(text, _line_from_index(text, m.start())),
                        recommendation="Add a WHERE clause or guard with partition predicates.",
                    )
                )

    return findings

