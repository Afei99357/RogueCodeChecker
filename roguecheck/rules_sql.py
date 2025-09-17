import re
from typing import Iterable, List, Tuple

from .models import Finding, Position


def _line_from_index(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


GRANT_ALL_RE = re.compile(r"\bGRANT\s+ALL\b", re.IGNORECASE)
DROP_TABLE_RE = re.compile(r"\bDROP\s+TABLE\b(?!\s+IF\s+EXISTS\s+temp)", re.IGNORECASE)
DELETE_STMT_RE = re.compile(
    r"\bDELETE\s+FROM\s+([A-Za-z0-9_.\"]+)(.*?);", re.IGNORECASE | re.DOTALL
)


def run_sql_rules(path: str, text: str, policy) -> Iterable[Finding]:
    findings: List[Finding] = []
    for m in GRANT_ALL_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="EXCESSIVE_DATABASE_PERMISSIONS",
                severity="high",
                message="Broad GRANT ALL detected.",
                path=path,
                position=Position(_line_from_index(text, m.start()), 1),
                snippet=None,
                recommendation="Use least-privilege GRANTs on specific objects.",
            )
        )
    for m in DROP_TABLE_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="DESTRUCTIVE_TABLE_DROP",
                severity="medium",
                message="Potential destructive DROP TABLE.",
                path=path,
                position=Position(_line_from_index(text, m.start()), 1),
                snippet=None,
                recommendation="Avoid DROP outside migrations/tests or guard with IF EXISTS and temp scope.",
            )
        )
    # DELETE without WHERE
    for m in DELETE_STMT_RE.finditer(text):
        stmt = m.group(0)
        if re.search(r"\bWHERE\b", stmt, re.IGNORECASE) is None:
            findings.append(
                Finding(
                    rule_id="UNSAFE_DELETE_ALL_ROWS",
                    severity="high",
                    message="DELETE statement without WHERE clause.",
                    path=path,
                    position=Position(_line_from_index(text, m.start()), 1),
                    snippet=None,
                    recommendation="Add a WHERE clause or guard with partition predicates.",
                )
            )
    return findings


def get_rules():
    return [run_sql_rules]
