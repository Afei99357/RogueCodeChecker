import re
from typing import Iterable, List

from .models import Finding, Position

# Minimal Databricks-aware patterns (works for .py and .sql scanned elsewhere)
SPARK_UDF_IO_RE = re.compile(r"@udf\(|spark\.udf|pyspark\.sql\.functions\.udf")
IO_HINT_RE = re.compile(r"open\(|requests\.|urllib|http\.client")


def run_dbx_rules(path: str, text: str, policy) -> Iterable[Finding]:
    findings: List[Finding] = []
    # crude detection: UDF file/network I/O (just flag for review)
    if SPARK_UDF_IO_RE.search(text) and IO_HINT_RE.search(text):
        findings.append(
            Finding(
                rule_id="UDF_PERFORMANCE_ISSUE",
                severity="high",
                message="Possible file/network I/O inside/near UDF definition.",
                path=path,
                position=Position(1, 1),
                recommendation="Avoid I/O inside UDFs; move I/O outside and pass data as columns.",
            )
        )
    return findings


def get_rules():
    return [run_dbx_rules]
