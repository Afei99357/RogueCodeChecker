import json
from typing import List

from .models import Finding

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def to_markdown(findings: List[Finding]) -> str:
    if not findings:
        return "✅ No issues found."
    lines = ["# RogueCheck Report", ""]
    for f in findings:
        lines.append(f"## [{f.severity.upper()}] {f.rule_id} — {f.path}:{f.position.line}")
        lines.append(f"{f.message}\n")
        if f.snippet:
            lines.append("```\n" + f.snippet + "\n```")
        if f.recommendation:
            lines.append(f"**Fix:** {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.__dict__ for f in findings], default=lambda o: o.__dict__, indent=2)


def to_sarif(findings: List[Finding]) -> str:
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {"id": f.rule_id, "shortDescription": {"text": f.message[:80]}},
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": {
                    "low": "note",
                    "medium": "warning",
                    "high": "error",
                    "critical": "error",
                }[f.severity],
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.position.line},
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "RogueCheck", "rules": list(rules.values())}}, "results": results}
        ],
    }
    return json.dumps(sarif, indent=2)

