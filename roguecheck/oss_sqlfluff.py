import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .utils import read_text, relpath, safe_snippet

_ORIG_CWD = os.getcwd()


def _which_abs(name: str) -> Optional[str]:
    p = shutil.which(name)
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.abspath(os.path.join(_ORIG_CWD, p))


def scan_with_sqlfluff(root: str, files: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    sqlfluff_bin = _which_abs("sqlfluff")
    if sqlfluff_bin is None:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_SQLFLUFF",
                severity="low",
                message="sqlfluff is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install sqlfluff (pipx install sqlfluff).",
            )
        )
        return findings

    targets: List[str] = []
    if files:
        # Filter to SQL-like files to avoid noise
        targets.extend(
            [
                (f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f)))
                for f in files
                if os.path.splitext(f)[1].lower() in {".sql"}
            ]
        )
        if not targets:
            return []
    else:
        targets.append(os.path.abspath(root))

    cmd = [sqlfluff_bin, "lint", "--format", "json"] + targets
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except Exception as e:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_SQLFLUFF_ERROR",
                severity="low",
                message=f"Failed to run sqlfluff: {e}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Verify installation and configuration (sqlfluff.cfg).",
            )
        )
        return findings

    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_SQLFLUFF_PARSE_ERROR",
                severity="low",
                message="Failed to parse sqlfluff JSON output.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Update sqlfluff and retry.",
            )
        )
        return findings

    # data is a list of file results
    for file_res in data or []:
        path = file_res.get("filepath") or root
        violations = file_res.get("violations", []) or []
        for v in violations:
            code = v.get("code", "SQLFLUFF")
            desc = v.get("description", "SQL lint issue")
            line = int(v.get("line_no", 1) or 1)
            col = int(v.get("line_pos", 1) or 1)
            # sqlfluff is a linter; mark as low/medium
            severity = "medium" if code and code.startswith("L") else "low"
            snippet: Optional[str] = None
            try:
                full = path if os.path.isabs(path) else os.path.join(root, path)
                snippet = safe_snippet(read_text(full), line)
            except Exception:
                snippet = None

            findings.append(
                Finding(
                    rule_id=f"SQLFLUFF:{code}",
                    severity=severity,  # type: ignore[arg-type]
                    message=desc,
                    path=relpath(path, root),
                    position=Position(line=line, column=col),
                    snippet=snippet,
                    recommendation="Fix SQL linting issue or adjust sqlfluff config.",
                    meta={"engine": "sqlfluff"},
                )
            )

    return findings
