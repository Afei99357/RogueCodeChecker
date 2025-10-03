import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .policy import Policy
from .utils import relpath


def _which_abs(name: str) -> Optional[str]:
    p = shutil.which(name)
    if not p:
        return None
    return os.path.abspath(p)


def _map_level(level: str) -> str:
    l = (level or "").lower()
    if l == "error":
        return "high"
    if l == "warning":
        return "medium"
    return "low"


def scan_with_shellcheck(root: str, policy: Policy, files: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    # Build targets (.sh or .bash if explicit list, else scan root)
    targets: List[str] = []
    if files:
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in {".sh", ".bash"}:
                targets.append(os.path.abspath(os.path.join(root, f)) if not os.path.isabs(f) else f)
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith((".sh", ".bash")):
                    targets.append(os.path.join(dirpath, fn))

    if not targets:
        return findings

    sh_bin = _which_abs("shellcheck")
    if sh_bin is None:
        # Only warn if there are shell targets to scan
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_SHELLCHECK",
                severity="low",
                message="shellcheck is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install shellcheck (e.g., apt/brew install shellcheck or pipx install shellcheck-py).",
            )
        )
        return findings

    for path in targets:
        try:
            proc = subprocess.run(
                [sh_bin, "-f", "json", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="OSS_ENGINE_SHELLCHECK_ERROR",
                    severity="low",
                    message=f"Failed to run shellcheck: {e}",
                    path=relpath(path, root),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Verify shellcheck installation and permissions.",
                )
            )
            continue

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            findings.append(
                Finding(
                    rule_id="OSS_ENGINE_SHELLCHECK_PARSE_ERROR",
                    severity="low",
                    message="Failed to parse shellcheck JSON output.",
                    path=relpath(path, root),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Update shellcheck or rerun with simpler flags.",
                )
            )
            continue
        # ShellCheck -f json may return a list of comments or an object with "comments" key.
        comments = []
        if isinstance(data, list):
            comments = data
        elif isinstance(data, dict):
            comments = data.get("comments", []) or []
        for item in comments:
            code = item.get("code")
            level = item.get("level", "warning")
            message = item.get("message", "ShellCheck finding")
            line = int(item.get("line", 1) or 1)
            findings.append(
                Finding(
                    rule_id=f"SHELLCHECK:SC{code}" if code else "SHELLCHECK",
                    severity=_map_level(level),  # type: ignore[arg-type]
                    message=message,
                    path=relpath(path, root),
                    position=Position(line=line, column=1),
                    snippet=None,
                    recommendation=None,
                    meta={"engine": "shellcheck", "code": code, "level": level},
                )
            )

    return findings
