import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet

DS_BIN = shutil.which("detect-secrets")


def _severity_for_secret(secret_type: str) -> str:
    t = (secret_type or "").lower()
    if any(k in t for k in ("token", "password", "apikey", "private")):
        return "critical"
    return "high"


def scan_with_detect_secrets(
    root: str, policy: Policy, files: Optional[List[str]] = None
) -> List[Finding]:
    findings: List[Finding] = []
    if DS_BIN is None:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_DETECT_SECRETS",
                severity="low",
                message="detect-secrets is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install detect-secrets (pipx install detect-secrets).",
            )
        )
        return findings

    targets: List[str] = []
    if files:
        targets.extend(files)
    else:
        targets.append(root)

    cmd = [DS_BIN, "scan", "--all-files"] + targets
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root)) or None,
            timeout=300,
        )
    except Exception as e:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_DETECT_SECRETS_ERROR",
                severity="low",
                message=f"Failed to run detect-secrets: {e}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Verify installation and permissions.",
            )
        )
        return findings

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_DETECT_SECRETS_PARSE_ERROR",
                severity="low",
                message="Failed to parse detect-secrets JSON output.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Update detect-secrets and retry.",
            )
        )
        return findings

    results = data.get("results", {}) or {}
    for path, items in results.items():
        for it in items or []:
            stype = it.get("type", "secret")
            line = int(it.get("line_number", 1) or 1)
            sev = _severity_for_secret(stype)
            snippet: Optional[str] = None
            try:
                full = path if os.path.isabs(path) else os.path.join(root, path)
                snippet = safe_snippet(read_text(full), line)
            except Exception:
                snippet = None
            findings.append(
                Finding(
                    rule_id=f"DETECT-SECRETS:{stype}",
                    severity=sev,  # type: ignore[arg-type]
                    message=f"Possible secret detected: {stype}",
                    path=relpath(path, root),
                    position=Position(line=line, column=1),
                    snippet=snippet,
                    recommendation="Rotate and remove hardcoded secrets. Use a secrets manager.",
                    meta={"engine": "detect-secrets"},
                )
            )

    return findings

