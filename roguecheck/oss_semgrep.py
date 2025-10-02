import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet

SEMGREP_BIN = shutil.which("semgrep")


def _map_severity(level: str) -> str:
    lvl = (level or "").strip().upper()
    if lvl in {"CRITICAL"}:
        return "critical"
    if lvl in {"ERROR", "HIGH"}:
        return "high"
    if lvl in {"WARNING", "MEDIUM"}:
        return "medium"
    return "low"


def scan_with_semgrep(
    root: str,
    policy: Policy,
    semgrep_config: str = "auto",
    files: Optional[List[str]] = None,
) -> List[Finding]:
    """
    Run Semgrep against the given root and convert results to RogueCheck findings.

    Notes:
      - Requires `semgrep` to be installed and available on PATH.
      - The default `--config=auto` may fetch rules from the network depending on environment.
    """
    findings: List[Finding] = []
    if SEMGREP_BIN is None:
        # Soft failure: return an informative low-sev finding
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_SEMGREP",
                severity="low",
                message="Semgrep is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install semgrep (pipx install semgrep) or switch --engine=builtin.",
            )
        )
        return findings

    cmd = [SEMGREP_BIN, "--json", "--quiet"]
    # Support multiple configs separated by comma
    configs = [c.strip() for c in str(semgrep_config).split(",") if c.strip()]
    if not configs:
        configs = ["auto"]
    for cfg in configs:
        cmd.append(f"--config={cfg}")
    if files:
        # Pass explicit files (relative or absolute). Semgrep supports multiple target paths.
        cmd.extend(files)
    else:
        cmd.append(root)
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
                rule_id="OSS_ENGINE_ERROR",
                severity="low",
                message=f"Failed to run Semgrep: {e}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Verify Semgrep installation and configuration.",
            )
        )
        return findings

    if proc.returncode not in (0, 1):  # 0=ok/no findings, 1=findings, others=errors
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_SEMGREP_NONZERO",
                severity="low",
                message=f"Semgrep exited with code {proc.returncode}: {proc.stderr.strip()[:200]}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Check Semgrep config or pass --semgrep-config pointing to valid rules.",
            )
        )
        # still attempt to parse any output

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_SEMGREP_PARSE_ERROR",
                severity="low",
                message="Failed to parse Semgrep JSON output.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Re-run with a simpler config or update Semgrep.",
            )
        )
        return findings

    for r in data.get("results", []) or []:
        path = r.get("path") or root
        check_id = r.get("check_id") or r.get("rule_id") or "SEMGREP_RULE"
        extra = r.get("extra", {}) or {}
        sev = _map_severity(extra.get("severity", ""))
        msg = extra.get("message", "Semgrep finding")
        start = r.get("start", {}) or {}
        line = int(start.get("line", 1) or 1)

        snippet: Optional[str] = None
        try:
            full_path = path if os.path.isabs(path) else os.path.join(root, path)
            text = read_text(full_path)
            snippet = safe_snippet(text, line)
        except Exception:
            snippet = None

        findings.append(
            Finding(
                rule_id=f"SEMGREP:{check_id}",
                severity=sev,  # type: ignore[arg-type]
                message=msg,
                path=relpath(path, root),
                position=Position(line=line, column=int(start.get("col", 1) or 1)),
                snippet=snippet,
                recommendation=None,
                meta={"engine": "semgrep"},
            )
        )

    return findings
