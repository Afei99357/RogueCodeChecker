import json
import os
import shutil
import subprocess
import tempfile
from typing import List, Optional

from .models import Finding, Position
from .utils import read_text, relpath, safe_snippet

_ORIG_CWD = os.getcwd()


def _which_abs(name: str) -> Optional[str]:
    p = shutil.which(name)
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.abspath(os.path.join(_ORIG_CWD, p))


def _severity_for_secret(secret_type: str) -> str:
    """Map GitLeaks rule severity to our severity levels."""
    t = (secret_type or "").lower()
    # GitLeaks uses rule IDs like "generic-api-key", "aws-access-token", etc.
    if any(k in t for k in ("token", "password", "apikey", "api-key", "private")):
        return "critical"
    return "high"


def scan_with_gitleaks(root: str, files: Optional[List[str]] = None) -> List[Finding]:
    """Scan files for secrets using GitLeaks.

    GitLeaks can scan files or directories without requiring a git repository.
    """
    findings: List[Finding] = []
    gitleaks_bin = _which_abs("gitleaks")

    if gitleaks_bin is None:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_GITLEAKS",
                severity="low",
                message="gitleaks is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install gitleaks from https://github.com/gitleaks/gitleaks/releases",
            )
        )
        return findings

    targets: List[str] = []
    if files:
        targets.extend(
            [
                f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f))
                for f in files
            ]
        )
    else:
        targets.append(os.path.abspath(root))

    # GitLeaks outputs to a report file, use temp file for JSON output
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as report_file:
        report_path = report_file.name

    try:
        # Run gitleaks detect command
        # --no-git: scan files without requiring a git repository
        # --report-path: output JSON report
        # --report-format: JSON format
        # --source: directory or file to scan
        for target in targets:
            cmd = [
                gitleaks_bin,
                "detect",
                "--no-git",
                "--report-path",
                report_path,
                "--report-format",
                "json",
                "--source",
                target,
            ]
            try:
                # GitLeaks exits with code 1 when secrets are found
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300,
                )
                # Exit codes: 0 = no leaks, 1 = leaks found, 2+ = error
                if proc.returncode not in (0, 1):
                    findings.append(
                        Finding(
                            rule_id="OSS_ENGINE_GITLEAKS_ERROR",
                            severity="low",
                            message=f"GitLeaks scan failed: {proc.stderr}",
                            path=relpath(target, root),
                            position=Position(1, 1),
                            snippet=None,
                            recommendation="Check gitleaks installation and permissions.",
                        )
                    )
                    continue
            except subprocess.TimeoutExpired:
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_GITLEAKS_TIMEOUT",
                        severity="low",
                        message="GitLeaks scan timed out after 5 minutes.",
                        path=relpath(target, root),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation="Try scanning smaller directories or individual files.",
                    )
                )
                continue
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_GITLEAKS_ERROR",
                        severity="low",
                        message=f"Failed to run gitleaks: {e}",
                        path=relpath(target, root),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation="Verify installation and permissions.",
                    )
                )
                continue

        # Parse the JSON report
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    try:
                        results = json.loads(content)
                    except json.JSONDecodeError:
                        findings.append(
                            Finding(
                                rule_id="OSS_ENGINE_GITLEAKS_PARSE_ERROR",
                                severity="low",
                                message="Failed to parse gitleaks JSON output.",
                                path=relpath(root, os.getcwd()),
                                position=Position(1, 1),
                                snippet=None,
                                recommendation="Update gitleaks and retry.",
                            )
                        )
                        return findings

                    # Process findings
                    for item in results or []:
                        rule_id = item.get("RuleID", "unknown-rule")
                        description = item.get("Description", "Secret detected")
                        file_path = item.get("File", "")
                        line = int(item.get("StartLine", 1) or 1)
                        secret_snippet = item.get("Secret", "")
                        match = item.get("Match", "")

                        sev = _severity_for_secret(rule_id)
                        snippet: Optional[str] = None
                        try:
                            full = (
                                file_path
                                if os.path.isabs(file_path)
                                else os.path.join(root, file_path)
                            )
                            if os.path.exists(full):
                                snippet = safe_snippet(read_text(full), line)
                        except Exception:
                            snippet = None

                        # Mask the secret in the message for security
                        masked_secret = (
                            secret_snippet[:4] + "***"
                            if len(secret_snippet) > 4
                            else "***"
                        )

                        findings.append(
                            Finding(
                                rule_id=f"GITLEAKS:{rule_id}",
                                severity=sev,  # type: ignore[arg-type]
                                message=f"{description}: {masked_secret}",
                                path=relpath(file_path, root),
                                position=Position(line=line, column=1),
                                snippet=snippet,
                                recommendation="Rotate and remove hardcoded secrets. Use environment variables or a secrets manager.",
                                meta={"engine": "gitleaks", "match": match},
                            )
                        )

    finally:
        # Clean up temp report file
        if os.path.exists(report_path):
            try:
                os.unlink(report_path)
            except Exception:
                pass

    return findings
