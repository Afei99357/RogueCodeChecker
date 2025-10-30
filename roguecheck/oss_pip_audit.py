import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .utils import relpath

_ORIG_CWD = os.getcwd()


def _which_abs(name: str) -> Optional[str]:
    p = shutil.which(name)
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.abspath(os.path.join(_ORIG_CWD, p))


def _severity_for_vulnerability(vuln_data: dict) -> str:
    """Map vulnerability data to severity levels."""
    # pip-audit doesn't provide CVSS scores in all cases, so we use heuristics
    # Check if there are any known vulnerabilities
    if vuln_data.get("is_vulnerable", False):
        # If we have aliases (like CVE IDs), it's likely a known serious issue
        aliases = vuln_data.get("aliases", [])
        if aliases:
            return "high"
        return "medium"
    return "low"


def scan_with_pip_audit(root: str, files: Optional[List[str]] = None) -> List[Finding]:
    """Scan Python dependencies for known vulnerabilities using pip-audit.

    pip-audit scans Python packages for known security vulnerabilities
    by checking against the PyPI Advisory Database.
    """
    findings: List[Finding] = []
    pip_audit_bin = _which_abs("pip-audit")

    if pip_audit_bin is None:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_PIP_AUDIT",
                severity="low",
                message="pip-audit is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install pip-audit (pip install pip-audit or add to pyproject.toml).",
            )
        )
        return findings

    # pip-audit scans the current environment or requirements files
    # We'll look for common dependency files in the root directory
    dependency_files = []
    for fname in [
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        "Pipfile",
    ]:
        fpath = os.path.join(root, fname)
        if os.path.isfile(fpath):
            dependency_files.append(fname)

    if not dependency_files:
        # No dependency files found, skip
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_PIP_AUDIT_NO_DEPS",
                severity="low",
                message="No Python dependency files found (requirements.txt, pyproject.toml, etc.).",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="pip-audit requires a requirements.txt, pyproject.toml, or similar file.",
            )
        )
        return findings

    # Run pip-audit with JSON output
    # We'll scan the first dependency file found (typically requirements.txt or pyproject.toml)
    target_file = os.path.join(root, dependency_files[0])

    cmd = [pip_audit_bin, "--format", "json"]

    # Determine which argument to use based on file type
    if dependency_files[0] in ["requirements.txt", "requirements-dev.txt"]:
        cmd.extend(["--requirement", target_file])
    elif dependency_files[0] == "pyproject.toml":
        # pip-audit can scan pyproject.toml directly when in that directory
        cmd.extend(["--requirement", target_file])
    else:
        # For other files, try to scan the environment
        cmd.extend(["--local"])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            cwd=root,  # Run in the target directory
        )
        # pip-audit exits with code 1 when vulnerabilities are found
        if proc.returncode not in (0, 1):
            findings.append(
                Finding(
                    rule_id="OSS_ENGINE_PIP_AUDIT_ERROR",
                    severity="low",
                    message=f"pip-audit scan failed: {proc.stderr}",
                    path=relpath(root, os.getcwd()),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Check pip-audit installation and dependency file format.",
                )
            )
            return findings
    except subprocess.TimeoutExpired:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_PIP_AUDIT_TIMEOUT",
                severity="low",
                message="pip-audit scan timed out after 5 minutes.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Try scanning with fewer dependencies or increase timeout.",
            )
        )
        return findings
    except Exception as e:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_PIP_AUDIT_ERROR",
                severity="low",
                message=f"Failed to run pip-audit: {e}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Verify pip-audit installation and permissions.",
            )
        )
        return findings

    # Parse JSON output
    try:
        results = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_PIP_AUDIT_PARSE_ERROR",
                severity="low",
                message="Failed to parse pip-audit JSON output.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Update pip-audit and retry.",
            )
        )
        return findings

    # Process vulnerabilities
    # pip-audit JSON format: list of dicts with "name", "version", "vulns"
    for package in results:
        package_name = package.get("name", "unknown")
        package_version = package.get("version", "unknown")
        vulnerabilities = package.get("vulns", [])

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", "UNKNOWN")
            description = vuln.get("description", "Vulnerability detected")
            fix_versions = vuln.get("fix_versions", [])
            aliases = vuln.get("aliases", [])

            # Build severity
            sev = _severity_for_vulnerability(vuln)

            # Build message
            alias_str = f" ({', '.join(aliases)})" if aliases else ""
            message = f"Vulnerable package: {package_name}=={package_version}{alias_str} - {description}"

            # Build recommendation
            if fix_versions:
                recommendation = f"Update {package_name} to version {', '.join(fix_versions)} or later."
            else:
                recommendation = f"Review {package_name} vulnerability {vuln_id} and update to a patched version."

            findings.append(
                Finding(
                    rule_id=f"PIP-AUDIT:{vuln_id}",
                    severity=sev,  # type: ignore[arg-type]
                    message=message,
                    path=relpath(dependency_files[0], root),
                    position=Position(line=1, column=1),
                    snippet=f"{package_name}=={package_version}",
                    recommendation=recommendation,
                    meta={
                        "engine": "pip-audit",
                        "package": package_name,
                        "version": package_version,
                        "fix_versions": fix_versions,
                        "aliases": aliases,
                    },
                )
            )

    return findings
