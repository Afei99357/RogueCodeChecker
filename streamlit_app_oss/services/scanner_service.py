"""
Scanner Service - Adapter layer between Streamlit and OSS scanners
"""

import os
import tempfile
from typing import Any, Dict, List, Optional

import pandas as pd

from roguecheck.models import Finding
from roguecheck.oss_runner import run_oss_tools
from roguecheck.policy import Policy


class ScannerService:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def scan_uploaded_files(self, uploaded_files: List) -> Dict[str, Any]:
        if not uploaded_files:
            return self._empty_results()

        results = {
            "findings_by_file": {},
            "all_findings": [],  # code issues only
            "diagnostics": [],  # engine advisories (OSS_ENGINE_*)
            "summary": {},
            "files_scanned": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                file_paths = self._save_uploaded_files(uploaded_files, temp_dir)
                policy = self._load_policy()
                tools = self.config.get(
                    "oss_tools", ["semgrep", "detect-secrets", "sqlfluff", "shellcheck"]
                )
                # Base packs from UI (or defaults)
                semgrep_packs = str(
                    self.config.get(
                        "semgrep_packs",
                        "p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/javascript,p/typescript",
                    )
                )
                # Auto-augment packs to match uploaded file types
                # Note: p/bash and p/sql don't exist in Semgrep registry - use ShellCheck and sql-strict instead
                ext_to_pack = {
                    ".py": "p/python",
                    ".js": "p/javascript",
                    ".ts": "p/typescript",
                    ".java": "p/java",
                    ".go": "p/go",
                    ".rb": "p/ruby",
                    ".php": "p/php",
                    ".cs": "p/csharp",
                    ".tf": "p/terraform",
                    ".yaml": "p/yaml",
                    ".yml": "p/yaml",
                }
                needed = {"p/security-audit"}
                for p in file_paths:
                    _, ext = os.path.splitext(p.lower())
                    if ext in ext_to_pack:
                        needed.add(ext_to_pack[ext])
                    # Dockerfile detection (no extension)
                    base = os.path.basename(p).lower()
                    if base == "dockerfile":
                        needed.add("p/dockerfile")
                # Merge with user-provided packs
                current = {s.strip() for s in semgrep_packs.split(",") if s.strip()}
                merged = current.union(needed)
                semgrep_packs = ",".join(sorted(merged))
                # Always enable strict SQL checks by default
                tools = list(tools) + ["sql-strict"]
                # Pass explicit file list so tools target exactly the uploaded files
                all_findings = run_oss_tools(
                    root=temp_dir,
                    policy=policy,
                    tools=list(tools),
                    semgrep_config=semgrep_packs,
                    files=file_paths,
                )
                filtered: List[Finding] = []
                for finding in all_findings:
                    if str(finding.rule_id).startswith("OSS_ENGINE_"):
                        results["diagnostics"].append(finding)
                        continue
                    filename = finding.path
                    results["findings_by_file"].setdefault(filename, []).append(finding)
                    filtered.append(finding)
                results["all_findings"] = filtered
                results["files_scanned"] = [f.name for f in uploaded_files]
                results["summary"] = self._generate_summary(filtered)
            except Exception as e:
                results["error"] = str(e)
                results["summary"] = {"error": True, "message": str(e)}

        return results

    def findings_to_dataframe(self, findings: List[Finding]) -> pd.DataFrame:
        if not findings:
            return pd.DataFrame()
        data = []
        for finding in findings:
            data.append(
                {
                    "File": finding.path,
                    "Rule ID": finding.rule_id,
                    "Severity": finding.severity,
                    "Message": finding.message,
                    "Line": finding.position.line,
                    "Column": finding.position.column,
                    "Recommendation": finding.recommendation
                    or "No recommendation available",
                    "Snippet": finding.snippet or "No code snippet available",
                }
            )
        df = pd.DataFrame(data)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        df["Severity_Order"] = df["Severity"].map(severity_order)
        df = df.sort_values(["Severity_Order", "File"], ascending=[False, True])
        df = df.drop("Severity_Order", axis=1)
        return df

    def _save_uploaded_files(self, uploaded_files: List, temp_dir: str) -> List[str]:
        file_paths = []
        for uploaded_file in uploaded_files:
            file_path = os.path.join(temp_dir, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getvalue())
            file_paths.append(file_path)
        return file_paths

    def _load_policy(self) -> Policy:
        try:
            return Policy.load()
        except Exception:
            from roguecheck.policy import DEFAULT_ALLOWLISTS, DEFAULT_POLICY

            return Policy(DEFAULT_POLICY, DEFAULT_ALLOWLISTS)

    def _generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        if not findings:
            return {
                "total_issues": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "unique_files": 0,
                "unique_rules": 0,
            }
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        unique_files = set()
        unique_rules = set()
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )
            unique_files.add(finding.path)
            unique_rules.add(finding.rule_id)
        return {
            "total_issues": len(findings),
            "by_severity": severity_counts,
            "unique_files": len(unique_files),
            "unique_rules": len(unique_rules),
            "files_with_issues": len(unique_files),
        }

    def _empty_results(self) -> Dict[str, Any]:
        return {
            "findings_by_file": {},
            "all_findings": [],
            "summary": {
                "total_issues": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "unique_files": 0,
                "unique_rules": 0,
            },
            "files_scanned": [],
        }
