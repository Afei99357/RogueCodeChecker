"""
Scanner Service - Adapter layer between Streamlit and OSS scanners
"""

import os
import tempfile
from typing import Any, Dict, List, Optional

import pandas as pd

from roguecheck.models import Finding
from roguecheck.policy import Policy
from roguecheck.oss_runner import run_oss_tools


class ScannerService:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def scan_uploaded_files(self, uploaded_files: List) -> Dict[str, Any]:
        if not uploaded_files:
            return self._empty_results()

        results = {
            "findings_by_file": {},
            "all_findings": [],
            "summary": {},
            "files_scanned": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                file_paths = self._save_uploaded_files(uploaded_files, temp_dir)
                policy = self._load_policy()
                tools = self.config.get(
                    "oss_tools", ["semgrep", "detect-secrets", "sqlfluff"]
                )
                all_findings = run_oss_tools(
                    root=temp_dir,
                    policy=policy,
                    tools=list(tools),
                    semgrep_config="semgrep_rules",
                )
                for finding in all_findings:
                    filename = finding.path
                    if filename not in results["findings_by_file"]:
                        results["findings_by_file"][filename] = []
                    results["findings_by_file"][filename].append(finding)
                results["all_findings"] = all_findings
                results["files_scanned"] = [f.name for f in uploaded_files]
                results["summary"] = self._generate_summary(all_findings)
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
                    "Recommendation": finding.recommendation or "No recommendation available",
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
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
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

