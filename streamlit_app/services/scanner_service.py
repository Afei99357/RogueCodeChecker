"""
Scanner Service - Adapter layer between Streamlit and RogueCheck
Handles file processing, temporary storage, and data conversion
"""

import os
import tempfile
from dataclasses import asdict
from typing import Any, Dict, List, Optional

import pandas as pd

from roguecheck.models import Finding
from roguecheck.policy import Policy

# Import from the core roguecheck package
from roguecheck.scanner import Scanner
try:
    from roguecheck.oss_semgrep import scan_with_semgrep
except Exception:
    scan_with_semgrep = None  # type: ignore


class ScannerService:
    """Service layer to bridge Streamlit and RogueCheck core functionality"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def scan_uploaded_files(self, uploaded_files: List) -> Dict[str, Any]:
        """
        Scan multiple uploaded files and return structured results

        Args:
            uploaded_files: List of Streamlit UploadedFile objects

        Returns:
            Dict containing scan results, summary stats, and metadata
        """
        if not uploaded_files:
            return self._empty_results()

        results = {
            "findings_by_file": {},
            "all_findings": [],
            "summary": {},
            "files_scanned": [],
        }

        # Create temporary directory for uploaded files
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Save uploaded files to temp directory
                file_paths = self._save_uploaded_files(uploaded_files, temp_dir)

                # Initialize policy
                policy = self._load_policy()

                # Choose engine
                engine = str(self.config.get("engine", "builtin"))
                if engine == "oss":
                    tools = self.config.get(
                        "oss_tools", ["semgrep", "detect-secrets", "sqlfluff"]
                    )
                    from roguecheck.oss_runner import run_oss_tools

                    all_findings = run_oss_tools(
                        root=temp_dir, policy=policy, tools=list(tools), semgrep_config="semgrep_rules"
                    )
                else:
                    # Fallback to built-in engine
                    scanner = Scanner(temp_dir, policy)
                    all_findings = scanner.scan()

                # Group findings by file
                for finding in all_findings:
                    filename = finding.path
                    if filename not in results["findings_by_file"]:
                        results["findings_by_file"][filename] = []
                    results["findings_by_file"][filename].append(finding)

                results["all_findings"] = all_findings
                results["files_scanned"] = [f.name for f in uploaded_files]
                results["summary"] = self._generate_summary(all_findings)

            except Exception as e:
                # Handle scanning errors gracefully
                results["error"] = str(e)
                results["summary"] = {"error": True, "message": str(e)}

        return results

    def findings_to_dataframe(self, findings: List[Finding]) -> pd.DataFrame:
        """Convert RogueCheck findings to pandas DataFrame for Streamlit display"""
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

        # Add severity ordering for proper sorting
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        df["Severity_Order"] = df["Severity"].map(severity_order)
        df = df.sort_values(["Severity_Order", "File"], ascending=[False, True])
        df = df.drop("Severity_Order", axis=1)

        return df

    def get_findings_by_severity(
        self, findings: List[Finding]
    ) -> Dict[str, List[Finding]]:
        """Group findings by severity level"""
        grouped = {"critical": [], "high": [], "medium": [], "low": []}

        for finding in findings:
            if finding.severity in grouped:
                grouped[finding.severity].append(finding)

        return grouped

    def get_findings_by_rule(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by rule ID"""
        grouped = {}

        for finding in findings:
            rule_id = finding.rule_id
            if rule_id not in grouped:
                grouped[rule_id] = []
            grouped[rule_id].append(finding)

        return grouped

    def _save_uploaded_files(self, uploaded_files: List, temp_dir: str) -> List[str]:
        """Save uploaded files to temporary directory"""
        file_paths = []

        for uploaded_file in uploaded_files:
            # Use original filename
            file_path = os.path.join(temp_dir, uploaded_file.name)

            # Write file content
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getvalue())

            file_paths.append(file_path)

        return file_paths

    def _load_policy(self) -> Policy:
        """Load RogueCheck policy with custom overrides from config"""
        try:
            # Load base policy (will use defaults if files don't exist)
            policy = Policy.load()

            # Apply custom configurations if provided
            if self.config.get("custom_domains"):
                # Add custom domains to allowlist
                current_domains = list(policy.allow_domains())
                new_domains = [
                    d.strip() for d in self.config["custom_domains"] if d.strip()
                ]
                all_domains = current_domains + new_domains
                policy.policy["network"]["allow_domains"] = all_domains

            if self.config.get("fail_threshold"):
                # Custom threshold can be used by the UI for display filtering
                # (RogueCheck core doesn't use this directly)
                pass

            return policy

        except Exception as e:
            # Fallback to default policy if loading fails
            from roguecheck.policy import DEFAULT_ALLOWLISTS, DEFAULT_POLICY

            return Policy(DEFAULT_POLICY, DEFAULT_ALLOWLISTS)

    def _generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary statistics from findings"""
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
        """Return empty results structure"""
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
