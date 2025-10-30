# Databricks notebook source
# MAGIC %md
# MAGIC # Security Scanner - Databricks Notebook
# MAGIC
# MAGIC This notebook runs the RogueCodeChecker security scanner on your code repository.
# MAGIC
# MAGIC ## Prerequisites
# MAGIC 1. Cluster with init script (`scripts/databricks_init.sh`) to install security tools
# MAGIC 2. Repository connected via Databricks Repos
# MAGIC 3. (Optional) Databricks serving endpoint for LLM review
# MAGIC
# MAGIC ## Tools Used
# MAGIC - semgrep (SAST)
# MAGIC - detect-secrets (secrets)
# MAGIC - pip-audit (dependency vulnerabilities)
# MAGIC - gitleaks (secrets - if available)
# MAGIC - sqlfluff (SQL linting)
# MAGIC - shellcheck (shell scripts)
# MAGIC - LLM review (semantic analysis - optional)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Configuration
# MAGIC
# MAGIC Set up the scan parameters below:

# COMMAND ----------

# SCAN CONFIGURATION
# Modify these values as needed

# Path to scan (repository or directory)
SCAN_PATH = "/Workspace/Repos/<username>/<repo-name>"  # Change this!

# Tools to use (comma-separated)
TOOLS = "semgrep,detect-secrets,pip-audit,sqlfluff,shellcheck,sql-strict"
# Add "gitleaks" if installed via init script
# Add "llm-review" for LLM-based semantic analysis

# Semgrep security packs
SEMGREP_PACKS = "p/security-audit,p/owasp-top-ten,p/secrets,p/python"

# LLM Configuration (for llm-review tool)
LLM_ENDPOINT = "databricks-claude-sonnet-4-5"  # Databricks serving endpoint
ENABLE_LLM_REVIEW = False  # Set to True to enable LLM review

# Output configuration
OUTPUT_FORMAT = "md"  # Options: md, json, sarif
OUTPUT_PATH = "/dbfs/security_scans/scan_report.md"
PER_FILE_OUTPUT_DIR = "/dbfs/security_scans/per_file_reports/"

# Fail threshold
FAIL_ON_SEVERITY = "high"  # Options: low, medium, high, critical

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Install RogueCodeChecker Package

# COMMAND ----------

# Install the package (if not already installed)
%pip install -e /Workspace/Repos/<username>/RogueCodeChecker

# Restart Python to load the package
dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Verify Tool Installation

# COMMAND ----------

import shutil

# Verify that security tools are installed
import subprocess

tools_to_check = ["semgrep", "detect-secrets", "pip-audit", "sqlfluff", "shellcheck", "gitleaks"]

print("=" * 60)
print("Tool Verification")
print("=" * 60)

all_installed = True
for tool in tools_to_check:
    path = shutil.which(tool)
    if path:
        try:
            # Get version
            version_cmds = {
                "semgrep": ["semgrep", "--version"],
                "detect-secrets": ["detect-secrets", "--version"],
                "pip-audit": ["pip-audit", "--version"],
                "sqlfluff": ["sqlfluff", "--version"],
                "shellcheck": ["shellcheck", "--version"],
                "gitleaks": ["gitleaks", "version"],
            }
            result = subprocess.run(
                version_cmds.get(tool, [tool, "--version"]),
                capture_output=True,
                text=True,
                timeout=5,
            )
            version = (result.stdout or result.stderr).strip().split("\n")[0]
            print(f"✓ {tool:20s} {path}")
            print(f"  Version: {version}")
        except Exception as e:
            print(f"✓ {tool:20s} {path} (version unavailable)")
    else:
        print(f"✗ {tool:20s} NOT FOUND")
        if tool != "gitleaks":  # gitleaks is optional
            all_installed = False

print("=" * 60)
if not all_installed:
    print("⚠️  WARNING: Some required tools are missing!")
    print("Run the cluster init script: scripts/databricks_init.sh")
else:
    print("✅ All tools are installed and ready!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Set Environment Variables

# COMMAND ----------

import os

# Set LLM endpoint (if using LLM review)
if ENABLE_LLM_REVIEW:
    os.environ["SERVING_ENDPOINT"] = LLM_ENDPOINT
    print(f"✓ LLM endpoint set: {LLM_ENDPOINT}")

# Databricks authentication is automatic in notebooks
print("✓ Databricks authentication: Automatic")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Run Security Scan

# COMMAND ----------

import os

from roguecheck.llm_backends import create_backend
from roguecheck.oss_runner import run_oss_tools

print("=" * 60)
print("Starting Security Scan")
print("=" * 60)
print(f"Scan path: {SCAN_PATH}")
print(f"Tools: {TOOLS}")
print(f"Semgrep packs: {SEMGREP_PACKS}")
print("=" * 60)
print()

# Prepare tools list
tools_list = [t.strip() for t in TOOLS.split(",") if t.strip()]
if ENABLE_LLM_REVIEW and "llm-review" not in tools_list:
    tools_list.append("llm-review")

# Create LLM backend if needed
llm_backend = None
if "llm-review" in tools_list:
    try:
        llm_backend = create_backend("databricks", endpoint_name=LLM_ENDPOINT)
        print("✓ LLM backend initialized")
    except Exception as e:
        print(f"⚠️  LLM backend initialization failed: {e}")
        tools_list.remove("llm-review")

# Run the scan
print(f"\n🔍 Running scan with tools: {', '.join(tools_list)}\n")

findings = run_oss_tools(
    root=SCAN_PATH,
    tools=tools_list,
    semgrep_config=SEMGREP_PACKS,
    files=None,  # Scan all files
    llm_backend=llm_backend,
)

print("\n" + "=" * 60)
print(f"✅ Scan Complete! Found {len(findings)} issues")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Generate Reports

# COMMAND ----------

import os

from roguecheck.report import to_json, to_markdown, to_sarif

# Create output directory
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
if PER_FILE_OUTPUT_DIR:
    os.makedirs(PER_FILE_OUTPUT_DIR, exist_ok=True)

# Generate report based on format
if OUTPUT_FORMAT == "md":
    report = to_markdown(findings)
elif OUTPUT_FORMAT == "json":
    report = to_json(findings)
elif OUTPUT_FORMAT == "sarif":
    report = to_sarif(findings)
else:
    report = to_markdown(findings)

# Save main report
with open(OUTPUT_PATH, "w") as f:
    f.write(report)

print(f"✅ Report saved to: {OUTPUT_PATH}")

# Generate per-file reports if configured
if PER_FILE_OUTPUT_DIR:
    from collections import defaultdict

    findings_by_file = defaultdict(list)
    for finding in findings:
        findings_by_file[finding.path].append(finding)

    for file_path, file_findings in findings_by_file.items():
        file_name = os.path.basename(file_path).replace(".", "_")
        per_file_report_path = os.path.join(PER_FILE_OUTPUT_DIR, f"{file_name}_report.md")

        per_file_report = to_markdown(file_findings)
        with open(per_file_report_path, "w") as f:
            f.write(per_file_report)

    print(f"✅ Per-file reports saved to: {PER_FILE_OUTPUT_DIR}")
    print(f"   Generated {len(findings_by_file)} file reports")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Display Summary

# COMMAND ----------

from collections import Counter

# Count by severity
severity_counts = Counter(f.severity for f in findings)

# Count by file
file_counts = Counter(f.path for f in findings)

# Count by rule
rule_counts = Counter(f.rule_id for f in findings)

print("=" * 60)
print("SCAN SUMMARY")
print("=" * 60)
print()
print(f"Total Issues: {len(findings)}")
print()
print("By Severity:")
for severity in ["critical", "high", "medium", "low"]:
    count = severity_counts.get(severity, 0)
    if count > 0:
        print(f"  {severity.upper():10s}: {count}")
print()
print(f"Files Affected: {len(file_counts)}")
print(f"Unique Rules:   {len(rule_counts)}")
print()

# Top 5 files with most issues
if file_counts:
    print("Top 5 Files with Issues:")
    for file_path, count in file_counts.most_common(5):
        print(f"  {count:3d} - {file_path}")
    print()

# Top 5 most common rules
if rule_counts:
    print("Top 5 Most Common Issues:")
    for rule_id, count in rule_counts.most_common(5):
        print(f"  {count:3d} - {rule_id}")

print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Display Critical/High Issues

# COMMAND ----------

# Filter and display high-severity issues
critical_high = [f for f in findings if f.severity in ["critical", "high"]]

if critical_high:
    print("=" * 60)
    print(f"CRITICAL & HIGH SEVERITY ISSUES ({len(critical_high)})")
    print("=" * 60)
    print()

    for finding in critical_high[:20]:  # Show first 20
        print(f"[{finding.severity.upper()}] {finding.rule_id}")
        print(f"File: {finding.path}:{finding.position.line}")
        print(f"Message: {finding.message}")
        if finding.recommendation:
            print(f"Fix: {finding.recommendation}")
        print("-" * 60)
else:
    print("✅ No critical or high severity issues found!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. View Full Report

# COMMAND ----------

# Display the markdown report in notebook
with open(OUTPUT_PATH, "r") as f:
    report_content = f.read()

# Display as HTML (for markdown)
if OUTPUT_FORMAT == "md":
    displayHTML(f"<pre style='background: #f5f5f5; padding: 20px; border-radius: 5px;'>{report_content}</pre>")
else:
    print(report_content)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 10. Check Fail Threshold

# COMMAND ----------

# Check if scan should fail based on severity threshold
severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
threshold = severity_order[FAIL_ON_SEVERITY]

worst_severity = max([severity_order.get(f.severity, 0) for f in findings], default=0)

if worst_severity >= threshold:
    print(f"❌ SCAN FAILED: Found issues at or above '{FAIL_ON_SEVERITY}' severity")
    print(f"   Worst severity: {[k for k, v in severity_order.items() if v == worst_severity][0]}")
    # In a job, you might want to: raise Exception("Scan failed")
else:
    print(f"✅ SCAN PASSED: No issues at or above '{FAIL_ON_SEVERITY}' severity")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Review the findings in the report
# MAGIC 2. Fix critical and high severity issues
# MAGIC 3. Run scan again to verify fixes
# MAGIC 4. Schedule this notebook as a Databricks Job for automated scanning
# MAGIC
# MAGIC ## Useful Commands
# MAGIC
# MAGIC ```python
# MAGIC # Download report locally
# MAGIC dbutils.fs.cp(OUTPUT_PATH.replace("/dbfs", "dbfs:"), "file:/tmp/report.md")
# MAGIC
# MAGIC # List all per-file reports
# MAGIC dbutils.fs.ls(PER_FILE_OUTPUT_DIR.replace("/dbfs", "dbfs:"))
# MAGIC
# MAGIC # View specific file report
# MAGIC with open(f"{PER_FILE_OUTPUT_DIR}/myfile_py_report.md", "r") as f:
# MAGIC     print(f.read())
# MAGIC ```
