# Databricks notebook source
# MAGIC %md
# MAGIC # Security Scanner - Databricks Notebook (No Init Script)
# MAGIC
# MAGIC This notebook runs the RogueCodeChecker security scanner without requiring cluster init scripts.
# MAGIC
# MAGIC ## Prerequisites
# MAGIC - Databricks cluster (any cluster, no init script needed)
# MAGIC - Repository connected via Databricks Repos
# MAGIC - (Optional) Databricks serving endpoint for LLM review
# MAGIC
# MAGIC ## Tools Installed
# MAGIC This notebook automatically installs:
# MAGIC - semgrep (SAST)
# MAGIC - detect-secrets (secrets)
# MAGIC - pip-audit (dependency vulnerabilities)
# MAGIC - sqlfluff (SQL linting)
# MAGIC - shellcheck (shell scripts)
# MAGIC
# MAGIC Note: gitleaks is not available (requires binary installation)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Install Security Tools
# MAGIC
# MAGIC This cell installs all required Python-based security scanning tools.
# MAGIC Runtime: ~2 minutes

# COMMAND ----------

print("=" * 60)
print("Installing Security Scanning Tools")
print("=" * 60)

# Install Python tools
%pip install semgrep==1.139.0 detect-secrets==1.5.0 pip-audit>=2.7.0 sqlfluff==3.4.2 shellcheck-py==0.11.0.1

print("✅ Security tools installed successfully!")
print("Restarting Python kernel...")

# COMMAND ----------

# Restart Python to load new packages
dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Install GitLeaks Binary (Optional)
# MAGIC
# MAGIC GitLeaks requires binary installation. This cell attempts to install it.
# MAGIC May fail if permissions are insufficient (skip if it fails).

# COMMAND ----------

import subprocess
import os

print("=" * 60)
print("Installing GitLeaks Binary")
print("=" * 60)

try:
    # Try to install gitleaks binary to /tmp (writable in Databricks)
    gitleaks_version = "8.18.4"
    install_dir = "/tmp/gitleaks_bin"

    # Download and extract
    commands = f"""
    mkdir -p {install_dir} && \
    cd /tmp && \
    wget -q https://github.com/gitleaks/gitleaks/releases/download/v{gitleaks_version}/gitleaks_{gitleaks_version}_linux_x64.tar.gz && \
    tar -xzf gitleaks_{gitleaks_version}_linux_x64.tar.gz && \
    mv gitleaks {install_dir}/ && \
    chmod +x {install_dir}/gitleaks && \
    rm gitleaks_{gitleaks_version}_linux_x64.tar.gz
    """

    result = subprocess.run(commands, shell=True, capture_output=True, text=True, timeout=60)

    if result.returncode == 0:
        # Add to PATH for this session
        os.environ["PATH"] = f"{install_dir}:{os.environ.get('PATH', '')}"
        print(f"✅ GitLeaks installed successfully to: {install_dir}/gitleaks")
        print(f"   PATH updated for this session")

        # Verify installation
        verify = subprocess.run([f"{install_dir}/gitleaks", "version"], capture_output=True, text=True)
        print(f"   Version: {verify.stdout.strip()}")

        print("\n⚠️  Note: GitLeaks will only be available during this notebook session")
        print("   It will need to be reinstalled when the cluster restarts")
    else:
        print(f"⚠️  GitLeaks installation failed: {result.stderr}")
        print("   Continuing without gitleaks (other tools will still work)")

except Exception as e:
    print(f"⚠️  GitLeaks installation failed: {e}")
    print("   Continuing without gitleaks (other tools will still work)")

print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Configuration
# MAGIC
# MAGIC Set up the scan parameters below:

# COMMAND ----------

# SCAN CONFIGURATION
# Modify these values as needed

# Path to scan (repository or directory)
SCAN_PATH = "/Workspace/Users/eliao@bpcs.com/gogue_code_test/files"  # Change this!

# Tools to use (comma-separated)
# gitleaks will be available if installation in cell 2 succeeded
TOOLS = "semgrep,detect-secrets,gitleaks,pip-audit,sqlfluff,shellcheck,sql-strict"
# Add "llm-review" for LLM-based semantic analysis

# Semgrep security packs
SEMGREP_PACKS = "p/security-audit,p/owasp-top-ten,p/secrets,p/python"

# LLM Configuration (for llm-review tool)
LLM_ENDPOINT = "databricks-claude-sonnet-4-5"  # Databricks serving endpoint
ENABLE_LLM_REVIEW = True  # Set to True to enable LLM review

# Output configuration
OUTPUT_FORMAT = "md"  # Options: md, json, sarif
OUTPUT_PATH = "/Workspace/Users/eliao@bpcs.com/gogue_code_test/security_scans/scan_report.md"
PER_FILE_OUTPUT_DIR = "/Workspace/Users/eliao@bpcs.com/gogue_code_test/security_scans/per_file_reports/"

# Fail threshold
FAIL_ON_SEVERITY = "high"  # Options: low, medium, high, critical

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Add RogueCodeChecker to Python Path

# COMMAND ----------

import sys
import os

# Add the repository root to Python path so we can import roguecheck modules
repo_root = "/Workspace/Users/eliao@bpcs.com/RogueCodeChecker"  # Change this!
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

print(f"✓ Added {repo_root} to Python path")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Verify Tool Installation

# COMMAND ----------

import shutil
import subprocess

tools_to_check = ["semgrep", "detect-secrets", "pip-audit", "sqlfluff", "shellcheck"]

print("=" * 60)
print("Tool Verification")
print("=" * 60)

all_installed = True
for tool in tools_to_check:
    path = shutil.which(tool)
    if path:
        try:
            version_cmds = {
                "semgrep": ["semgrep", "--version"],
                "detect-secrets": ["detect-secrets", "--version"],
                "pip-audit": ["pip-audit", "--version"],
                "sqlfluff": ["sqlfluff", "--version"],
                "shellcheck": ["shellcheck", "--version"],
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
        except Exception:
            print(f"✓ {tool:20s} {path} (version unavailable)")
    else:
        print(f"✗ {tool:20s} NOT FOUND")
        all_installed = False

print("=" * 60)
if not all_installed:
    print("⚠️  WARNING: Some tools are missing! Re-run the install cell.")
else:
    print("✅ All tools are installed and ready!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Set Environment Variables

# COMMAND ----------

import os

if ENABLE_LLM_REVIEW:
    os.environ["SERVING_ENDPOINT"] = LLM_ENDPOINT
    print(f"✓ LLM endpoint set: {LLM_ENDPOINT}")

print("✓ Databricks authentication: Automatic")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5a. Test LLM Connection (Optional)
# MAGIC
# MAGIC Run this cell to verify the LLM endpoint is working before starting the scan.

# COMMAND ----------

if ENABLE_LLM_REVIEW:
    from roguecheck.oss_llm_reviewer import create_llm_backend

    print("=" * 60)
    print("Testing LLM Connection")
    print("=" * 60)

    try:
        # Create backend
        backend = create_llm_backend(endpoint_name=LLM_ENDPOINT)
        print(f"✓ Backend initialized")
        print(f"  Endpoint: {backend.endpoint_name}")
        print(f"  Available: {backend.is_available()}")

        # Test with a simple prompt
        print("\n🧪 Testing with sample prompt...")
        test_prompt = "Say 'Hello! LLM is working.' in one sentence."
        response = backend.generate(test_prompt, max_tokens=50, temperature=0.1)

        print(f"\n✅ LLM Response:")
        print(f"  {response}")
        print("\n" + "=" * 60)
        print("✅ LLM is working correctly!")
        print("=" * 60)

    except Exception as e:
        print("\n" + "=" * 60)
        print(f"❌ LLM Test Failed: {e}")
        print("=" * 60)
        print("\nTroubleshooting:")
        print("1. Check that the endpoint name is correct")
        print("2. Verify the endpoint exists in Databricks serving endpoints")
        print("3. Ensure the endpoint is in 'Ready' state")
        print("4. Check that you have permissions to access the endpoint")
else:
    print("⚠️  LLM review is disabled (ENABLE_LLM_REVIEW = False)")
    print("   Set ENABLE_LLM_REVIEW = True in the configuration to test LLM")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Run Security Scan

# COMMAND ----------

from roguecheck.oss_runner import run_oss_tools
from roguecheck.oss_llm_reviewer import create_llm_backend
import os

print("=" * 60)
print("Starting Security Scan")
print("=" * 60)
print(f"Scan path: {SCAN_PATH}")
print(f"Tools: {TOOLS}")
print(f"Semgrep packs: {SEMGREP_PACKS}")
print("=" * 60)
print()

tools_list = [t.strip() for t in TOOLS.split(",") if t.strip()]
if ENABLE_LLM_REVIEW and "llm-review" not in tools_list:
    tools_list.append("llm-review")

llm_backend = None
if "llm-review" in tools_list:
    try:
        llm_backend = create_llm_backend(endpoint_name=LLM_ENDPOINT)
        print("✓ LLM backend initialized")
    except Exception as e:
        print(f"⚠️  LLM backend initialization failed: {e}")
        tools_list.remove("llm-review")

print(f"\n🔍 Running scan with tools: {', '.join(tools_list)}\n")

findings = run_oss_tools(
    root=SCAN_PATH,
    tools=tools_list,
    semgrep_config=SEMGREP_PACKS,
    files=None,
    llm_backend=llm_backend,
)

print("\n" + "=" * 60)
print(f"✅ Scan Complete! Found {len(findings)} issues")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Generate Reports

# COMMAND ----------

from roguecheck.report import to_markdown, to_json, to_sarif
from collections import defaultdict
import os

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
if PER_FILE_OUTPUT_DIR:
    os.makedirs(PER_FILE_OUTPUT_DIR, exist_ok=True)

if OUTPUT_FORMAT == "md":
    report = to_markdown(findings)
elif OUTPUT_FORMAT == "json":
    report = to_json(findings)
elif OUTPUT_FORMAT == "sarif":
    report = to_sarif(findings)
else:
    report = to_markdown(findings)

with open(OUTPUT_PATH, "w") as f:
    f.write(report)

print(f"✅ Report saved to: {OUTPUT_PATH}")

if PER_FILE_OUTPUT_DIR:
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
# MAGIC ## 8. Display Summary

# COMMAND ----------

from collections import Counter

severity_counts = Counter(f.severity for f in findings)
file_counts = Counter(f.path for f in findings)
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

if file_counts:
    print("Top 5 Files with Issues:")
    for file_path, count in file_counts.most_common(5):
        print(f"  {count:3d} - {file_path}")
    print()

if rule_counts:
    print("Top 5 Most Common Issues:")
    for rule_id, count in rule_counts.most_common(5):
        print(f"  {count:3d} - {rule_id}")

print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. Display Critical/High Issues

# COMMAND ----------

critical_high = [f for f in findings if f.severity in ["critical", "high"]]

if critical_high:
    print("=" * 60)
    print(f"CRITICAL & HIGH SEVERITY ISSUES ({len(critical_high)})")
    print("=" * 60)
    print()

    for finding in critical_high[:20]:
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
# MAGIC ## 10. View Full Report

# COMMAND ----------

with open(OUTPUT_PATH, "r") as f:
    report_content = f.read()

if OUTPUT_FORMAT == "md":
    displayHTML(f"<pre style='background: #f5f5f5; padding: 20px; border-radius: 5px;'>{report_content}</pre>")
else:
    print(report_content)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 11. Check Fail Threshold

# COMMAND ----------

severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
threshold = severity_order[FAIL_ON_SEVERITY]
worst_severity = max([severity_order.get(f.severity, 0) for f in findings], default=0)

if worst_severity >= threshold:
    print(f"❌ SCAN FAILED: Found issues at or above '{FAIL_ON_SEVERITY}' severity")
    print(f"   Worst severity: {[k for k, v in severity_order.items() if v == worst_severity][0]}")
else:
    print(f"✅ SCAN PASSED: No issues at or above '{FAIL_ON_SEVERITY}' severity")
