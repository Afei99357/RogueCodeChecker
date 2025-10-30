# Databricks Notebooks

This directory contains Databricks notebooks for running security scans.

## security_scan_notebook.py

A complete Databricks notebook for running the RogueCodeChecker security scanner.

### Features

- ✅ Configurable scan settings via notebook parameters
- ✅ Tool verification checks
- ✅ Automatic LLM backend setup (Databricks)
- ✅ Multiple output formats (Markdown, JSON, SARIF)
- ✅ Per-file report generation
- ✅ Summary statistics and visualizations
- ✅ Severity-based fail thresholds
- ✅ Ready for Databricks Jobs scheduling

### Quick Start

**1. Import to Databricks**

```bash
# Via Databricks CLI
databricks workspace import notebooks/security_scan_notebook.py \
  /Users/<your-email>/security_scan_notebook \
  --language PYTHON --format SOURCE

# Or use Databricks Repos (recommended)
# Connect your Git repo and access the notebook at:
# /Workspace/Repos/<username>/RogueCodeChecker/notebooks/security_scan_notebook.py
```

**2. Configure the Notebook**

Edit these values in Cell 3 (Configuration):

```python
# Path to scan
SCAN_PATH = "/Workspace/Repos/<username>/<repo-name>"

# Tools to use
TOOLS = "semgrep,detect-secrets,pip-audit,sqlfluff,shellcheck,sql-strict"

# Enable LLM review (optional)
ENABLE_LLM_REVIEW = True
LLM_ENDPOINT = "databricks-claude-sonnet-4-5"

# Output settings
OUTPUT_PATH = "/dbfs/security_scans/scan_report.md"
```

**3. Run the Notebook**

- Click **Run All** or execute cells sequentially
- Wait for scan to complete (typically 2-10 minutes depending on repo size)
- View results in the summary section

### Notebook Structure

| Section | Description |
|---------|-------------|
| 1. Configuration | Set scan parameters and paths |
| 2. Install Package | Install RogueCodeChecker |
| 3. Verify Tools | Check that security tools are installed |
| 4. Set Env Variables | Configure LLM endpoint |
| 5. Run Security Scan | Execute the scan |
| 6. Generate Reports | Create output files |
| 7. Display Summary | Show statistics |
| 8. Display Issues | Show critical/high findings |
| 9. View Full Report | Display complete report |
| 10. Check Threshold | Verify pass/fail criteria |

### Prerequisites

**Required:**
- Databricks cluster with init script (`scripts/databricks_init.sh`)
- Repository connected via Databricks Repos
- Security tools installed (semgrep, detect-secrets, pip-audit, etc.)

**Optional:**
- Databricks serving endpoint (for LLM review)
- DBFS access (for saving reports)

### Using as a Databricks Job

**1. Create a Job**

Go to **Workflows** → **Create Job**

**2. Configure Job Task**

- Task name: `Security Scan`
- Type: **Notebook**
- Path: `/Workspace/Repos/<username>/RogueCodeChecker/notebooks/security_scan_notebook`
- Cluster: Select cluster with init script
- Parameters (optional):
  ```json
  {
    "scan_path": "/Workspace/Repos/<username>/<repo>",
    "enable_llm_review": "true"
  }
  ```

**3. Set Schedule**

- Trigger: Scheduled
- Schedule: Daily at 2 AM (or your preference)
- Timezone: Your timezone

**4. Configure Alerts**

- On Failure: Send email alert
- On Success: Optional notification with summary

### Parameterized Notebook (Advanced)

To use notebook parameters, add this cell at the beginning:

```python
# COMMAND ----------

# MAGIC %md
# MAGIC ## Notebook Parameters
# MAGIC Define these as job parameters or notebook widgets

# COMMAND ----------

# Create widgets for parameterization
dbutils.widgets.text("scan_path", "/Workspace/Repos/<username>/<repo>", "Repository Path")
dbutils.widgets.dropdown("enable_llm_review", "false", ["true", "false"], "Enable LLM Review")
dbutils.widgets.text("llm_endpoint", "databricks-claude-sonnet-4-5", "LLM Endpoint")
dbutils.widgets.dropdown("output_format", "md", ["md", "json", "sarif"], "Output Format")
dbutils.widgets.dropdown("fail_on_severity", "high", ["low", "medium", "high", "critical"], "Fail Threshold")

# Get parameter values
SCAN_PATH = dbutils.widgets.get("scan_path")
ENABLE_LLM_REVIEW = dbutils.widgets.get("enable_llm_review") == "true"
LLM_ENDPOINT = dbutils.widgets.get("llm_endpoint")
OUTPUT_FORMAT = dbutils.widgets.get("output_format")
FAIL_ON_SEVERITY = dbutils.widgets.get("fail_on_severity")
```

Then you can pass parameters when running as a job:

```json
{
  "scan_path": "/Workspace/Repos/username/my-project",
  "enable_llm_review": "true",
  "fail_on_severity": "critical"
}
```

### Output Files

The notebook generates:

| File | Location | Description |
|------|----------|-------------|
| Main Report | `/dbfs/security_scans/scan_report.md` | Complete scan results |
| Per-File Reports | `/dbfs/security_scans/per_file_reports/` | Individual file reports |
| Summary Stats | Notebook output | Statistics and charts |

### Troubleshooting

**Tools Not Found**

- Ensure cluster init script ran successfully
- Check cluster event logs for errors
- Run cell 3 (Verify Tools) to see which tools are missing

**LLM Backend Fails**

- Verify serving endpoint exists and is running
- Check endpoint name matches configuration
- Ensure cluster has permissions to access endpoint

**Permission Denied on DBFS**

- Ensure output paths are writable
- Use `/dbfs/` prefix for file paths
- Check DBFS access permissions

**Scan Times Out**

- Large repositories may take time
- Consider scanning specific directories
- Disable LLM review for faster scans
- Use more powerful cluster

### Performance Tips

1. **Use single-node cluster** - Only driver needs tools
2. **Filter files** - Scan only relevant directories
3. **Disable unused tools** - Remove tools you don't need
4. **Schedule during off-hours** - Avoid peak usage times
5. **Cache results** - Store and compare previous scans

### Next Steps

- Customize the notebook for your workflow
- Schedule as a recurring job
- Integrate with your CI/CD pipeline
- Export reports to dashboards or ticketing systems
