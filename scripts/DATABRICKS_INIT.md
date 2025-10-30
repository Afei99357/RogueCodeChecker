# Databricks Cluster Init Script

This init script installs all security scanning tools required by RogueCodeChecker on a Databricks cluster.

## What Gets Installed

### Python Tools (via pip)
- semgrep (1.139.0) - SAST engine
- detect-secrets (1.5.0) - Secret detection
- pip-audit (≥2.7.0) - Dependency vulnerability scanning
- sqlfluff (3.4.2) - SQL linting
- shellcheck-py (0.11.0.1) - Shell script analysis

### Binary Tools
- gitleaks (8.18.4) - Secret detection binary

### Supporting Packages
- pandas, plotly, streamlit (if pyproject.toml is found)

## Setup Instructions

### Step 1: Upload Init Script to DBFS

**Option A: Via Databricks UI**
1. Go to your Databricks workspace
2. Navigate to **Data** → **DBFS Browser**
3. Create folder: `dbfs:/databricks/scripts/`
4. Upload `databricks_init.sh` to this folder

**Option B: Via Databricks CLI**
```bash
# Install Databricks CLI if needed
pip install databricks-cli

# Configure authentication
databricks configure --token

# Upload the script
databricks fs cp scripts/databricks_init.sh dbfs:/databricks/scripts/databricks_init.sh
```

**Option C: Via Repos (Recommended)**
1. Connect your Git repo to Databricks Repos
2. The script will be available at: `/Workspace/Repos/<your-username>/<repo-name>/scripts/databricks_init.sh`

### Step 2: Configure Cluster

1. Go to **Compute** → Select your cluster → **Edit**
2. Scroll to **Advanced Options**
3. Click **Init Scripts** tab
4. Add init script:
   - **Type:** DBFS or Workspace
   - **Path:**
     - DBFS: `dbfs:/databricks/scripts/databricks_init.sh`
     - Workspace: `/Workspace/Repos/<your-username>/<repo-name>/scripts/databricks_init.sh`
5. Click **Confirm** and **Save**

### Step 3: Restart Cluster

1. Stop the cluster
2. Start the cluster
3. Wait for initialization (2-3 minutes)
4. Check cluster logs to verify installation

### Step 4: Verify Installation

**Option A: Run in Notebook**
```python
import subprocess

tools = ["semgrep", "detect-secrets", "pip-audit", "sqlfluff", "shellcheck", "gitleaks"]
for tool in tools:
    result = subprocess.run(["which", tool], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✓ {tool}: {result.stdout.strip()}")
    else:
        print(f"✗ {tool}: NOT FOUND")
```

**Option B: Check Cluster Logs**
1. Go to **Compute** → Select your cluster
2. Click **Event Log** tab
3. Look for "RogueCodeChecker Init Script Started/Completed"
4. Check for any error messages

## Troubleshooting

### Init Script Fails
- Check cluster event logs for error messages
- Ensure script has correct line endings (LF, not CRLF)
- Verify DBFS path is correct
- Check cluster has internet access for downloads

### Tools Not Found After Init
- Verify init script ran successfully in cluster logs
- Check PATH includes `/usr/local/bin`
- Try manually running: `/usr/local/bin/gitleaks version`

### Permission Errors
- Ensure cluster has admin privileges
- Check DBFS permissions on the init script
- Verify network access to GitHub releases (for gitleaks)

### Slow Initialization
- Init script adds ~2-3 minutes to cluster start time
- This is normal for installing multiple tools
- Consider using a custom container image for faster starts

## For Production Deployments

For Databricks Apps or production environments, consider:

1. **Custom Container Image**: Pre-bake tools into a Docker image
2. **Libraries Section**: Install Python packages via cluster libraries config
3. **Environment Variables**: Set `SERVING_ENDPOINT` for LLM integration

## Alternative: Manual Installation

If you can't use init scripts, install manually in a notebook:
```bash
%pip install semgrep detect-secrets pip-audit sqlfluff shellcheck-py

# For gitleaks
%sh
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

## Notes

- Init script runs on **all cluster nodes** (driver + workers)
- Only driver needs the tools for scanning
- Consider using a single-node cluster for scanning workloads
- Tools persist only during cluster lifetime (not saved between restarts)
