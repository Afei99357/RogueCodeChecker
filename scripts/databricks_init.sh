#!/bin/bash
# Databricks Cluster Init Script for RogueCodeChecker
# This script installs all required security scanning tools

set -e  # Exit on error

echo "=== RogueCodeChecker Init Script Started ==="
echo "Installing security scanning tools..."

# Update package manager
apt-get update -y

# Install system dependencies
echo "Installing system dependencies..."
apt-get install -y wget curl tar

# 1. Install Python-based tools via pip
echo "Installing Python security tools..."
pip install --upgrade pip
pip install semgrep==1.139.0
pip install detect-secrets==1.5.0
pip install pip-audit>=2.7.0
pip install sqlfluff==3.4.2
pip install shellcheck-py==0.11.0.1

# 2. Install GitLeaks binary
echo "Installing GitLeaks..."
GITLEAKS_VERSION="8.18.4"
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

cd /tmp
wget -q ${GITLEAKS_URL} -O gitleaks.tar.gz
tar -xzf gitleaks.tar.gz
chmod +x gitleaks
mv gitleaks /usr/local/bin/
rm gitleaks.tar.gz

# Verify gitleaks installation
if command -v gitleaks &> /dev/null; then
    echo "✓ GitLeaks installed: $(gitleaks version)"
else
    echo "⚠ GitLeaks installation failed"
fi

# 3. Verify all installations
echo ""
echo "=== Verification ==="
echo "Checking installed tools..."

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✓ $1: $(command -v $1)"
        $1 --version 2>&1 | head -n 1 || echo "  (version command not available)"
    else
        echo "✗ $1: NOT FOUND"
    fi
}

check_tool semgrep
check_tool detect-secrets
check_tool pip-audit
check_tool sqlfluff
check_tool shellcheck
check_tool gitleaks

# 4. Install RogueCodeChecker package dependencies (if pyproject.toml is present)
if [ -f "/Workspace/Repos/YOUR_REPO_PATH/pyproject.toml" ]; then
    echo ""
    echo "Installing RogueCodeChecker package..."
    pip install pandas==2.3.2 plotly==6.3.1 streamlit==1.49.1
    echo "✓ RogueCodeChecker dependencies installed"
fi

echo ""
echo "=== RogueCodeChecker Init Script Completed Successfully ==="
echo "All security scanning tools are ready!"
