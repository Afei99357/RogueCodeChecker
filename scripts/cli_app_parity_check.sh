#!/usr/bin/env bash
set -euo pipefail

# Simple parity demo: run CLI scan on test_samples and print summary.
# Usage: scripts/cli_app_parity_check.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "== CLI scan (Markdown) on test_samples =="
uv run python -m osscheck_cli scan \
  --path "$ROOT_DIR/test_samples" \
  --format md \
  --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict \
  --semgrep-config p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql \
  --per-file-out-dir "$ROOT_DIR/out_cli"

echo
echo "Reports written to: $ROOT_DIR/out_cli"
echo "Open the Streamlit app and upload the same files to compare results."
