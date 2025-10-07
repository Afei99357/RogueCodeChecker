#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <path> [--format md|json|sarif] [--out <dir>] [--packs <packs>] [--no-sql-strict] [--llm]

Examples:
  $0 test_samples                         # Quick scan, per-file reports in ./test_output_TIMESTAMP/
  $0 . --format json --out my_reports     # JSON to combined stdout and per-file JSON in my_reports/
  $0 . --packs auto                       # Use Semgrep auto rules if registry is blocked
  $0 test_samples --llm                   # Include LLM review with Ollama/Qwen3

Notes:
  - Output directory defaults to test_output_YYYYMMDD_HHMMSS (unique per run)
  - Use --out <dir> to specify custom output directory
  - Requires Python deps installed (uv sync or pip install -r requirements.txt)
  - shellcheck is optional (install via brew/apt for Bash analysis)
  - LLM review requires Ollama running with qwen3 model (ollama pull qwen3)
EOF
}

if [[ $# -lt 1 ]]; then usage; exit 1; fi

TARGET="$1"; shift || true
FORMAT="md"
# Generate timestamp for unique output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="test_output_${TIMESTAMP}"
PACKS="p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/javascript,p/typescript,roguecheck/rules/"
EXTRA_TOOLS="semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict"
NO_SQL_STRICT="false"
USE_LLM="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --packs) PACKS="$2"; shift 2;;
    --no-sql-strict) NO_SQL_STRICT="true"; shift;;
    --llm) USE_LLM="true"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

# Add LLM review to tools if requested
if [[ "$USE_LLM" == "true" ]]; then
  EXTRA_TOOLS="${EXTRA_TOOLS},llm-review"
fi

mkdir -p "$OUT_DIR"

# Ensure Semgrep can write logs locally (avoid HOME perms issues)
export HOME="$(pwd)/.semgrephome"
mkdir -p "$HOME"

# Prefer uv if available
run()
{
  local LLM_ARGS=""
  if [[ "$USE_LLM" == "true" ]]; then
    LLM_ARGS="--llm-backend ollama --llm-model qwen3"
  fi

  # Build sql-strict flag conditionally
  local SQL_STRICT_FLAG=""
  if [[ "$NO_SQL_STRICT" == "true" ]]; then
    SQL_STRICT_FLAG="--no-sql-strict"
  fi

  if command -v uv >/dev/null 2>&1; then
    uv run python -m osscheck_cli scan --path "$TARGET" \
      --format "$FORMAT" \
      --tools "$EXTRA_TOOLS" \
      --semgrep-config "$PACKS" \
      $SQL_STRICT_FLAG \
      ${LLM_ARGS} \
      --per-file-out-dir "$OUT_DIR"
  else
    python -m osscheck_cli scan --path "$TARGET" \
      --format "$FORMAT" \
      --tools "$EXTRA_TOOLS" \
      --semgrep-config "$PACKS" \
      $SQL_STRICT_FLAG \
      ${LLM_ARGS} \
      --per-file-out-dir "$OUT_DIR"
  fi
}

run

echo
echo "Per-file reports written to: $OUT_DIR" >&2
