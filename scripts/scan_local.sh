#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <path> [--format md|json|sarif] [--out <dir>] [--packs <packs>] [--no-sql-strict]

Examples:
  $0 test_samples                         # Quick scan, Markdown to stdout, per-file reports in ./out_cli
  $0 . --format json --out out_json       # JSON to combined stdout and per-file JSON in out_json/
  $0 . --packs auto                       # Use Semgrep auto rules if registry is blocked

Notes:
  - Requires Python deps installed (uv sync or pip install -r requirements.txt)
  - shellcheck is optional (install via brew/apt for Bash analysis)
EOF
}

if [[ $# -lt 1 ]]; then usage; exit 1; fi

TARGET="$1"; shift || true
FORMAT="md"
OUT_DIR="out_cli"
PACKS="p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql"
EXTRA_TOOLS="semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict"
NO_SQL_STRICT="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --packs) PACKS="$2"; shift 2;;
    --no-sql-strict) NO_SQL_STRICT="true"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

mkdir -p "$OUT_DIR"

# Ensure Semgrep can write logs locally (avoid HOME perms issues)
export HOME="$(pwd)/.semgrephome"
mkdir -p "$HOME"

# Prefer uv if available
run()
{
  if command -v uv >/dev/null 2>&1; then
    uv run python -m osscheck_cli scan --path "$TARGET" \
      --format "$FORMAT" \
      --tools "$EXTRA_TOOLS" \
      --semgrep-config "$PACKS" \
      ${NO_SQL_STRICT:+--no-sql-strict} \
      --per-file-out-dir "$OUT_DIR"
  else
    python -m osscheck_cli scan --path "$TARGET" \
      --format "$FORMAT" \
      --tools "$EXTRA_TOOLS" \
      --semgrep-config "$PACKS" \
      ${NO_SQL_STRICT:+--no-sql-strict} \
      --per-file-out-dir "$OUT_DIR"
  fi
}

run

echo
echo "Per-file reports written to: $OUT_DIR" >&2
