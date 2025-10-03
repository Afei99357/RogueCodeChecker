# RogueCheck

RogueCheck scans for malicious/rogue code patterns across languages using open-source tools. It supports a CLI and a Streamlit web app.

## What It Covers

- Multi-language SAST (Semgrep)
  - Defaults: p/security-audit, p/owasp-top-ten, p/secrets, p/python, p/bash, p/javascript, p/typescript, p/sql
  - App auto-adds packs for uploaded types: java/go/ruby/php/csharp/dockerfile/terraform/yaml
- Secrets scanning (detect-secrets) across any file
- SQL checks
  - Style: sqlfluff (linting)
  - Security: strict raw .sql checks (enabled by default) for GRANT ALL, DELETE without WHERE, DROP TABLE (non-temp)
- Shell checks
  - ShellCheck for .sh/.bash (install shellcheck on PATH)
- Notebooks
  - Extracts Python cells and %sql/%%sql cells from .ipynb and Databricks-exported .py notebooks
- Embedded content detection
  - Heuristics to extract SQL/Shell snippets inside other files (e.g., SQL inside Python strings, shell commands inside Java/JS), then runs the right tool on the snippet
- Per-file reports
  - CLI can write one report per file (md/json/sarif)

## Requirements

- Python 3.10+
- Network access to semgrep.dev for registry packs (or use `--semgrep-config auto`)
- Tools on PATH:
  - semgrep, detect-secrets, sqlfluff are installed via `requirements.txt`
  - shellcheck via OS package (brew/apt) or vendored binary via `shellcheck-py` (already pinned in `requirements.txt`)

## Quickstart (CLI)

- Using uv (recommended)
  - Install deps: `uv sync`
  - Full scan with per-file reports (Markdown):
    ```bash
    uv run python -m osscheck scan \
      --path . \
      --format md \
      --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict \
      --semgrep-config p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql \
      --per-file-out-dir out_cli
    ```
- Using venv + pip
  - `python -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
  - `python -m osscheck scan --path . --format md --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict --semgrep-config p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql --per-file-out-dir out_cli`

- One‑command helper script
  - `bash scripts/scan_local.sh test_samples` (adds per‑file reports to `out_cli/`)

## Options (CLI)

- `--path <dir|file>` — scan a directory or single file
- `--paths-from <file>` — scan only files listed (one per line)
- `--format md|json|sarif` — output format
- `--tools` — comma-separated tools (default: `semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict`)
- `--semgrep-config` — comma-separated packs or `auto` (default includes security-audit, OWASP Top 10, secrets, Python/Bash/JS/TS/SQL packs)
- `--per-file-out-dir <dir>` — additionally write one report per file into this directory
- `--fail-on low|medium|high|critical` — exit non-zero if any finding at/above threshold
  
Notes:
- Passing a single file in `--path` runs all selected tools against that file (including strict SQL and snippet extraction).
- You can also pass `--paths-from <filelist>` to scan an explicit list.

## Web App (Streamlit)

- Run: `python run_app_oss.py` then open `http://localhost:8501`
- Sidebar
  - “Semgrep Packs” (default set; auto-augmented to match uploaded file types)
- Upload
  - Supports: `.py`, `.sql`, `.sh`, `.bash`, `.ipynb`, `.js`, `.ts`, `.java`, `.go`, `.rb`, `.php`, `.cs`, `.tf`, `.yaml`/`.yml`, `.txt`, `.md`, `Dockerfile`
- Results
  - View Mode: Combined or By File
  - Export combined CSV, or per-file CSV ZIP
  - Diagnostics panel shows tool presence/versions and active packs

## Behavior & Notes

- Strict SQL checks are enabled by default (CLI/app).
- ShellCheck: if not installed and there are shell targets, you will see a low-severity diagnostic. Install via OS or use `shellcheck-py`.
- Semgrep packs: if egress to `semgrep.dev` is blocked, the scanner falls back to `--config=auto` and adds a low-severity advisory about reduced coverage.
- Embedded snippets (SQL/Shell) are extracted from any file (including `.txt`/`.md`) and scanned; findings are mapped back to the source file and line.

## Examples

- Folder scan with per-file reports (Markdown):
  ```bash
  uv run python -m osscheck scan \
    --path test_samples \
    --format md \
    --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict \
    --semgrep-config p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql \
    --per-file-out-dir out_cli
  ```
  This includes `.txt`/`.md` capture and notebook extraction; findings from embedded snippets are mapped back to the source files.
- Single file (Python + secrets):
  ```bash
  uv run python -m osscheck scan --path test_samples/dangerous_python.py --format md --tools semgrep,detect-secrets --semgrep-config p/python
  ```
- Batch via list and SARIF output:
  ```bash
  git ls-files 'test_samples/*' > files.txt
  uv run python -m osscheck scan --path . --paths-from files.txt --format sarif --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict --semgrep-config p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/bash,p/javascript,p/typescript,p/sql
  ```

## Troubleshooting

- “No issues found” but tools are installed
  - Check the app Diagnostics section or run `semgrep --version`, `detect-secrets --version`, `sqlfluff --version`, `shellcheck --version`.
  - If Semgrep can’t fetch packs, the scanner will fallback to `--config=auto` and print an advisory. Consider pointing `--semgrep-config` to local rule paths.
- Semgrep permission errors in containers/CI
  - The scanner sets a local writable Semgrep home automatically; if running manually, set `SEMGREP_USER_HOME=$(pwd)/.semgrephome`.
- ShellCheck not found
  - Install OS package or rely on `shellcheck-py` provided in `requirements.txt`.
