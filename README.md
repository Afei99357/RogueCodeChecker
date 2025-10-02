# RogueCheck

Minimal, extensible scanner for "rogue code" patterns in AI-generated snippets.

## Quickstart (OSS-only)
```bash
# Run all OSS tools (Semgrep, detect-secrets, sqlfluff, shellcheck)
python -m osscheck scan --path . --format md \
  --semgrep-config p/security-audit,p/python,p/bash,p/javascript,p/sql \
  --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict
```

### Options

* `--format md|json|sarif` — output type.
* `--fail-on low|medium|high|critical` — exit non-zero at/above threshold.
* `--tools` — comma-separated tools to run (default: semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict).
* `--semgrep-config <value>` — Semgrep config (registry packs or 'auto'). You can pass multiple (e.g., `p/security-audit,p/python,p/bash,p/javascript,p/sql`).
* `--no-sql-strict` — disable strict raw SQL checks (enabled by default).
* `--paths-from <file>` — scan only files listed in a text file (one per line).
* `--per-file-out-dir <dir>` — additionally write one report per file to this directory (e.g., `name_report.md`).

## Extending

Use upstream Semgrep rule packs via `--semgrep-config` (e.g., `p/security-audit,p/python,p/bash,p/javascript`).

## OSS Engine Notes

- The OSS engine includes Semgrep (code SAST), detect-secrets (secret scanning), and sqlfluff (SQL linting). You can toggle tools in `osscheck` via `--tools`.
- Requires `semgrep` to be installed and available on PATH. Example installation: `pipx install semgrep`.

### OSS-only App

- CLI: `python -m osscheck scan --path <dir> [--paths-from filelist] --tools semgrep,detect-secrets,sqlfluff`
- Web: `python run_app_oss.py` then open `http://localhost:8501`

### Batch Scanning

- Generate file lists and scan in chunks using `--paths-from`:
  - `git ls-files '*.py' > files.txt` then split into batches and run multiple invocations.
  - Each run respects `--fail-on` and outputs in `md|json|sarif`.

## Prompt Injection Detection

- Static scanners (Semgrep, detect-secrets, sqlfluff) do not reliably detect prompt injection in user content. They can flag risky code patterns (e.g., unsafely concatenating user input into prompts) using rules, but identifying malicious prompt content requires runtime/content analysis.
- Options:
  - Add Semgrep rules for LLM app code patterns (e.g., unsafe prompt building, missing input validation) — improves prevention, not detection.
  - Add a content scanner stage that checks uploaded text/markdown/notebooks for known prompt-injection indicators. This can be rule-based (regex/heuristics) or model-based.
  - For stronger coverage, pair static scanning with runtime guards (input/output filtering) in your LLM pipeline.

## Databricks Notebooks

- OSS scanning supports Databricks notebooks:
  - `.ipynb` files: Python code cells and `%sql`/`%%sql` cells are extracted and scanned by Semgrep and sqlfluff respectively.
  - Databricks-exported `.py` notebooks: `# MAGIC %sql` blocks are extracted to `.sql` and scanned.
  - Extraction happens automatically in OSS modes (CLI and Web). Findings will reference extracted files (e.g., `notebook__cell012.sql`).
