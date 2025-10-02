# RogueCheck

Minimal, extensible scanner for "rogue code" patterns in AI-generated snippets.

## Quickstart
```bash
# Built-in rules
python -m roguecheck scan --path . --format md --fail-on high --engine builtin

# Open-source engine (Semgrep)
python -m roguecheck scan --path . --format md --engine oss --semgrep-config auto

# OSS-only CLI (Semgrep, detect-secrets, sqlfluff)
python -m osscheck scan --path . --format md \
  --semgrep-config semgrep_rules \
  --tools semgrep,detect-secrets,sqlfluff
```

### Options

* `--policy policy.yaml` — organization policy knobs.
* `--allowlists allowlists.yaml` — domain and path allowlists.
* `--format md|json|sarif` — output type.
* `--fail-on low|medium|high|critical` — exit non-zero at/above threshold.
* `--engine builtin|oss` — choose built-in rules or OSS tools.
* `--semgrep-config <value>` — Semgrep config (when `--engine=oss`).
* `--paths-from <file>` — scan only files listed in a text file (one per line).

## Extending

Drop a `.py` file in `roguecheck/plugins/` that exposes `get_rules() -> list[callable]`.
Each rule is `fn(path: str, text: str, policy) -> Iterable[Finding]`.

For richer Python checks, switch `ast` to `libcst` or `astroid` without changing the scanner contract.

## OSS Engine Notes

- The OSS engine includes Semgrep (code SAST), detect-secrets (secret scanning), and sqlfluff (SQL linting). You can toggle tools in `osscheck` via `--tools`.
- Local Semgrep rules are included under `semgrep_rules/` (offline-friendly). Use `--semgrep-config semgrep_rules` to load them; you can pass multiple configs separated by commas (e.g., `auto,semgrep_rules`).
- Requires `semgrep` to be installed and available on PATH. Example installation: `pipx install semgrep`.
- The default `--semgrep-config=auto` may need network access to fetch rules. Provide a local ruleset if running fully offline.

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
