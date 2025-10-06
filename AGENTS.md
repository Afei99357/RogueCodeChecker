# Repository Guidelines

## Project Structure & Module Organization
- `roguecheck/` holds the core OSS scanner orchestration (Semgrep, detect-secrets, sqlfluff, shellcheck, strict SQL, snippet extractors).
- `osscheck_cli/` exposes the command-line interface; `run_app_oss.py` launches the Streamlit UI in `streamlit_app_oss/` (components, services, pages).
- `scripts/` contains helper workflows such as `scan_local.sh` (one-command scan) and `cli_app_parity_check.sh` (CLI vs app sanity run).
- `test_samples/` provides cross-language fixtures; add new regression cases here before coding changes. Generated reports go in `out_cli/` or `test_output/` (gitignored).
- Root configs: `requirements.txt`, `uv.lock`, `policy.yaml`, and `allowlists.yaml` define runtime dependencies and guard-rail policies.

## Build, Test, and Development Commands
- `uv sync` — install pinned dependencies into `.venv`.
- `uv run python -m osscheck_cli scan --path test_samples --per-file-out-dir out_cli` — end-to-end CLI validation with per-file Markdown.
- `uv run streamlit run streamlit_app_oss/main.py` — launch the Streamlit app locally.
- `bash scripts/scan_local.sh test_samples` — convenience wrapper that mirrors the default CLI options.
- `bash scripts/cli_app_parity_check.sh` — ensure the app and CLI surface identical findings on fixtures.

## Coding Style & Naming Conventions
- Python 3.10+, 4-space indentation, descriptive docstrings, and explicit type hints (mirroring existing modules in `roguecheck/`).
- Keep functions focused; prefer smaller helpers over large monoliths for new scanners or UI components.
- Use lowercase_with_underscores for modules/functions, PascalCase for classes, and UPPER_CASE for constants.
- Follow existing doc/comment tone: short, intent-focused comments only when behaviour is non-obvious.

## Testing Guidelines
- Add targeted unit tests under `tests/` (create the directory if absent) for new parsing or rule logic. Use `pytest` style naming: `test_<feature>.py` with descriptive method names.
- For integration checks, wire new fixtures into `test_samples/` and run `scripts/cli_app_parity_check.sh` plus manual Streamlit sweeps before submitting.
- Update or extend sample files whenever a bug fix relies on a new pattern so regressions are covered by the parity script.

## Commit & Pull Request Guidelines
- Follow conventional commits seen in history (`feat(streamlit): …`, `fix(cli): …`, `chore(deps): …`); keep messages imperative and scoped.
- Group related changes per commit; avoid mixing feature work and formatting in one diff.
- Pull requests should include: concise summary, testing evidence (CLI command outputs or screenshots), mention of new fixtures, and any deployment considerations (e.g., Semgrep pack additions or Databricks app updates).
- Confirm `README.md` and `AGENTS.md` stay accurate when flows or dependencies change.

## Security & Configuration Tips
- Verify Semgrep packs include required coverage (e.g., `p/security-audit`, `p/ai-code-security/prompt-injection`); document any local rule mirrors.
- Keep `policy.yaml` and `allowlists.yaml` in sync with customer requirements; note changes in PR descriptions.
- Ensure shellcheck availability on target runtimes or surface guidance in diagnostics when absent.
