# RogueCodeChecker Project Analysis

## Open Source Security Packages

Your project uses **8 open source tools** for security scanning:

1. **semgrep** (v1.139.0) - Semantic pattern matching for security rules (SAST)
2. **detect-secrets** (v1.5.0) - Detects hardcoded secrets, API keys, passwords
3. **gitleaks** - Detects secrets and sensitive information in git repositories and files *(CLI only - requires binary installation)*
4. **pip-audit** (v2.7.0+) - Scans Python dependencies for known vulnerabilities
5. **sqlfluff** (v3.4.2) - SQL linter for style and anti-patterns
6. **shellcheck-py** (v0.11.0.1) - Shell script analyzer
7. **sqlcheck** - SQL anti-pattern detection library
8. **LLM-based review** (Optional) - Uses Databricks models for semantic analysis

**Note on GitLeaks:** GitLeaks is available in the CLI tool (`osscheck-cli`) where users have control over their environment to install the binary. It is excluded from the Streamlit app defaults because Databricks Apps don't allow binary installation. Users can install gitleaks via: `brew install gitleaks` (macOS) or download from [GitHub releases](https://github.com/gitleaks/gitleaks/releases).

## Self-Defined Rules

Your project has **27+ custom rules** organized into 4 categories:

### 1. Python Security Rules (`roguecheck/rules/python-security.yaml`)
- `python-dangerous-eval` - Detects eval() usage
- `python-dangerous-exec` - Detects exec() usage
- `python-os-system-injection` - Shell injection via os.system()
- `python-subprocess-shell-true` - subprocess with shell=True
- `python-pickle-load` - Unsafe pickle deserialization
- `python-requests-verify-false` - Disabled SSL verification
- `python-hardcoded-secret-in-environ` - Hardcoded environment variables
- `python-sql-injection-spark` - SQL injection in Spark queries

### 2. Prompt Injection Rules (`roguecheck/rules/prompt-injection.yaml`)
- `python-prompt-function-with-user-param` - Unvalidated user input in prompt functions
- `python-string-format-in-prompt-function` - String formatting in prompt builders
- `python-docstring-warns-about-prompt-injection` - Warning patterns in docstrings
- `python-llm-api-call-in-function` - LLM API calls with user parameters
- `python-comment-warns-prompt-injection` - Comment warnings about injection

### 3. AI Code Quality Rules (`roguecheck/rules/ai-code-quality.yaml`)
- `python-missing-input-validation` - Parameters without validation
- `python-overly-permissive-exception` - Bare except clauses
- `python-todo-fixme-in-security-context` - TODOs in security code
- `python-debug-code-left-enabled` - Debug statements left in code
- `python-ai-generated-placeholder` - Placeholder values (YOUR_API_KEY, etc.)
- `python-incomplete-error-handling` - Empty except blocks
- `python-missing-authentication-check` - API endpoints without auth
- `python-rate-limiting-missing` - LLM endpoints without rate limiting

### 4. SQL Strict Rules (`roguecheck/oss_sql_strict.py`)
- `SQL_STRICT_GRANT_ALL` - Broad GRANT ALL statements
- `SQL_STRICT_DROP_TABLE` - Potentially destructive DROP TABLE
- `SQL_STRICT_DELETE_ALL` - DELETE without WHERE clause

## Streamlit App Integration

The Streamlit app (`streamlit_app_oss/main.py`) integrates all these through:

- **Config Panel**: Choose Semgrep packs, enable LLM review, set thresholds
- **File Upload**: Supports 20+ file types (.py, .sql, .sh, .ipynb, .js, .ts, etc.)
- **Scanner Service**: Orchestrates all 7 OSS tools (semgrep, detect-secrets, pip-audit, sqlfluff, shellcheck, sqlcheck, sql-strict) + custom rules
- **Results Display**: Filtered tables, severity breakdown, per-file reports
- **Export**: Download findings as Markdown reports in ZIP format

The app automatically augments Semgrep packs based on uploaded file types and deduplicates findings by rule_id, path, and line number.
