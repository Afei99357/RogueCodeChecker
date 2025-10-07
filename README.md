# RogueCheck

Security scanner for detecting malicious code patterns, vulnerabilities, and AI-specific security issues using open-source tools and LLM-based analysis.

## Features

### Multi-Layer Security Scanning

1. **Static Analysis (Semgrep)**
   - Multi-language SAST with 10+ language support
   - Security-audit, OWASP Top 10, secrets detection
   - Custom AI security rules (prompt injection, AI code quality)

2. **LLM-Based Code Review**
   - Semantic security analysis using local (Ollama) or cloud (Databricks) LLMs
   - Detects context-specific vulnerabilities pattern-based tools miss
   - Supports qwen3, llama3, codellama, and custom models

3. **Specialized Scanners**
   - **Secrets**: detect-secrets for API keys, tokens, passwords
   - **SQL**: sqlfluff linting + strict security checks (unsafe queries, missing WHERE)
   - **Shell**: ShellCheck for bash/sh scripts
   - **Notebooks**: Extracts and scans .ipynb and Databricks notebooks

4. **Smart Detection**
   - Embedded code extraction (SQL in Python strings, shell in Java, etc.)
   - Per-file reports (Markdown, JSON, SARIF)

## Installation

```bash
# Using uv (recommended)
uv sync
```

**Optional: Install Ollama for local LLM review**
```bash
# Install Ollama: https://ollama.ai
ollama pull qwen3
```

## Quick Start

### CLI

**Using the wrapper script (easiest):**
```bash
# Comprehensive scan with all tools and custom rules
bash scripts/scan_local.sh myproject/

# With LLM review (requires Ollama + Qwen3)
bash scripts/scan_local.sh myproject/ --llm
```

**Direct CLI (full control):**
```bash
# All tools + custom rules + LLM review
uv run python -m osscheck_cli scan \
  --path myproject/ \
  --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict,llm-review \
  --semgrep-config p/security-audit,p/owasp-top-ten,roguecheck/rules/ \
  --llm-backend ollama \
  --llm-model qwen3
```

### Streamlit App

```bash
# Start the app
uv run streamlit run streamlit_app_oss/main.py

# Open browser to http://localhost:8501
# Upload files, configure settings in sidebar, and scan
```

## CLI Usage

### Wrapper Script Usage

**Basic scan (no LLM):**
```bash
bash scripts/scan_local.sh myproject/
```

**With LLM review:**
```bash
bash scripts/scan_local.sh myproject/ --llm
```

**Custom output directory:**
```bash
bash scripts/scan_local.sh myproject/ --llm --out my_reports/
```

**Other options:**
```bash
bash scripts/scan_local.sh myproject/ --llm --format json --out reports/
```

### Direct CLI Usage

**Comprehensive scan with everything:**
```bash
uv run python -m osscheck_cli scan \
  --path myproject/ \
  --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict,llm-review \
  --semgrep-config p/security-audit,p/owasp-top-ten,roguecheck/rules/ \
  --llm-backend ollama \
  --llm-model qwen3 \
  --per-file-out-dir reports/
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--path <dir\|file>` | Directory or file to scan | `.` |
| `--format <md\|json\|sarif>` | Output format | `md` |
| `--tools <list>` | Comma-separated tools to run | `semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict` |
| `--semgrep-config <packs>` | Semgrep packs (comma-separated) | `p/security-audit,p/owasp-top-ten,p/secrets,p/python,p/javascript,p/typescript` |
| `--llm-backend <ollama\|databricks>` | LLM backend for code review | `ollama` |
| `--llm-model <name>` | Model name for Ollama | `qwen3` |
| `--per-file-out-dir <dir>` | Write per-file reports | None |
| `--fail-on <severity>` | Exit non-zero if severity found | `high` |

## Streamlit App Usage

### Setup

**1. Configure LLM Backend (Optional)**

For Ollama (local):
```bash
export OLLAMA_MODEL=qwen3
export OLLAMA_ENDPOINT=http://localhost:11434
```

For Databricks:
```bash
export DATABRICKS_HOST=https://your-workspace.cloud.databricks.com
export DATABRICKS_TOKEN=dapi...
export DATABRICKS_LLM_ENDPOINT=llama-2-70b-chat
```

**2. Start the App**
```bash
uv run streamlit run streamlit_app_oss/main.py
```

**3. Open Browser**
Navigate to `http://localhost:8501`

### Using the App

1. **Configure Settings (Sidebar)**
   - Set priority focus (low/medium/high/critical)
   - Add custom Semgrep packs: `roguecheck/rules/`
   - Enable "LLM Code Review" and select backend

2. **Upload Files**
   - Drag & drop or browse files
   - Supports: `.py`, `.sql`, `.sh`, `.js`, `.ts`, `.java`, `.go`, `.rb`, `.php`, `.cs`, `.tf`, `.yaml`, `.ipynb`, Dockerfile

3. **Scan & View Results**
   - View combined results or by-file
   - Download reports (CSV, Markdown, per-file ZIP)
   - Check diagnostics panel for tool status

### Example Streamlit Workflow

**Scenario: Scan AI-generated Python code with LLM review**

1. Start app: `uv run streamlit run streamlit_app_oss/main.py`
2. Sidebar → "Semgrep Packs": Add `roguecheck/rules/`
3. Sidebar → Check "Enable LLM Code Review"
4. Sidebar → Select backend: `databricks` or `ollama`
5. Upload your Python files
6. Click "Scan"
7. Review findings with severity colors
8. Download Markdown report

## What Gets Scanned

### Languages & File Types

- **Python** (`.py`, `.ipynb`)
- **SQL** (`.sql`, embedded in notebooks)
- **Shell** (`.sh`, `.bash`)
- **JavaScript/TypeScript** (`.js`, `.ts`)
- **Java** (`.java`)
- **Go** (`.go`)
- **Ruby** (`.rb`)
- **PHP** (`.php`)
- **C#** (`.cs`)
- **Terraform** (`.tf`)
- **YAML** (`.yaml`, `.yml`)
- **Dockerfile**
- **Notebooks** (`.ipynb`, Databricks `.py`)

### Security Issues Detected

**Semgrep (Pattern-Based):**
- OWASP Top 10 vulnerabilities
- SQL injection, command injection
- Hardcoded secrets (API keys, passwords)
- Insecure defaults, missing auth
- Prompt injection (custom rules)
- AI code quality issues (custom rules)

**LLM Review (Semantic):**
- Prompt injection with context understanding
- Business logic flaws
- Authorization bypasses
- Context-specific vulnerabilities
- Race conditions
- Unsafe input validation

## AI Security Features

RogueCheck includes specialized scanning for AI/LLM security:

### Custom Semgrep Rules

**Location:** `roguecheck/rules/`

**What it detects:**
- Functions building prompts with user input
- String formatting in prompt functions
- LLM API calls with unvalidated input
- Missing input validation
- Debug code in production
- Placeholder values
- Missing authentication
- Missing rate limiting

**Usage:**
```bash
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --semgrep-config roguecheck/rules/
```

See `roguecheck/rules/README.md` for full rule documentation.

### LLM-Based Code Review

**What it detects:**
- Semantic security issues
- Complex injection patterns
- Business logic vulnerabilities
- Context-aware threat analysis

**Backends:**
- **Ollama** (local): Privacy-first, offline operation
- **Databricks**: Enterprise-scale, cloud-based

**Models supported:**
- qwen3 (fast, recommended)
- llama3 (powerful)
- codellama (code-specialized)
- Custom models via Ollama

**Usage:**
```bash
# Local Ollama
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --tools llm-review \
  --llm-backend ollama \
  --llm-model qwen3

# Databricks
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --tools llm-review \
  --llm-backend databricks
```

See `LLM_CODE_REVIEW.md` for comprehensive documentation.

## Examples

### Example 1: Quick Security Scan
```bash
# Scan a project with default tools
uv run python -m osscheck_cli scan --path myproject/
```

### Example 2: AI Code Security Scan
```bash
# Scan AI-generated code with custom rules + LLM review
uv run python -m osscheck_cli scan \
  --path ai_generated_code/ \
  --tools semgrep,detect-secrets,llm-review \
  --semgrep-config p/security-audit,roguecheck/rules/ \
  --llm-backend ollama \
  --llm-model qwen3 \
  --format md
```

### Example 3: Comprehensive Scan with Reports
```bash
# Full scan with all tools and per-file reports
uv run python -m osscheck_cli scan \
  --path myproject/ \
  --tools semgrep,detect-secrets,sqlfluff,shellcheck,sql-strict,llm-review \
  --semgrep-config p/security-audit,p/owasp-top-ten,roguecheck/rules/ \
  --llm-backend ollama \
  --per-file-out-dir reports/ \
  --format md
```

### Example 4: Single File Scan
```bash
# Scan a single Python file
uv run python -m osscheck_cli scan \
  --path src/main.py \
  --tools semgrep,detect-secrets,llm-review \
  --llm-backend ollama
```

### Example 5: CI/CD Integration
```bash
# Fail build if high/critical issues found
uv run python -m osscheck_cli scan \
  --path . \
  --tools semgrep,detect-secrets,sql-strict \
  --fail-on high \
  --format sarif \
  --out report.sarif
```

## Environment Variables

### Ollama Configuration
```bash
export OLLAMA_MODEL=qwen3                      # Model name (optional, default: qwen3)
export OLLAMA_ENDPOINT=http://localhost:11434  # Ollama endpoint (optional, default: localhost:11434)
```

### Databricks Configuration
```bash
export DATABRICKS_HOST=https://your-workspace.cloud.databricks.com  # Required
export DATABRICKS_TOKEN=dapi...                                      # Required
export DATABRICKS_LLM_ENDPOINT=llama-2-70b-chat                     # Required
```

## Troubleshooting

### "No issues found" but expecting findings
- Check tool versions: `semgrep --version`, `detect-secrets --version`
- Verify Semgrep packs are accessible: try `--semgrep-config auto`
- Check file extensions match tool patterns

### LLM review not working
- **Ollama**: Verify Ollama is running: `ollama list`
- **Ollama**: Pull model: `ollama pull qwen3`
- **Databricks**: Check environment variables are set correctly
- **Databricks**: Verify endpoint is running: `curl -H "Authorization: Bearer $DATABRICKS_TOKEN" $DATABRICKS_HOST/api/2.0/serving-endpoints/$DATABRICKS_LLM_ENDPOINT`

### ShellCheck not found
- Install via package manager: `brew install shellcheck` or `apt install shellcheck`
- Or rely on `shellcheck-py` (already in pyproject.toml dependencies)

### Semgrep permission errors in containers
- Set writable home: `export SEMGREP_USER_HOME=$(pwd)/.semgrephome`

## Documentation

- **`semgrep_rules/README.md`** - Custom Semgrep rules documentation
- **`LLM_CODE_REVIEW.md`** - LLM code review comprehensive guide
- **`AI_SECURITY_RULES.md`** - AI security features summary

## Requirements

- Python 3.10+
- Network access to semgrep.dev (for registry packs)
- Optional: Ollama (for local LLM review)
- Optional: Databricks workspace with serving endpoint (for cloud LLM review)

## License

See LICENSE file for details.
