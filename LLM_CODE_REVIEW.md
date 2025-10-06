# LLM-Based Code Security Review

RogueCheck includes an LLM-based semantic security analyzer that complements pattern-based tools (Semgrep) with AI-powered code understanding.

## Overview

The LLM code reviewer performs deep semantic analysis to detect security vulnerabilities that static analysis tools may miss, including:

- **Prompt Injection**: Unsanitized user input in LLM prompts
- **SQL Injection**: Unsafe SQL query construction
- **Command Injection**: Unsafe shell command execution
- **Authentication Issues**: Missing or weak authentication
- **Input Validation**: Missing validation on user inputs
- **Hardcoded Secrets**: API keys, passwords, tokens in code
- **Business Logic Flaws**: Authorization bypasses, race conditions
- **Insecure Defaults**: Debug mode, permissive settings

## Architecture

### Backend Abstraction Layer

The LLM reviewer uses a flexible backend abstraction that supports multiple LLM providers:

```
roguecheck/
├── llm_backends.py          # Backend abstraction layer
│   ├── LLMBackend (ABC)     # Base interface
│   ├── OllamaBackend        # Local Ollama support
│   ├── DatabricksBackend    # Databricks FM support
│   └── create_backend()     # Factory function
└── oss_llm_reviewer.py      # Security review scanner
```

### Why Multiple Backends?

- **CLI**: Uses **Ollama** (local) for privacy and offline operation
- **Streamlit**: Uses **Databricks Foundation Models** for enterprise deployment
- **Extensible**: Easy to add OpenAI, Anthropic, or other providers

## Installation & Setup

### Option 1: Ollama (Local)

1. Install Ollama: https://ollama.ai
2. Pull a model:
   ```bash
   ollama pull qwen3
   # OR
   ollama pull llama3
   ollama pull codellama
   ```
3. Verify:
   ```bash
   ollama list
   curl http://localhost:11434/api/tags
   ```

### Option 2: Databricks Foundation Models

1. Set environment variables:
   ```bash
   export DATABRICKS_HOST=https://your-workspace.cloud.databricks.com
   export DATABRICKS_TOKEN=dapi...
   export DATABRICKS_LLM_ENDPOINT=your-endpoint-name
   ```
2. Verify endpoint is running:
   ```bash
   curl -H "Authorization: Bearer $DATABRICKS_TOKEN" \
     $DATABRICKS_HOST/api/2.0/serving-endpoints/$DATABRICKS_LLM_ENDPOINT
   ```

## Usage

### CLI

**Basic LLM review:**
```bash
uv run python -m osscheck_cli scan \
  --path test_samples/prompt_injection_example.py \
  --tools llm-review \
  --format md
```

**Combine with Semgrep and other tools:**
```bash
uv run python -m osscheck_cli scan \
  --path myproject/ \
  --tools semgrep,detect-secrets,llm-review \
  --semgrep-config p/security-audit,semgrep_rules/ai-security/ \
  --llm-backend ollama \
  --llm-model qwen3 \
  --format md
```

**Switch models:**
```bash
# Qwen3 (default, fast)
--llm-model qwen3

# Llama3 (more powerful)
--llm-model llama3

# CodeLlama (code-specialized)
--llm-model codellama
```

**Databricks backend:**
```bash
uv run python -m osscheck_cli scan \
  --path myproject/ \
  --tools llm-review \
  --llm-backend databricks \
  --format md
```

### Streamlit App

1. Configure backend via environment variables
2. Start app: `uv run streamlit run streamlit_app_oss/main.py`
3. In sidebar:
   - Check "Enable LLM Code Review"
   - Select backend (databricks/ollama)
4. Upload files and scan

### Environment Variables

```bash
# Ollama (optional, has defaults)
export OLLAMA_MODEL=qwen3                    # Default: qwen3
export OLLAMA_ENDPOINT=http://localhost:11434 # Default: localhost:11434

# Databricks (required for databricks backend)
export DATABRICKS_HOST=https://workspace.databricks.com
export DATABRICKS_TOKEN=dapi...
export DATABRICKS_LLM_ENDPOINT=llama-2-70b-chat
```

## Example Output

**Input:** `test_samples/prompt_injection_example.py`

```python
def build_prompt(user_input: str) -> str:
    """Naively compose a system prompt with untrusted user input."""
    system_context = (
        "You are a helpful assistant. "
        "Follow policy and never disclose secrets."
    )
    return f"{system_context}\n\nUser instructions:\n{user_input}"
```

**LLM Review Findings:**

```markdown
## [CRITICAL] LLM_REVIEW:PROMPT_INJECTION — prompt_injection_example.py:12
The `build_prompt` function directly appends untrusted user input into the
system prompt without sanitization. This enables attackers to inject arbitrary
commands or bypass security constraints.

**Recommendation:** Implement input validation to filter out dangerous characters
or patterns before constructing the prompt. Use a whitelist approach to allow
only safe characters and structures.
```

## How It Works

### 1. Prompt Template

The scanner uses a structured prompt that instructs the LLM to act as a security expert:

```python
SECURITY_REVIEW_PROMPT = """You are a security expert reviewing code for vulnerabilities.

Focus on:
1. **Prompt Injection**: Unsanitized user input in LLM prompts
2. **SQL Injection**: Unsafe SQL query construction
[... 8 categories ...]

For each vulnerability found, respond in this EXACT format:

VULNERABILITY: <brief title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <detailed explanation>
RECOMMENDATION: <how to fix>
---

If NO vulnerabilities found, respond with exactly: "NO_SECURITY_ISSUES_FOUND"
"""
```

### 2. Response Parsing

The scanner parses structured LLM responses into `Finding` objects compatible with other tools:

```python
findings = parse_llm_findings(response, file_path, code)
# Returns: List[Finding] with rule_id, severity, message, position, recommendation
```

### 3. Integration

LLM findings are merged with Semgrep, detect-secrets, and other tool findings for unified reporting.

## Performance Considerations

### File Size Limits

By default, the scanner only reviews files ≤10KB to avoid overwhelming LLM context:

```python
scan_with_llm_review(
    root="myproject/",
    policy=policy,
    max_file_size=10000  # bytes (default: 10KB)
)
```

### Timeout

Ollama/Databricks requests have a 120-second timeout by default:

```python
OllamaBackend(timeout=120)  # seconds
DatabricksBackend(timeout=120)
```

### Token Limits

The prompt limits LLM responses to 2000 tokens to keep results focused and fast.

## Error Handling

### LLM Unavailable

If the LLM backend is not available, the scanner returns a diagnostic finding instead of failing:

```
[LOW] LLM_ENGINE_UNAVAILABLE
LLM code review unavailable: Connection refused
Recommendation: Install Ollama or configure Databricks endpoint to enable LLM review.
```

### Backend Initialization Failed

If backend config is missing:

```
[LOW] LLM_BACKEND_INIT_FAILED
Failed to initialize LLM backend: Databricks backend requires endpoint_name, workspace_url, and token
Recommendation: Provide via environment variables: DATABRICKS_HOST, DATABRICKS_TOKEN, DATABRICKS_LLM_ENDPOINT
```

### Individual File Review Errors

If LLM review fails for a specific file (timeout, parsing error, etc.):

```
[LOW] LLM_REVIEW_ERROR
LLM review failed for myfile.py: Request timeout
Recommendation: Check LLM backend configuration and file accessibility.
```

## Comparison: Pattern-Based vs LLM-Based

| Aspect | Custom Semgrep Rules | LLM Code Review |
|--------|---------------------|-----------------|
| **Speed** | Very fast | Slower (seconds per file) |
| **Accuracy** | High precision | May have false positives |
| **Coverage** | Known patterns only | Understands context & intent |
| **Cost** | Free | May incur API costs (Databricks) |
| **Offline** | Yes | Yes (Ollama) or No (Cloud APIs) |
| **Maintenance** | Rules need updates | Model-dependent |

**Best Practice:** Use **both** approaches together for comprehensive coverage.

## Extending the Backend

### Adding a New Backend (e.g., OpenAI)

1. Create a new backend class in `roguecheck/llm_backends.py`:

```python
class OpenAIBackend(LLMBackend):
    def __init__(self, api_key=None, model="gpt-4"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model

    def generate(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1) -> str:
        import openai
        openai.api_key = self.api_key
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature
        )
        return response.choices[0].message.content.strip()

    def is_available(self) -> bool:
        return bool(self.api_key)
```

2. Register in factory:

```python
def create_backend(backend_type: str = "ollama", **kwargs) -> LLMBackend:
    backends = {
        "ollama": OllamaBackend,
        "databricks": DatabricksBackend,
        "openai": OpenAIBackend,  # New
    }
    return backends[backend_type](**kwargs)
```

3. Use it:

```bash
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --tools llm-review \
  --llm-backend openai
```

## Troubleshooting

### "Connection refused" error

- Ollama: Make sure Ollama is running: `ollama serve`
- Databricks: Check `DATABRICKS_HOST` and `DATABRICKS_TOKEN`

### "Model not found" error

- Pull the model: `ollama pull qwen3`
- Check available models: `ollama list`

### LLM review is slow

- Reduce `max_file_size` to skip large files
- Use a faster model (qwen3 is faster than llama3)
- Consider parallel scanning (future enhancement)

### False positives

- LLMs may flag test code or intentionally vulnerable examples
- Review findings manually
- Use `# nosem: LLM_REVIEW:*` comments to suppress (future enhancement)

## Future Enhancements

- [ ] Parallel file scanning for better performance
- [ ] Caching of LLM responses for repeated scans
- [ ] OpenAI/Anthropic backend support
- [ ] Custom prompt templates per project
- [ ] Model fine-tuning on security-specific datasets
- [ ] Integration with CI/CD pipelines

## References

- [Ollama Documentation](https://ollama.ai/docs)
- [Databricks Foundation Models](https://docs.databricks.com/machine-learning/foundation-models/index.html)
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
