# Custom Semgrep Rules for AI Code Security

This directory contains custom Semgrep rules specifically designed to detect security issues in AI-generated code and LLM-integrated applications.

## Rules Overview

### AI Security Rules (`ai-security/`)

#### Prompt Injection Detection (`prompt-injection.yaml`)

Detects potential prompt injection vulnerabilities in LLM integrations:

- **python-prompt-function-with-user-param**: Identifies functions that build prompts with user input parameters
  - Severity: ERROR
  - Matches function names containing: prompt, build, create, message, instruction
  - Matches parameters containing: user, input, query, message, data, content

- **python-string-format-in-prompt-function**: Detects string formatting in prompt-building functions
  - Severity: WARNING
  - Catches `.format()` and `%` formatting in LLM-related functions

- **python-docstring-warns-about-prompt-injection**: Flags functions with security-warning docstrings
  - Severity: WARNING
  - Matches docstrings mentioning: untrusted, unsafe, naive, injection, attack

- **python-llm-api-call-in-function**: Detects LLM API calls that may use unvalidated input
  - Severity: WARNING
  - Matches OpenAI, Anthropic, and other LLM API calls

- **python-comment-warns-prompt-injection**: Identifies comments mentioning injection risks
  - Severity: INFO
  - Useful for finding intentionally vulnerable test code

#### AI Code Quality Issues (`ai-code-quality.yaml`)

Detects common security issues in AI-generated code:

- **python-missing-input-validation**: Functions without input validation
- **python-overly-permissive-exception**: Bare `except:` clauses
- **python-todo-fixme-in-security-context**: TODO comments in security-sensitive code
- **python-debug-code-left-enabled**: Debug statements in production code
- **python-ai-generated-placeholder**: Placeholder values (YOUR_API_KEY, REPLACE_ME, etc.)
- **python-incomplete-error-handling**: Empty except blocks
- **python-missing-authentication-check**: API endpoints without auth
- **python-rate-limiting-missing**: LLM API endpoints without rate limiting

## Usage

### With CLI

Scan with custom rules:

```bash
# Use only custom rules
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --semgrep-config semgrep_rules/ai-security/ \
  --format md

# Combine with registry packs
uv run python -m osscheck_cli scan \
  --path mycode/ \
  --semgrep-config p/security-audit,semgrep_rules/ai-security/ \
  --format md
```

### With Streamlit App

1. Start the app: `uv run streamlit run streamlit_app_oss/main.py`
2. In the sidebar under "Semgrep Packs", add: `semgrep_rules/ai-security/`
3. Upload files and scan

### Directly with Semgrep

```bash
# Scan specific file
semgrep --config semgrep_rules/ai-security/ myfile.py

# Scan directory
semgrep --config semgrep_rules/ai-security/ src/

# Combine with other configs
semgrep --config p/python --config semgrep_rules/ai-security/ .
```

## Test Files

Test the rules against the provided examples:

```bash
# Test prompt injection detection
semgrep --config semgrep_rules/ai-security/prompt-injection.yaml \
  test_samples/prompt_injection_example.py

# Test AI code quality rules
semgrep --config semgrep_rules/ai-security/ai-code-quality.yaml \
  test_samples/dangerous_python.py
```

## Expected Output

Running against `test_samples/prompt_injection_example.py`:

```
python-prompt-function-with-user-param
  Potential prompt injection risk in function 'build_prompt'!
  Line 4: def build_prompt(user_input: str) -> str:
```

## Rule Development

### Adding New Rules

1. Create or edit YAML files in `semgrep_rules/ai-security/`
2. Follow Semgrep rule syntax: https://semgrep.dev/docs/writing-rules/rule-syntax
3. Test your rule:
   ```bash
   semgrep --config your-rule.yaml test_file.py --test
   ```
4. Add test cases in `test_samples/`

### Rule Template

```yaml
rules:
  - id: your-rule-id
    patterns:
      - pattern: |
          vulnerable_code_pattern
    message: |
      Description of the vulnerability and how to fix it.
    metadata:
      category: security
      technology:
        - python
        - llm
      confidence: HIGH
      likelihood: HIGH
      impact: CRITICAL
    severity: ERROR
    languages:
      - python
```

## Coverage

These rules detect:

✅ Prompt injection in function parameters
✅ Unsafe string formatting in LLM contexts
✅ Missing input validation
✅ AI-generated code smells
✅ Debug code in production
✅ Missing authentication
✅ Missing rate limiting
✅ Placeholder values

## False Positives

Some rules may flag intentional test code. Use `# nosem` comments to suppress:

```python
def vulnerable_test_function(user_input: str):  # nosem: python-prompt-function-with-user-param
    """Intentionally vulnerable for testing"""
    return f"Prompt: {user_input}"
```

## References

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Semgrep Rule Writing](https://semgrep.dev/docs/writing-rules/overview)
- [Simon Willison on Prompt Injection](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)
