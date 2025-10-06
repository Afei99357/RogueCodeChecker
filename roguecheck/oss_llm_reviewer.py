"""
LLM-based code security reviewer.

Uses local or cloud LLMs to perform semantic security analysis of code,
detecting issues that pattern-based tools may miss.
"""

import os
from typing import List, Literal, Optional

from .llm_backends import LLMBackend, get_default_backend
from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet

SECURITY_REVIEW_PROMPT = """You are a security expert reviewing code for vulnerabilities. Analyze the following code and identify security issues.

Focus on:
1. **Prompt Injection**: Unsanitized user input in LLM prompts
2. **SQL Injection**: Unsafe SQL query construction
3. **Command Injection**: Unsafe shell command execution
4. **Authentication Issues**: Missing or weak authentication
5. **Input Validation**: Missing validation on user inputs
6. **Hardcoded Secrets**: API keys, passwords, tokens in code
7. **Business Logic Flaws**: Authorization bypasses, race conditions
8. **Insecure Defaults**: Debug mode, permissive settings

**CRITICAL**: Only report ACTUAL security vulnerabilities. Do not report:
- Code style issues
- Performance optimizations
- Missing docstrings
- General best practices (unless security-related)

For each vulnerability found, respond in this EXACT format:

VULNERABILITY: <brief title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <detailed explanation>
RECOMMENDATION: <how to fix>
---

If NO vulnerabilities found, respond with exactly: "NO_SECURITY_ISSUES_FOUND"

Code to review:
```
{code}
```

Your security analysis:"""


def parse_llm_findings(response: str, file_path: str, code: str) -> List[Finding]:
    """
    Parse LLM response into Finding objects.

    Args:
        response: Raw LLM response
        file_path: Path to the file being reviewed
        code: Original code content

    Returns:
        List of Finding objects
    """
    findings: List[Finding] = []

    if "NO_SECURITY_ISSUES_FOUND" in response:
        return findings

    # Split response into vulnerability blocks
    blocks = response.split("---")

    for block in blocks:
        block = block.strip()
        if not block or "VULNERABILITY:" not in block:
            continue

        try:
            # Parse vulnerability fields
            vuln_data = {}
            for line in block.split("\n"):
                line = line.strip()
                if ":" not in line:
                    continue

                key, value = line.split(":", 1)
                key = key.strip().upper()
                value = value.strip()

                if key in [
                    "VULNERABILITY",
                    "SEVERITY",
                    "LINE",
                    "DESCRIPTION",
                    "RECOMMENDATION",
                ]:
                    vuln_data[key] = value

            # Validate required fields
            if not all(k in vuln_data for k in ["VULNERABILITY", "SEVERITY", "LINE"]):
                continue

            # Map severity
            severity_map: dict[str, Literal["critical", "high", "medium", "low"]] = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            }
            severity = severity_map.get(
                vuln_data["SEVERITY"].upper(), "medium"
            )  # type: Literal["critical", "high", "medium", "low"]

            # Parse line number
            try:
                line_num = int(vuln_data["LINE"])
            except ValueError:
                line_num = 1

            # Create finding
            finding = Finding(
                rule_id=f"LLM_REVIEW:{vuln_data['VULNERABILITY'].replace(' ', '_').upper()}",
                severity=severity,
                message=vuln_data.get("DESCRIPTION", vuln_data["VULNERABILITY"]),
                path=file_path,
                position=Position(line=line_num, column=1),
                snippet=safe_snippet(code, line_num),
                recommendation=vuln_data.get("RECOMMENDATION"),
                meta={"engine": "llm", "source": "code_review"},
            )
            findings.append(finding)

        except Exception:
            # Skip malformed blocks
            continue

    return findings


def scan_with_llm_review(
    root: str,
    policy: Policy,
    files: Optional[List[str]] = None,
    backend: Optional[LLMBackend] = None,
    max_file_size: int = 10000,
) -> List[Finding]:
    """
    Scan code files using LLM-based security review.

    Args:
        root: Root directory being scanned
        policy: Policy configuration
        files: Optional list of specific files to scan
        backend: LLM backend to use (defaults to auto-detected)
        max_file_size: Max file size in bytes to review (default 10KB)

    Returns:
        List of findings from LLM review
    """
    findings: List[Finding] = []

    # Get or create backend
    if backend is None:
        try:
            backend = get_default_backend()
        except Exception as e:
            # Return diagnostic finding if LLM not available
            findings.append(
                Finding(
                    rule_id="LLM_ENGINE_UNAVAILABLE",
                    severity="low",
                    message=f"LLM code review unavailable: {e}",
                    path=relpath(root, os.getcwd()),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Install Ollama or configure Databricks endpoint to enable LLM review.",
                    meta={"engine": "llm"},
                )
            )
            return findings

    # Check if backend is available
    if not backend.is_available():
        # Add more detailed diagnostic for Databricks
        recommendation = (
            "Start Ollama service or verify Databricks endpoint configuration."
        )
        if hasattr(backend, "endpoint_name"):
            # Databricks backend - check what's missing
            missing = []
            if not backend.endpoint_name:
                missing.append("SERVING_ENDPOINT")
            if not backend.workspace_url:
                missing.append("DATABRICKS_HOST")
            if not backend.token:
                missing.append("DATABRICKS_TOKEN")
            if missing:
                recommendation = f"Missing environment variables: {', '.join(missing)}"

        findings.append(
            Finding(
                rule_id="LLM_ENGINE_NOT_READY",
                severity="low",
                message="LLM backend not available. Skipping LLM code review.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation=recommendation,
                meta={"engine": "llm"},
            )
        )
        return findings

    # Determine files to scan
    scan_files: List[str] = []
    if files:
        scan_files = [f for f in files if os.path.isfile(f)]
    elif os.path.isfile(root):
        scan_files = [root]
    elif os.path.isdir(root):
        # Scan Python files by default
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(".py"):
                    scan_files.append(os.path.join(dirpath, fn))

    # Scan each file
    for file_path in scan_files:
        try:
            # Skip large files
            file_size = os.path.getsize(file_path)
            if file_size > max_file_size:
                continue

            # Read file
            code = read_text(file_path)
            if not code.strip():
                continue

            # Generate review prompt
            prompt = SECURITY_REVIEW_PROMPT.format(code=code)

            # Get LLM analysis
            response = backend.generate(prompt, max_tokens=2000, temperature=0.1)

            # Parse findings
            file_findings = parse_llm_findings(response, relpath(file_path, root), code)
            findings.extend(file_findings)

        except Exception as e:
            # Add diagnostic for failed reviews
            findings.append(
                Finding(
                    rule_id="LLM_REVIEW_ERROR",
                    severity="low",
                    message=f"LLM review failed for {file_path}: {e}",
                    path=relpath(file_path, root),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Check LLM backend configuration and file accessibility.",
                    meta={"engine": "llm"},
                )
            )

    return findings
