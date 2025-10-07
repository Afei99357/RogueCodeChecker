"""
LLM-based code security reviewer.

Uses local or cloud LLMs to perform semantic security analysis of code,
detecting issues that pattern-based tools may miss.
"""

import os
from typing import List, Literal, Optional

from .llm_backends import LLMBackend, get_default_backend
from .models import Finding, Position
from .utils import read_text, relpath, safe_snippet

# Prompt for files with NO findings from OSS tools - do full review
GAP_FILLING_PROMPT = """You are a security expert reviewing code for vulnerabilities. Static analysis tools found NO issues in this file, but they may have missed something.

**YOUR MISSION:** Find security issues that pattern-based tools missed.

**CRITICAL VULNERABILITIES TO DETECT:**
1. **eval() or exec()**: Arbitrary code execution
2. **pickle.load()**: Unsafe deserialization
3. **os.system()**: Shell command injection
4. **subprocess with shell=True**: Command injection
5. **SQL string concatenation/f-strings**: SQL injection
6. **requests with verify=False**: Disabled SSL verification
7. **yaml.load() without SafeLoader**: Code execution via YAML
8. **Hardcoded secrets**: API keys, passwords, tokens in code
9. **Prompt Injection**: Unsanitized user input in LLM prompts
10. **Authentication Issues**: Missing or weak authentication
11. **Input Validation**: Missing validation on user inputs
12. **Logic flaws**: Race conditions, business logic bypasses

**INSTRUCTIONS:**
- Focus on semantic issues that regex/patterns can't catch
- Look for context-dependent vulnerabilities
- Analyze data flow and control flow
- Ignore comments - analyze actual code behavior
- Even if it's a test file, report all vulnerabilities

For each vulnerability found, respond in this EXACT format:

VULNERABILITY: <brief title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <detailed explanation>
RECOMMENDATION: <how to fix>
---

If NO additional vulnerabilities found, respond with exactly: "NO_SECURITY_ISSUES_FOUND"

Code to review:
```
{code}
```

Your security analysis:"""

# Prompt for files WITH findings - look for ADDITIONAL issues only
ENRICHMENT_PROMPT = """You are a security expert reviewing code. Static analysis tools already found these issues:

{existing_findings}

**YOUR MISSION:** Find ADDITIONAL security issues that the tools missed. DO NOT repeat the issues above.

**CRITICAL VULNERABILITIES TO CHECK (that tools may have missed):**
1. **eval() or exec()**: Arbitrary code execution (indirect patterns)
2. **pickle.load()**: Unsafe deserialization (dynamic module loading)
3. **os.system()**: Shell command injection (via variables)
4. **subprocess with shell=True**: Command injection (partial user input)
5. **SQL string concatenation/f-strings**: SQL injection (complex patterns)
6. **requests with verify=False**: Disabled SSL verification (conditionally set)
7. **yaml.load() without SafeLoader**: Code execution via YAML (custom loaders)
8. **Hardcoded secrets**: API keys, passwords, tokens (obfuscated or encoded)
9. **Prompt Injection**: Unsanitized user input in LLM prompts (indirect flow)
10. **Authentication Issues**: Missing or weak authentication (logic-level)
11. **Input Validation**: Missing validation on user inputs (complex inputs)
12. **Logic flaws**: Race conditions, business logic bypasses, TOCTOU

**FOCUS AREAS:**
- Context-dependent vulnerabilities the tools can't understand
- Complex data flow issues (multi-step injection paths)
- Indirect code injection paths (via config, templates, imports)
- Authentication/authorization flaws in business logic
- Configuration issues that depend on usage context

**INSTRUCTIONS:**
- Only report NEW issues not already listed above in the findings
- Focus on semantic/contextual security problems
- Analyze how the code is used in context
- Look for indirect/complex patterns of the critical vulnerabilities

For each NEW vulnerability found, respond in this EXACT format:

VULNERABILITY: <brief title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <detailed explanation>
RECOMMENDATION: <how to fix>
---

If NO additional vulnerabilities found beyond what tools detected, respond: "NO_ADDITIONAL_ISSUES_FOUND"

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

    # Check for "no issues" responses from both modes
    if (
        "NO_SECURITY_ISSUES_FOUND" in response
        or "NO_ADDITIONAL_ISSUES_FOUND" in response
    ):
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
    files: Optional[List[str]] = None,
    backend: Optional[LLMBackend] = None,
    max_file_size: int = 10000,
    existing_findings: Optional[List[Finding]] = None,
) -> List[Finding]:
    """
    Scan code files using LLM-based security review.

    Two-stage approach:
    - For files WITH findings: LLM looks for ADDITIONAL issues only (enrichment)
    - For files WITHOUT findings: LLM does full security review (gap-filling)

    Args:
        root: Root directory being scanned
        files: Optional list of specific files to scan
        backend: LLM backend to use (defaults to auto-detected)
        max_file_size: Max file size in bytes to review (default 10KB)
        existing_findings: Findings from OSS/rule-based tools (for enrichment mode)

    Returns:
        List of NEW findings from LLM review (non-overlapping with existing)
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
        # Provide recommendation based on backend type
        recommendation = (
            "Start Ollama service or verify Databricks endpoint configuration."
        )
        if hasattr(backend, "endpoint_name") and not backend.endpoint_name:
            recommendation = "Missing SERVING_ENDPOINT environment variable."

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
        # If explicit file list provided, scan all of them
        scan_files = [f for f in files if os.path.isfile(f)]
    elif os.path.isfile(root):
        scan_files = [root]
    elif os.path.isdir(root):
        # When scanning a directory, scan all code files (skip binaries, images, etc.)
        code_extensions = (
            ".py",
            ".js",
            ".ts",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".cs",
            ".sh",
            ".bash",
            ".sql",
            ".tf",
            ".yaml",
            ".yml",
            ".json",
            ".md",
            ".txt",
        )
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(code_extensions) or fn == "Dockerfile":
                    scan_files.append(os.path.join(dirpath, fn))

    # Group existing findings by file path for enrichment mode
    findings_by_file: dict[str, List[Finding]] = {}
    if existing_findings:
        for finding in existing_findings:
            path = finding.path
            if path not in findings_by_file:
                findings_by_file[path] = []
            findings_by_file[path].append(finding)

    # Scan each file
    print(f"\n🤖 LLM Review: Scanning {len(scan_files)} file(s)...")
    for idx, file_path in enumerate(scan_files, 1):
        try:
            # Skip large files
            file_size = os.path.getsize(file_path)
            if file_size > max_file_size:
                print(
                    f"  [{idx}/{len(scan_files)}] ⏭️  Skipping {relpath(file_path, root)} (too large: {file_size} bytes)"
                )
                continue

            # Read file
            code = read_text(file_path)
            if not code.strip():
                print(
                    f"  [{idx}/{len(scan_files)}] ⏭️  Skipping {relpath(file_path, root)} (empty)"
                )
                continue

            # Determine which prompt to use
            rel_path = relpath(file_path, root)
            file_existing_findings = findings_by_file.get(rel_path, [])

            if file_existing_findings:
                # ENRICHMENT MODE: File has findings - look for additional issues
                print(
                    f"  [{idx}/{len(scan_files)}] 🔍 Enriching {rel_path} ({len(file_existing_findings)} existing findings)..."
                )
                # Format existing findings for prompt
                findings_text = "\n".join(
                    f"- {f.rule_id}: {f.message} (line {f.position.line})"
                    for f in file_existing_findings
                )
                prompt = ENRICHMENT_PROMPT.format(
                    existing_findings=findings_text, code=code
                )
            else:
                # GAP-FILLING MODE: File has no findings - do full review
                print(
                    f"  [{idx}/{len(scan_files)}] 🔍 Reviewing {rel_path} (gap-filling)..."
                )
                prompt = GAP_FILLING_PROMPT.format(code=code)

            # Get LLM analysis
            response = backend.generate(prompt, max_tokens=2000, temperature=0.1)

            # Parse findings
            file_findings = parse_llm_findings(response, rel_path, code)
            findings.extend(file_findings)

            if file_findings:
                print(f"      ✓ Found {len(file_findings)} additional issue(s)")
            else:
                print(f"      ✓ No additional issues found")

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
