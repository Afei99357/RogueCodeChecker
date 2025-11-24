"""
LLM-based code security reviewer.

Uses Databricks LLMs to perform semantic security analysis of code,
detecting issues that pattern-based tools may miss.
"""

import os
from typing import List, Literal, Optional

from .models import Finding, Position
from .utils import read_text, relpath, safe_snippet

try:
    from mlflow.deployments import get_deploy_client

    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


# ============================================================================
# Databricks LLM Backend
# ============================================================================


class DatabricksLLMBackend:
    """
    Databricks Foundation Models backend for LLM-based code review.

    Uses Databricks serving endpoints for model inference via MLflow deployments.
    Automatically authenticates using workspace context when running in Databricks.
    """

    def __init__(
        self,
        endpoint_name: Optional[str] = None,
        timeout: int = 120,
    ):
        """
        Initialize Databricks backend.

        Args:
            endpoint_name: Databricks serving endpoint name
            timeout: Request timeout in seconds

        Environment variables (if endpoint_name not provided):
            SERVING_ENDPOINT or DATABRICKS_LLM_ENDPOINT: Endpoint name
        """
        if not MLFLOW_AVAILABLE:
            raise ImportError(
                "MLflow is required for Databricks backend. "
                "Install with: pip install mlflow"
            )

        self.endpoint_name = (
            endpoint_name
            or os.getenv("SERVING_ENDPOINT")
            or os.getenv("DATABRICKS_LLM_ENDPOINT")
        )
        self.timeout = timeout

        if not self.endpoint_name:
            raise ValueError(
                "Databricks backend requires endpoint_name. "
                "Provide via constructor or environment variable: SERVING_ENDPOINT"
            )

        # Get MLflow deploy client (handles authentication automatically)
        try:
            self.client = get_deploy_client("databricks")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Databricks deploy client: {e}")

    def generate(
        self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1
    ) -> str:
        """Generate response using Databricks serving endpoint via MLflow."""
        # Convert prompt to chat messages format expected by Databricks endpoints
        messages = [{"role": "user", "content": prompt}]

        try:
            response = self.client.predict(
                endpoint=self.endpoint_name,
                inputs={
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )

            # Handle different response formats from Databricks models
            # Agent/chat endpoints return "messages"
            if "messages" in response:
                return response["messages"][-1]["content"].strip()

            # Foundation models return "choices"
            elif "choices" in response:
                choice_message = response["choices"][0]["message"]
                content = choice_message.get("content", "")

                # Handle list content format
                if isinstance(content, list):
                    combined = "".join(
                        part.get("text", "")
                        for part in content
                        if part.get("type") == "text"
                    )
                    return combined.strip()

                # Handle string content format
                if isinstance(content, str):
                    return content.strip()

            raise RuntimeError(f"Unexpected Databricks response format: {response}")

        except Exception as e:
            raise RuntimeError(f"Databricks API request failed: {e}")

    def is_available(self) -> bool:
        """Check if Databricks endpoint is accessible."""
        # If we have an endpoint name and client initialized, assume available
        # The client handles authentication automatically in Databricks
        return bool(self.endpoint_name and self.client)


def create_llm_backend(endpoint_name: Optional[str] = None) -> DatabricksLLMBackend:
    """
    Create Databricks LLM backend.

    Args:
        endpoint_name: Databricks serving endpoint name (optional)

    Returns:
        Initialized Databricks LLM backend

    Examples:
        >>> backend = create_llm_backend("databricks-claude-sonnet-4-5")
        >>> backend = create_llm_backend()  # Uses SERVING_ENDPOINT env var
    """
    return DatabricksLLMBackend(endpoint_name=endpoint_name)


# ============================================================================
# Cell Batching Logic
# ============================================================================


def _batch_notebook_cells(files: List[str], max_batch_size: int) -> List[List[str]]:
    """
    Batch extracted notebook cells together to reduce LLM calls.

    Groups files from the same notebook (matching __cell pattern) into batches
    that fit within max_batch_size. Other files are kept as single-file batches.

    Args:
        files: List of file paths to scan
        max_batch_size: Maximum total size in bytes for a batch

    Returns:
        List of batches, where each batch is a list of file paths
    """
    import re

    # Group files by notebook origin
    notebook_cells: dict[str, List[str]] = {}
    standalone_files: List[str] = []

    for file_path in files:
        # Check if this is an extracted notebook cell
        basename = os.path.basename(file_path)
        match = re.match(r"(.+)__(cell|sqlblock)(\d+)\.(py|sql)$", basename)

        if match:
            notebook_name = match.group(1)
            if notebook_name not in notebook_cells:
                notebook_cells[notebook_name] = []
            notebook_cells[notebook_name].append(file_path)
        else:
            standalone_files.append(file_path)  # type: ignore[unreachable]

    # Create batches
    batches: List[List[str]] = []

    # Each standalone file gets its own batch
    for file_path in standalone_files:
        batches.append([file_path])

    # Batch cells from the same notebook
    for notebook_name, cells in notebook_cells.items():
        # Sort cells by cell number for logical order
        cells_sorted = sorted(cells)

        current_batch: List[str] = []
        current_size = 0

        for cell_path in cells_sorted:
            try:
                cell_size = os.path.getsize(cell_path)

                # If adding this cell would exceed limit, start new batch
                if current_batch and current_size + cell_size > max_batch_size:
                    batches.append(current_batch)
                    current_batch = []
                    current_size = 0

                current_batch.append(cell_path)
                current_size += cell_size

            except OSError:
                # If we can't get size, put in separate batch
                if current_batch:
                    batches.append(current_batch)
                    current_batch = []
                    current_size = 0
                batches.append([cell_path])

        # Add remaining cells
        if current_batch:
            batches.append(current_batch)

    return batches


# ============================================================================
# Platform Detection
# ============================================================================


def _detect_platform_context(code: str) -> str:
    """
    Detect execution platform from code patterns.

    Returns a context string to help LLM understand the security model.
    """
    # Databricks indicators
    if any(
        x in code
        for x in [
            "dbutils",
            "spark.table",
            "Unity Catalog",
            "/Volumes/",
            "DATABRICKS_",
            "saveAsTable",
        ]
    ):
        return """
**DETECTED PLATFORM: Databricks with Unity Catalog**
- Unity Catalog enforces table/volume access controls automatically
- saveAsTable() is Spark DataFrame API (NOT SQL string) - validates table names
- Workspace provides authentication via service principals
- Volume paths are access-controlled, preventing path traversal
- Config values in notebooks are code, not user input (unless from widgets/getArgument)
"""

    # AWS Lambda indicators
    if "def lambda_handler" in code or "boto3" in code or "aws_lambda" in code:
        return """
**DETECTED PLATFORM: AWS Lambda**
- IAM roles provide authentication and authorization
- boto3 SDK methods validate resource names
- Environment variables from Lambda config are trusted
- Check for user input from event payload
"""

    # Azure Functions indicators
    if "azure.functions" in code or "def main(req: func." in code:
        return """
**DETECTED PLATFORM: Azure Functions**
- Azure AD provides authentication
- SDK methods validate resource names
- Environment variables from function config are trusted
- Check for user input from HTTP requests
"""

    # Web frameworks
    if any(x in code for x in ["Flask", "FastAPI", "Django", "@app.route", "@api"]):
        return """
**DETECTED PLATFORM: Web Framework (Flask/FastAPI/Django)**
- Check for framework-provided authentication decorators
- Framework may provide input validation
- ALL HTTP request parameters are user-controlled
- Check for CSRF, XSS, SQL injection in web context
"""

    # Generic Python
    return """
**PLATFORM: Unknown/Generic Python**
- Assume NO built-in authentication or access controls
- Validate all external inputs carefully
- Check for common Python vulnerabilities
"""


# ============================================================================
# LLM Review Prompts
# ============================================================================

# Prompt for files with NO findings from OSS tools - do full review
GAP_FILLING_PROMPT = """You are a security expert reviewing code for REAL, EXPLOITABLE vulnerabilities.

{platform_context}

**CRITICAL: Avoid False Positives**
Before flagging an issue, answer these 4 questions:

**Q1: Is this input ATTACKER-CONTROLLED?**
✅ YES: User widgets (dbutils.widgets.get), HTTP request params, CLI args, file uploads, untrusted env vars
❌ NO: Hardcoded config dicts, constants in code, internal configuration

**Q2: Does the PLATFORM or CODE validate this input?**
✅ Validated: API methods (saveAsTable, boto3 SDK), framework validators, allowlist checks
❌ Not validated: String concatenation, direct SQL/shell execution, no input checks

**Q3: Can you write a REALISTIC exploit payload?**
✅ YES: Provide specific exploit example
❌ NO: If you can't demonstrate it, don't report it

**Q4: What's the ACTUAL impact?**
✅ Real: SQL injection reads data, RCE executes commands, auth bypass grants access
❌ Theoretical: "Could maybe affect something" is not enough

**Only report if ALL 4 answers indicate a real vulnerability.**

**VULNERABILITY CATEGORIES:**

**1. Code Execution:**
- eval()/exec() with user input
- Unsafe deserialization (pickle.load, yaml.load)
- Template injection with user data
- Dynamic imports from untrusted sources

**2. Injection Attacks:**
- SQL injection via STRING CONCATENATION: ✅ spark.sql(f"SELECT * FROM {{user_var}}")
- SQL injection via API methods: ❌ df.write.saveAsTable(var)  # API validates, not vulnerable
- Command injection: os.system() or subprocess(shell=True) with user input
- Prompt injection: User input directly in LLM system prompts

**3. Authentication & Authorization:**
- Missing auth on PUBLIC endpoints (not platform-authenticated operations)
- Hardcoded credentials IN CODE (not config file references)
- Privilege escalation in business logic

**4. Data Exposure:**
- Hardcoded secrets: API keys, passwords IN code
- Logging sensitive data without sanitization
- Disabled SSL verification (requests(verify=False))

**EXAMPLES - What to FLAG vs. IGNORE:**

❌ DON'T FLAG (False Positives):
```python
# Config dict in code (not user input)
config = {{"table": "catalog.schema.table"}}
df.write.saveAsTable(config["table"])  # API validates

# Platform-controlled paths
path = "/Volumes/catalog/schema/volume/data"  # Access controlled

# Framework auth (Databricks workspace auth)
# No need for manual auth checks in notebooks
```

✅ DO FLAG (Real Issues):
```python
# User input in SQL string
table = dbutils.widgets.get("table_name")
spark.sql(f"SELECT * FROM {{table}}")  # SQL INJECTION!

# User input in shell
cmd = request.args.get("cmd")
os.system(cmd)  # COMMAND INJECTION!

# Hardcoded secret
api_key = "sk_live_abc123"  # SECRET IN CODE!
```

**OUTPUT FORMAT:**
For each REAL vulnerability:

VULNERABILITY: <specific title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
CONFIDENCE: <HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <Q1-Q4 analysis + exploitation path>
RECOMMENDATION: <concrete fix>
---

**Only include HIGH or MEDIUM confidence findings.**

If NO real vulnerabilities found, respond: "NO_SECURITY_ISSUES_FOUND"

Code to review:
```
{code}
```

Your security analysis:"""

# Prompt for files WITH findings - look for ADDITIONAL issues only
ENRICHMENT_PROMPT = """You are a security expert reviewing code for REAL, EXPLOITABLE vulnerabilities.

{platform_context}

Static analysis tools already found these issues:
{existing_findings}

**YOUR MISSION:** Find ADDITIONAL security issues. DO NOT repeat the issues above.

**CRITICAL: Avoid False Positives**
Before flagging an issue, answer these 4 questions:

**Q1: Is this input ATTACKER-CONTROLLED?**
✅ YES: User widgets, HTTP params, CLI args, file uploads, untrusted env vars
❌ NO: Hardcoded config, constants, internal configuration

**Q2: Does the PLATFORM or CODE validate this input?**
✅ Validated: API methods, framework validators, allowlist checks
❌ Not validated: String concat, direct SQL/shell exec, no checks

**Q3: Can you write a REALISTIC exploit payload?**
✅ YES: Provide specific exploit example
❌ NO: If you can't demonstrate it, don't report it

**Q4: What's the ACTUAL impact?**
✅ Real: Concrete damage (data exfiltration, RCE, auth bypass)
❌ Theoretical: Vague "could maybe" scenarios

**Only report if ALL 4 answers indicate a real vulnerability.**

**FOCUS AREAS (beyond what static tools caught):**
- Indirect injection paths (multi-step, via config/templates)
- Complex data flow vulnerabilities
- Business logic flaws (TOCTOU, race conditions)
- Context-dependent security issues
- Obfuscated or encoded sensitive data

**EXAMPLES - What to FLAG vs. IGNORE:**

❌ DON'T FLAG:
- API methods with built-in validation (saveAsTable, boto3 SDK)
- Platform-provided auth (workspace, IAM, framework decorators)
- Hardcoded config values (not user-controllable)
- Access-controlled storage paths

✅ DO FLAG:
- User input in SQL strings: spark.sql(f"... {{user_var}}")
- Multi-step injection: config loaded → user input → execution
- Business logic bypasses in auth/authorization
- Obfuscated secrets: base64-encoded keys

**OUTPUT FORMAT:**
For each NEW vulnerability:

VULNERABILITY: <specific title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
CONFIDENCE: <HIGH|MEDIUM|LOW>
LINE: <line number>
DESCRIPTION: <Q1-Q4 analysis + exploitation path>
RECOMMENDATION: <concrete fix>
---

**Only include HIGH or MEDIUM confidence findings.**

If NO additional vulnerabilities beyond static tool findings, respond: "NO_ADDITIONAL_ISSUES_FOUND"

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
                    "CONFIDENCE",
                ]:
                    vuln_data[key] = value

            # Validate required fields
            if not all(k in vuln_data for k in ["VULNERABILITY", "SEVERITY", "LINE"]):
                continue

            # Filter LOW confidence findings
            confidence = vuln_data.get("CONFIDENCE", "MEDIUM").upper()
            if confidence == "LOW":
                continue  # Skip low confidence findings

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
    backend: Optional[DatabricksLLMBackend] = None,
    max_file_size: int = 60000,
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
        backend: Databricks LLM backend to use (defaults to env var)
        max_file_size: Max file size in bytes to review (default 60KB)
        existing_findings: Findings from OSS/rule-based tools (for enrichment mode)

    Returns:
        List of NEW findings from LLM review (non-overlapping with existing)
    """
    findings: List[Finding] = []

    # Get or create backend
    if backend is None:
        try:
            backend = create_llm_backend()
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
                    recommendation="Configure Databricks endpoint via SERVING_ENDPOINT environment variable.",
                    meta={"engine": "llm"},
                )
            )
            return findings

    # Check if backend is available
    if not backend.is_available():
        recommendation = "Missing SERVING_ENDPOINT environment variable."
        if backend.endpoint_name:
            recommendation = (
                f"Verify Databricks endpoint '{backend.endpoint_name}' is accessible."
            )

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

    # Batch extracted notebook cells together to reduce LLM calls
    batched_files = _batch_notebook_cells(scan_files, max_file_size)

    # Scan each batch
    print(f"\n🤖 LLM Review: Scanning {len(batched_files)} batch(es)...")
    for idx, batch in enumerate(batched_files, 1):
        try:
            # Handle single file vs batch
            if len(batch) == 1:
                # Single file
                file_path = batch[0]
                file_size = os.path.getsize(file_path)

                # Skip large files
                if file_size > max_file_size:
                    print(
                        f"  [{idx}/{len(batched_files)}] ⏭️  Skipping {relpath(file_path, root)} (too large: {file_size} bytes)"
                    )
                    continue

                # Read file
                code = read_text(file_path)
                if not code.strip():
                    print(
                        f"  [{idx}/{len(batched_files)}] ⏭️  Skipping {relpath(file_path, root)} (empty)"
                    )
                    continue

                # Detect platform context
                platform_context = _detect_platform_context(code)

                # Determine which prompt to use
                rel_path = relpath(file_path, root)
                file_existing_findings = findings_by_file.get(rel_path, [])

                if file_existing_findings:
                    # ENRICHMENT MODE
                    print(
                        f"  [{idx}/{len(batched_files)}] 🔍 Enriching {rel_path} ({len(file_existing_findings)} existing findings)..."
                    )
                    findings_text = "\n".join(
                        f"- {f.rule_id}: {f.message} (line {f.position.line})"
                        for f in file_existing_findings
                    )
                    prompt = ENRICHMENT_PROMPT.format(
                        platform_context=platform_context,
                        existing_findings=findings_text,
                        code=code,
                    )
                else:
                    # GAP-FILLING MODE
                    print(
                        f"  [{idx}/{len(batched_files)}] 🔍 Reviewing {rel_path} (gap-filling)..."
                    )
                    prompt = GAP_FILLING_PROMPT.format(
                        platform_context=platform_context, code=code
                    )

                # Get LLM analysis
                response = backend.generate(prompt, max_tokens=2000, temperature=0.1)

                # Parse findings for single file
                file_findings = parse_llm_findings(response, rel_path, code)
                findings.extend(file_findings)

                if file_findings:
                    print(f"      ✓ Found {len(file_findings)} additional issue(s)")
                else:
                    print(f"      ✓ No additional issues found")

            else:
                # Multiple files batched together (notebook cells)
                # Combine code from all cells
                combined_code = ""
                cell_map = []  # Track which lines belong to which file
                current_line = 1

                for cell_path in batch:
                    try:
                        cell_code = read_text(cell_path)
                        if cell_code.strip():
                            # Add separator
                            cell_name = os.path.basename(cell_path)
                            combined_code += f"\n# ===== {cell_name} =====\n"
                            current_line += 2

                            # Track line mapping
                            cell_start = current_line
                            cell_lines = cell_code.count("\n") + 1
                            cell_map.append((cell_path, cell_start, cell_lines))

                            combined_code += cell_code + "\n"
                            current_line += cell_lines + 1
                    except Exception:
                        pass

                if not combined_code.strip():
                    print(
                        f"  [{idx}/{len(batched_files)}] ⏭️  Skipping batch of {len(batch)} cells (all empty)"
                    )
                    continue

                # Detect platform context
                platform_context = _detect_platform_context(combined_code)

                # Review the combined code
                batch_name = f"{len(batch)} cells from {os.path.basename(batch[0]).split('__')[0]}"
                print(
                    f"  [{idx}/{len(batched_files)}] 🔍 Reviewing {batch_name} (batched, gap-filling)..."
                )
                prompt = GAP_FILLING_PROMPT.format(
                    platform_context=platform_context, code=combined_code
                )

                # Get LLM analysis
                response = backend.generate(prompt, max_tokens=2000, temperature=0.1)

                # Parse findings - they'll have line numbers relative to combined code
                # We need to map them back to individual cells
                batch_findings = parse_llm_findings(response, "batch", combined_code)

                # Map findings back to individual cells
                for finding in batch_findings:
                    finding_line = finding.position.line

                    # Find which cell this line belongs to
                    for cell_path, start_line, num_lines in cell_map:
                        if start_line <= finding_line < start_line + num_lines:
                            # Update finding to point to correct cell
                            finding.path = relpath(cell_path, root)
                            finding.position.line = finding_line - start_line + 1
                            findings.append(finding)
                            break

                if batch_findings:
                    print(f"      ✓ Found {len(batch_findings)} issue(s) across batch")
                else:
                    print(f"      ✓ No additional issues found")

        except Exception as e:
            # Add diagnostic for failed reviews
            batch_desc = batch[0] if len(batch) == 1 else f"batch of {len(batch)} files"
            findings.append(
                Finding(
                    rule_id="LLM_REVIEW_ERROR",
                    severity="low",
                    message=f"LLM review failed for {batch_desc}: {e}",
                    path=relpath(batch[0], root) if batch else "unknown",
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Check LLM backend configuration and file accessibility.",
                    meta={"engine": "llm"},
                )
            )

    return findings
