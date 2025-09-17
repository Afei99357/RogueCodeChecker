# RogueCheck Test Samples

This directory contains test files to demonstrate RogueCheck's detection capabilities.

## Test Files

### 🔴 **Dangerous Files (Should trigger warnings)**

1. **`dangerous_python.py`** - Comprehensive Python security issues
   - Expected findings: PY001, PY003, PY004, PY005, PY010, PY011, PY012, PY020, PY030, PY031, PY040
   - Demonstrates: eval/exec, unsafe deserialization, shell injection, HTTP issues, secret exposure, SQL injection

2. **`dangerous_sql.sql`** - SQL security anti-patterns
   - Expected findings: SQL001, SQL010, SQL020
   - Demonstrates: Broad permissions, destructive operations, DELETE without WHERE

3. **`dangerous_bash.sh`** - Bash script security issues
   - Expected findings: SH001, SH002, SH010, SH020, SH030
   - Demonstrates: Plain HTTP, non-allowlisted domains, rm -rf, chmod 777, sudo usage

4. **`databricks_udf.py`** - Databricks-specific issues
   - Expected findings: DBX001_UDF_IO
   - Demonstrates: File/network I/O inside UDFs (performance killer)

5. **`ai_generated_malware.py`** - Simulated malicious AI code
   - Expected findings: Multiple high-severity issues across all categories
   - Demonstrates: Complete attack chain with persistence, exfiltration, lateral movement

### 🟡 **Mixed Files (Partial warnings)**

6. **`mixed_with_ignores.py`** - Demonstrates ignore comment functionality
   - Shows how to suppress specific findings with `# roguecheck: ignore RULE_ID`
   - Some issues ignored, others still reported

### 🟢 **Safe Files (Should NOT trigger warnings)**

7. **`safe_python.py`** - Secure coding practices
   - No expected findings
   - Demonstrates: Safe alternatives to dangerous patterns

## Usage Examples

### Scan all test files:
```bash
uv run python -m roguecheck scan --path test_samples --format md
```

### Scan specific dangerous file:
```bash
uv run python -m roguecheck scan --path test_samples/ai_generated_malware.py --format md
```

### Compare safe vs dangerous:
```bash
# This should show no issues
uv run python -m roguecheck scan --path test_samples/safe_python.py --format md

# This should show many issues
uv run python -m roguecheck scan --path test_samples/dangerous_python.py --format md
```

### Test ignore functionality:
```bash
# Shows how ignore comments work
uv run python -m roguecheck scan --path test_samples/mixed_with_ignores.py --format md
```

### Generate reports:
```bash
# JSON report for tooling
uv run python -m roguecheck scan --path test_samples --format json --out security-report.json

# SARIF for GitHub Security tab
uv run python -m roguecheck scan --path test_samples --format sarif --out security-report.sarif
```

## Expected Results Summary

| File | Expected Findings | Severity Levels |
|------|------------------|-----------------|
| `dangerous_python.py` | 10+ issues | High, Critical |
| `dangerous_sql.sql` | 5+ issues | Medium, High |
| `dangerous_bash.sh` | 8+ issues | Low, Medium, High |
| `databricks_udf.py` | 2+ issues | High |
| `ai_generated_malware.py` | 15+ issues | High, Critical |
| `mixed_with_ignores.py` | 3-4 issues | High (some suppressed) |
| `safe_python.py` | 0 issues | None |

Use these files to test RogueCheck's capabilities and understand what types of AI-generated code patterns it can detect!
