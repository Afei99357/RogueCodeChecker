#!/usr/bin/env python3
"""
Verify that all security scanning tools are installed and working.
Can be run in Databricks notebook or locally.
"""

import shutil
import subprocess
import sys


def check_tool(name: str, version_cmd: list = None) -> tuple[bool, str]:
    """Check if a tool is installed and get its version."""
    # Check if tool exists in PATH
    path = shutil.which(name)
    if not path:
        return False, "NOT FOUND"

    # Try to get version
    if version_cmd is None:
        version_cmd = [name, "--version"]

    try:
        result = subprocess.run(
            version_cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = (result.stdout or result.stderr).strip().split("\n")[0]
        return True, f"{path} - {version}"
    except Exception as e:
        return True, f"{path} - (version unavailable: {e})"


def main():
    """Check all required security tools."""
    print("=" * 60)
    print("RogueCodeChecker Tool Verification")
    print("=" * 60)
    print()

    tools = {
        "semgrep": ["semgrep", "--version"],
        "detect-secrets": ["detect-secrets", "--version"],
        "pip-audit": ["pip-audit", "--version"],
        "sqlfluff": ["sqlfluff", "--version"],
        "shellcheck": ["shellcheck", "--version"],
        "gitleaks": ["gitleaks", "version"],
    }

    results = {}
    for tool_name, version_cmd in tools.items():
        found, info = check_tool(tool_name, version_cmd)
        results[tool_name] = found
        status = "✓" if found else "✗"
        print(f"{status} {tool_name:20s} {info}")

    print()
    print("=" * 60)

    installed = sum(results.values())
    total = len(results)

    if installed == total:
        print(f"✓ SUCCESS: All {total} tools are installed!")
        return 0
    else:
        print(f"⚠ WARNING: {installed}/{total} tools installed")
        print()
        print("Missing tools:")
        for tool, found in results.items():
            if not found:
                print(f"  - {tool}")
        print()
        print("See scripts/DATABRICKS_INIT.md for installation instructions")
        return 1


if __name__ == "__main__":
    sys.exit(main())
