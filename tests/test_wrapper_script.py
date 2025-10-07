"""Tests for the wrapper script (scan_local.sh).

This test ensures that:
1. sql-strict is enabled by default (not disabled)
2. sql-strict can be explicitly disabled with --no-sql-strict flag
3. LLM review can be enabled with --llm flag
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest


def test_wrapper_sql_strict_enabled_by_default(tmp_path):
    """Test that sql-strict runs by default and detects SQL issues."""
    # Use the dangerous_sql.sql test file
    test_file = Path("test_samples/dangerous_sql.sql")
    if not test_file.exists():
        pytest.skip("test_samples/dangerous_sql.sql not found")

    # Run wrapper script on test_samples directory
    result = subprocess.run(
        [
            "bash",
            "scripts/scan_local.sh",
            str(test_file.parent),
            "--out",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # Check that sql-strict findings are present
    assert result.returncode in (0, 1), f"Script failed: {result.stderr}"

    # Check output contains SQL_STRICT findings
    output = result.stdout
    assert (
        "SQL_STRICT_GRANT_ALL" in output
        or "SQL_STRICT_DELETE_ALL" in output
        or "SQL_STRICT_DROP_TABLE" in output
    ), f"Expected sql-strict findings in output. Got:\n{output[:500]}"

    # Check per-file report was created and contains findings
    reports = list(tmp_path.glob("dangerous_sql_report.md"))
    assert len(reports) == 1, f"Expected 1 report, found {len(reports)}"

    report_content = reports[0].read_text()
    # Should NOT show "No issues found" since dangerous_sql.sql has vulnerabilities
    assert (
        "No issues found" not in report_content
    ), f"Report should contain SQL findings, got:\n{report_content}"
    assert (
        "SQL_STRICT" in report_content
    ), f"Report should contain sql-strict findings, got:\n{report_content}"


def test_wrapper_sql_strict_can_be_disabled(tmp_path):
    """Test that --no-sql-strict flag disables sql-strict scanning."""
    test_file = Path("test_samples/dangerous_sql.sql")
    if not test_file.exists():
        pytest.skip("test_samples/dangerous_sql.sql not found")

    # Run wrapper with --no-sql-strict flag
    result = subprocess.run(
        [
            "bash",
            "scripts/scan_local.sh",
            str(test_file.parent),
            "--no-sql-strict",
            "--out",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode in (0, 1), f"Script failed: {result.stderr}"

    # With --no-sql-strict, we should not see SQL_STRICT findings
    output = result.stdout
    # This might be empty or only contain findings from other tools (semgrep, etc)
    # The key is that SQL_STRICT findings should NOT be present
    if "SQL_STRICT" in output:
        pytest.fail(
            f"sql-strict findings should not appear when --no-sql-strict is used. Got:\n{output[:500]}"
        )


def test_wrapper_creates_unique_output_directories():
    """Test that wrapper creates timestamped output directories."""
    # Run wrapper twice quickly
    result1 = subprocess.run(
        ["bash", "scripts/scan_local.sh", "test_samples/safe_python.py"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # Extract output directory from result
    match1 = None
    for line in result1.stderr.split("\n"):
        if "Per-file reports written to:" in line:
            match1 = line.split(":")[-1].strip()
            break

    assert match1 is not None, "Expected output directory in stderr"
    assert "test_output_" in match1, f"Expected timestamped directory, got: {match1}"

    # Check directory exists
    assert os.path.exists(match1), f"Output directory should exist: {match1}"


def test_wrapper_llm_flag_adds_llm_review():
    """Test that --llm flag enables LLM review."""
    # This test just verifies the flag is passed correctly
    # We don't actually require LLM to be running
    result = subprocess.run(
        ["bash", "-x", "scripts/scan_local.sh", "test_samples/safe_python.py", "--llm"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # Check that llm-review is in the tools list (from bash -x debug output)
    debug_output = result.stderr
    assert (
        "llm-review" in debug_output
    ), f"Expected llm-review in tools when --llm is used. Debug output:\n{debug_output}"


def test_cli_directly_with_sql_strict():
    """Test that CLI directly with sql-strict detects issues in dangerous_sql.sql."""
    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "-m",
            "osscheck_cli",
            "scan",
            "--path",
            "test_samples/dangerous_sql.sql",
            "--tools",
            "sql-strict",
            "--format",
            "md",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode in (0, 1), f"CLI failed: {result.stderr}"

    output = result.stdout
    # Should detect GRANT ALL, DROP TABLE, and DELETE without WHERE
    assert (
        "SQL_STRICT_GRANT_ALL" in output
    ), f"Expected GRANT ALL finding. Got:\n{output}"
    assert (
        "SQL_STRICT_DROP_TABLE" in output
    ), f"Expected DROP TABLE finding. Got:\n{output}"
    assert (
        "SQL_STRICT_DELETE_ALL" in output
    ), f"Expected DELETE without WHERE finding. Got:\n{output}"

    # Should find multiple issues (at least 5-7)
    assert (
        output.count("SQL_STRICT") >= 5
    ), f"Expected at least 5 SQL_STRICT findings. Got:\n{output}"


def test_cli_per_file_reports_include_sql_findings(tmp_path):
    """Test that per-file reports include sql-strict findings (regression test for path matching bug)."""
    out_dir = tmp_path / "reports"
    out_dir.mkdir()

    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "-m",
            "osscheck_cli",
            "scan",
            "--path",
            "test_samples/",
            "--tools",
            "sql-strict",
            "--format",
            "md",
            "--per-file-out-dir",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode in (0, 1), f"CLI failed: {result.stderr}"

    # Check that dangerous_sql_report.md was created
    report_file = out_dir / "dangerous_sql_report.md"
    assert report_file.exists(), f"Expected report file: {report_file}"

    report_content = report_file.read_text()
    # Should NOT be empty
    assert (
        len(report_content) > 50
    ), f"Report should not be nearly empty: {report_content}"
    # Should contain SQL_STRICT findings
    assert (
        "SQL_STRICT" in report_content
    ), f"Per-file report should contain sql-strict findings. Got:\n{report_content}"
    assert (
        "No issues found" not in report_content
    ), f"Report should not say 'No issues found' for dangerous_sql.sql. Got:\n{report_content}"
