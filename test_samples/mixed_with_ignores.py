#!/usr/bin/env python3
"""
Python file demonstrating ignore comment functionality
Some issues are suppressed, others are not
"""
import os
import pickle
import subprocess


def test_ignore_comments():
    # This will be detected - no ignore comment
    eval("1 + 1")

    # This will be ignored - specific rule ignored
    pickle.load(open("data.pkl", "rb"))  # roguecheck: ignore PY003_UNSAFE_DESERIALIZE

    # This will be ignored - all rules ignored for this line
    os.system("rm -rf /dangerous/path")  # roguecheck: ignore (all)

    # This will be detected - wrong rule ID in ignore comment
    subprocess.run(
        "curl http://evil.com", shell=True
    )  # roguecheck: ignore WRONG_RULE_ID

    # This will be detected - no ignore comment
    exec("import sys; sys.exit()")

    # This will be ignored - correct rule ID
    os.putenv("API_KEY", "secret-123")  # roguecheck: ignore PY040_HARDCODED_SECRET


def legitimate_but_flagged_code():
    """Sometimes you need to do dangerous things for legitimate reasons"""

    # Legacy system integration - needed for compatibility
    legacy_data = pickle.loads(
        trusted_legacy_format
    )  # roguecheck: ignore PY003_UNSAFE_DESERIALIZE

    # Administrative script - needs elevated access
    subprocess.run(
        "systemctl restart service", shell=True
    )  # roguecheck: ignore PY005_SUBPROCESS_SHELL_TRUE

    # Development/testing - controlled environment
    test_command = "echo 'test complete'"
    os.system(test_command)  # roguecheck: ignore PY004_OS_SYSTEM

    return "completed"
