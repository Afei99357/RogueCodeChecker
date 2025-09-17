#!/usr/bin/env python3
"""
Safe Python code that should NOT trigger any RogueCheck warnings
This demonstrates proper security practices
"""
import json
import subprocess
from typing import Any, Dict

import requests
import yaml


def safe_ai_generated_code():
    # Safe: Using JSON instead of pickle for data serialization
    with open("data.json", "r") as f:
        safe_data = json.load(f)

    # Safe: subprocess without shell=True and explicit arguments
    result = subprocess.run(["ls", "-la", "/tmp"], capture_output=True, text=True)

    # Safe: HTTPS request to allowlisted domain with SSL verification
    response = requests.get("https://login.microsoftonline.com/api/health")

    # Safe: Using yaml.safe_load instead of yaml.load
    with open("config.yml", "r") as f:
        config = yaml.safe_load(f)

    # Safe: Parameterized SQL query (not string concatenation)
    user_id = safe_data.get("user_id", 1)
    spark.sql("SELECT * FROM users WHERE id = ?", [user_id])

    # Safe: Using secrets properly without printing
    api_key = dbutils.secrets.get("production-api-key")
    headers = {"Authorization": f"Bearer {api_key}"}  # Used, not printed

    # Safe: Environment variables for non-sensitive config
    os.environ["LOG_LEVEL"] = "INFO"
    os.environ["ENVIRONMENT"] = "production"

    return {"status": "success", "records": len(safe_data)}


def process_user_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Process user data safely"""
    # Safe: Input validation
    if not isinstance(data, dict):
        raise ValueError("Invalid input data")

    # Safe: Using allowlisted domains only
    profile_response = requests.get(
        "https://login.microsoftonline.com/api/profile",
        headers={"User-ID": str(data.get("id", ""))},
    )

    return {"user_id": data.get("id"), "profile_status": profile_response.status_code}


if __name__ == "__main__":
    safe_ai_generated_code()
