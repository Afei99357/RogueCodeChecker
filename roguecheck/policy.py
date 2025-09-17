import os
from typing import Any, Dict, Tuple

import yaml

DEFAULT_POLICY = {
    "secrets": {
        "allow_env": ["DATABRICKS_HOST", "UC_CATALOG"],
    },
    "network": {
        "allow_domains": ["localhost", "127.0.0.1", "login.microsoftonline.com"],
        "deny_plain_http": True,
    },
    "filesystems": {
        "allowed_sinks": ["/Volumes/", "/dbfs/tmp/", "abfss://trusted/"],
    },
    "licenses": {"deny": ["GPL-3.0", "AGPL-3.0"]},
    "python": {
        "forbid_calls": [
            "builtins.eval",
            "builtins.exec",
            "subprocess.Popen",
            "pickle.load",
            "yaml.load",
        ],
        "sql_concat_blocklist": True,
    },
}

DEFAULT_ALLOWLISTS = {
    "domains": ["*.corp.example.com", "login.microsoftonline.com"],
    "paths": ["/Volumes/proj/"],
}


class Policy:
    def __init__(self, policy: Dict[str, Any], allowlists: Dict[str, Any]):
        self.policy = policy
        self.allowlists = allowlists

    @staticmethod
    def load(
        policy_path: str = "policy.yaml", allowlists_path: str = "allowlists.yaml"
    ) -> "Policy":
        def load_yaml(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or default
            return default

        return Policy(
            load_yaml(policy_path, DEFAULT_POLICY),
            load_yaml(allowlists_path, DEFAULT_ALLOWLISTS),
        )

    def get(self, *keys: str, default=None):
        cur = self.policy
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    def allow_domains(self) -> Tuple[str, ...]:
        return tuple(self.policy.get("network", {}).get("allow_domains", []))

    def deny_plain_http(self) -> bool:
        return bool(self.policy.get("network", {}).get("deny_plain_http", False))
