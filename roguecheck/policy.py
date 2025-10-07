"""Simplified policy configuration for scanner."""

from typing import Any, Dict

DEFAULT_POLICY = {
    "scanner": {
        "exclude_dirs": [
            ".git",
            ".venv",
            "__pycache__",
            ".idea",
            ".eggs",
            "dist",
            "build",
            "node_modules",
        ],
        "max_file_bytes": 2000000,
    },
}


class Policy:
    """Simple policy configuration for scanner settings."""

    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy

    @staticmethod
    def load() -> "Policy":
        """Load default policy configuration."""
        return Policy(DEFAULT_POLICY)

    def get(self, *keys: str, default=None):
        """Get nested policy value by key path."""
        cur = self.policy
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur
