import os
import re
from typing import Tuple
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+(:\d+)?$")


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def relpath(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def extract_domain(url: str) -> str:
    try:
        p = urlparse(url)
        host = p.hostname or url.split("/", 1)[0]
        return host
    except Exception:
        return url


def is_plain_http(url: str) -> bool:
    return url.strip().lower().startswith("http://")


def glob_match_any(s: str, patterns: Tuple[str, ...]) -> bool:
    # very small glob support for *.corp.example.com
    for p in patterns:
        if p.startswith("*.") and s.endswith(p[1:]):
            return True
        if s == p:
            return True
    return False


def safe_snippet(text: str, line: int, context: int = 2) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    i = max(0, min(line - 1, len(lines) - 1))
    start = max(0, i - context)
    end = min(len(lines), i + context + 1)
    numbered = []
    for idx in range(start, end):
        prefix = "-->" if idx == i else "   "
        numbered.append(f"{prefix} {idx+1:5d}: {lines[idx]}")
    return "\n".join(numbered)
