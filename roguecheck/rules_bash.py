import re
from typing import Iterable, List

from .models import Finding, Position
from .utils import extract_domain, glob_match_any, is_plain_http

CURL_WGET_RE = re.compile(r"\b(curl|wget)\s+([^\n]+)")
URL_RE = re.compile(r"https?://[^\s'\"]+")
RM_RF_RE = re.compile(r"\brm\s+-rf\s+(/|\$|~)", re.IGNORECASE)
CHMOD_777_RE = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
SUDO_RE = re.compile(r"\bsudo\s+", re.IGNORECASE)


def _line_from_index(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def run_bash_rules(path: str, text: str, policy) -> Iterable[Finding]:
    findings: List[Finding] = []
    for m in CURL_WGET_RE.finditer(text):
        cmd = m.group(0)
        urlm = URL_RE.search(cmd)
        if not urlm:
            continue
        url = urlm.group(0)
        if policy.deny_plain_http() and is_plain_http(url):
            findings.append(
                Finding(
                    rule_id="INSECURE_HTTP_DOWNLOAD",
                    severity="medium",
                    message=f"Plain HTTP in shell: {url}",
                    path=path,
                    position=Position(_line_from_index(text, m.start()), 1),
                    recommendation="Use HTTPS or approved proxy.",
                )
            )
        dom = extract_domain(url)
        if not glob_match_any(dom, policy.allow_domains()):
            findings.append(
                Finding(
                    rule_id="UNTRUSTED_DOWNLOAD_SOURCE",
                    severity="high",
                    message=f"Outbound to non-allowlisted domain: {dom}",
                    path=path,
                    position=Position(_line_from_index(text, m.start()), 1),
                    recommendation="Add to allowlist or remove call.",
                )
            )
    for m in RM_RF_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="DANGEROUS_RECURSIVE_DELETE",
                severity="high",
                message="Potentially destructive rm -rf.",
                path=path,
                position=Position(_line_from_index(text, m.start()), 1),
                recommendation="Avoid recursive delete at root/home; restrict path or add safety checks.",
            )
        )
    for m in CHMOD_777_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="OVERLY_PERMISSIVE_FILE_ACCESS",
                severity="medium",
                message="chmod 777 grants world-writable permissions.",
                path=path,
                position=Position(_line_from_index(text, m.start()), 1),
                recommendation="Use least-privilege modes (e.g., 750/640).",
            )
        )
    for m in SUDO_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="ELEVATED_PRIVILEGES_DETECTED",
                severity="low",
                message="Use of sudo detected (review necessity in CI/runtime).",
                path=path,
                position=Position(_line_from_index(text, m.start()), 1),
                recommendation="Avoid sudo in automation where possible.",
            )
        )
    return findings


def get_rules():
    return [run_bash_rules]
