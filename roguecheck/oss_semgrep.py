import json
import os
import shutil
import subprocess
from typing import List, Optional

from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet

_ORIG_CWD = os.getcwd()


def _which_abs(name: str) -> Optional[str]:
    p = shutil.which(name)
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.abspath(os.path.join(_ORIG_CWD, p))


def _map_severity(level: str) -> str:
    lvl = (level or "").strip().upper()
    if lvl in {"CRITICAL"}:
        return "critical"
    if lvl in {"ERROR", "HIGH"}:
        return "high"
    if lvl in {"WARNING", "MEDIUM"}:
        return "medium"
    return "low"


def scan_with_semgrep(
    root: str,
    policy: Policy,
    semgrep_config: str = "auto",
    files: Optional[List[str]] = None,
) -> List[Finding]:
    """
    Run Semgrep against the given root and convert results to RogueCheck findings.

    Notes:
      - Requires `semgrep` to be installed and available on PATH.
      - The default `--config=auto` may fetch rules from the network depending on environment.
    """
    findings: List[Finding] = []
    semgrep_bin = _which_abs("semgrep")
    if semgrep_bin is None:
        # Soft failure: return an informative low-sev finding
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_MISSING_SEMGREP",
                severity="low",
                message="Semgrep is not installed or not in PATH.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Install semgrep (pipx install semgrep) or switch --engine=builtin.",
            )
        )
        return findings

    cmd = [semgrep_bin, "--json", "--quiet"]
    # Support multiple configs separated by comma
    configs = [c.strip() for c in str(semgrep_config).split(",") if c.strip()]
    if not configs:
        configs = ["auto"]

    print(f"\n🔍 Semgrep: Scanning with configs: {', '.join(configs)}")

    for cfg in configs:
        # If cfg is a local path (dir or file), resolve to absolute from original CWD
        cfg_path = cfg
        try:
            if os.path.isdir(os.path.join(_ORIG_CWD, cfg)) or os.path.isfile(
                os.path.join(_ORIG_CWD, cfg)
            ):
                cfg_path = os.path.abspath(os.path.join(_ORIG_CWD, cfg))
        except Exception:
            cfg_path = cfg
        cmd.append(f"--config={cfg_path}")
    if files:
        # Normalize to absolute paths to avoid cwd issues
        # Files may already be absolute (from oss_runner.py), so don't double-join
        abs_files = [
            f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f))
            for f in files
        ]
        cmd.extend(abs_files)
    else:
        cmd.append(os.path.abspath(root))
    # Ensure Semgrep has a writable home to avoid permission issues in CI/containers
    env = os.environ.copy()
    try:
        # Prefer a dedicated semgrep home inside repo if not set
        if not env.get("SEMGREP_USER_HOME"):
            local_home = os.path.abspath(os.path.join(_ORIG_CWD, ".semgrephome"))
            os.makedirs(local_home, exist_ok=True)
            env["SEMGREP_USER_HOME"] = local_home
        # Some environments require HOME to be writable as well
        if not env.get("HOME"):
            home_tmp = os.path.abspath(os.path.join(_ORIG_CWD, ".home_tmp"))
            os.makedirs(home_tmp, exist_ok=True)
            env["HOME"] = home_tmp
    except Exception:
        pass

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            env=env,
        )
    except Exception as e:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_ERROR",
                severity="low",
                message=f"Failed to run Semgrep: {e}",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Verify Semgrep installation and configuration.",
            )
        )
        return findings

    # We'll parse output regardless; treat RC 7 (no targets) as non-fatal if no results

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        findings.append(
            Finding(
                rule_id="OSS_ENGINE_SEMGREP_PARSE_ERROR",
                severity="low",
                message="Failed to parse Semgrep JSON output.",
                path=relpath(root, os.getcwd()),
                position=Position(1, 1),
                snippet=None,
                recommendation="Re-run with a simpler config or update Semgrep.",
            )
        )
        return findings

    # If Semgrep returned 7 (no targets) and no results, try a helpful fallback and surface an advisory
    if proc.returncode == 7 and not data.get("results"):
        fallback_cmd = [semgrep_bin, "--json", "--quiet", "--config=auto"]
        if files:
            abs_files = [
                f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f))
                for f in files
            ]
            fallback_cmd.extend(abs_files)
        else:
            fallback_cmd.append(os.path.abspath(root))
        try:
            fb = subprocess.run(
                fallback_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180,
                env=env,
            )
            if fb.returncode in (0, 1):
                try:
                    data = json.loads(fb.stdout or "{}")
                except json.JSONDecodeError:
                    data = {"results": []}
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_SEMGREP_FALLBACK",
                        severity="low",
                        message=(
                            "Semgrep reported no targets or packs. Used --config=auto fallback; coverage may be reduced."
                        ),
                        path=relpath(root, os.getcwd()),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation=(
                            "Ensure network access to semgrep.dev or provide local packs via --semgrep-config."
                        ),
                    )
                )
                proc = fb
            else:
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_SEMGREP_NO_TARGETS",
                        severity="low",
                        message="Semgrep returned no targets and no results.",
                        path=relpath(root, os.getcwd()),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation=(
                            "Check included packs and file types. Add packs or pass explicit files."
                        ),
                    )
                )
        except Exception:
            findings.append(
                Finding(
                    rule_id="OSS_ENGINE_SEMGREP_NO_TARGETS",
                    severity="low",
                    message="Semgrep returned no targets and no results.",
                    path=relpath(root, os.getcwd()),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation=(
                        "Check included packs and file types. Add packs or pass explicit files."
                    ),
                )
            )
        if not data.get("results"):
            return findings

    if proc.returncode not in (0, 1, 7):
        # Attempt a fallback with --config=auto which may work better offline
        fallback_cmd = [semgrep_bin, "--json", "--quiet", "--config=auto"]
        if files:
            abs_files = [
                f if os.path.isabs(f) else os.path.abspath(os.path.join(root, f))
                for f in files
            ]
            fallback_cmd.extend(abs_files)
        else:
            fallback_cmd.append(os.path.abspath(root))
        try:
            fb = subprocess.run(
                fallback_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180,
                env=env,
            )
            if fb.returncode in (0, 1, 7):
                try:
                    data = json.loads(fb.stdout or "{}")
                except json.JSONDecodeError:
                    data = {"results": []}
                # Surface an advisory about the fallback
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_SEMGREP_FALLBACK",
                        severity="low",
                        message=(
                            f"Semgrep packs failed (rc={proc.returncode}). Used --config=auto fallback;"
                            " coverage may be reduced."
                        ),
                        path=relpath(root, os.getcwd()),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation="Ensure network access to semgrep.dev or provide local packs via --semgrep-config.",
                    )
                )
                # Replace proc/data with fallback for downstream parsing
                proc = fb
                try:
                    parsed = json.loads(proc.stdout or "{}")
                except json.JSONDecodeError:
                    parsed = {"results": []}
                data = parsed
            else:
                findings.append(
                    Finding(
                        rule_id="OSS_ENGINE_SEMGREP_NONZERO",
                        severity="low",
                        message=f"Semgrep exited with code {proc.returncode}: {proc.stderr.strip()[:200]}",
                        path=relpath(root, os.getcwd()),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation="Check Semgrep config or pass --semgrep-config pointing to valid rules.",
                    )
                )
        except Exception:
            findings.append(
                Finding(
                    rule_id="OSS_ENGINE_SEMGREP_NONZERO",
                    severity="low",
                    message=f"Semgrep exited with code {proc.returncode}: {proc.stderr.strip()[:200]}",
                    path=relpath(root, os.getcwd()),
                    position=Position(1, 1),
                    snippet=None,
                    recommendation="Check Semgrep config or pass --semgrep-config pointing to valid rules.",
                )
            )

    for r in data.get("results", []) or []:
        path = r.get("path") or root
        check_id = r.get("check_id") or r.get("rule_id") or "SEMGREP_RULE"
        extra = r.get("extra", {}) or {}
        sev = _map_severity(extra.get("severity", ""))
        msg = extra.get("message", "Semgrep finding")
        start = r.get("start", {}) or {}
        line = int(start.get("line", 1) or 1)

        snippet: Optional[str] = None
        try:
            full_path = path if os.path.isabs(path) else os.path.join(root, path)
            text = read_text(full_path)
            snippet = safe_snippet(text, line)
        except Exception:
            snippet = None

        findings.append(
            Finding(
                rule_id=f"SEMGREP:{check_id}",
                severity=sev,  # type: ignore[arg-type]
                message=msg,
                path=relpath(path, root),
                position=Position(line=line, column=int(start.get("col", 1) or 1)),
                snippet=snippet,
                recommendation=None,
                meta={"engine": "semgrep"},
            )
        )

    return findings
