import importlib
import json
import os
import pkgutil
from typing import Callable, Dict, Iterable, List

from .models import Finding, Position
from .policy import Policy
from .utils import read_text, relpath, safe_snippet

RuleFn = Callable[[str, str, Policy], Iterable[Finding]]

EXT_TO_RULESET = {
    ".py": ["roguecheck.rules_python", "roguecheck.rules_dbx"],
    ".sql": ["roguecheck.rules_sql"],
    ".sh": ["roguecheck.rules_bash"],
}

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Scanner:
    def __init__(self, root: str, policy: Policy):
        self.root = os.path.abspath(root)
        self.policy = policy
        self.rules: Dict[str, List[RuleFn]] = {}
        self._load_builtin_rules()
        self._load_plugins()
        self.max_bytes = int(
            self.policy.get("scanner", "max_file_bytes", default=2_000_000) or 2_000_000
        )
        self.exclude_dirs = set(
            self.policy.get(
                "scanner",
                "exclude_dirs",
                default=[
                    ".git",
                    ".venv",
                    "__pycache__",
                    ".idea",
                    ".eggs",
                    "dist",
                    "build",
                ],
            )
        )

    def _load_builtin_rules(self):
        for ext, mods in EXT_TO_RULESET.items():
            fns: List[RuleFn] = []
            for m in mods:
                mod = importlib.import_module(m)
                fns.extend(mod.get_rules())
            self.rules[ext] = fns

    def _load_plugins(self):
        # optional: roguecheck/plugins/*.py with get_rules()
        plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
        if not os.path.isdir(plugins_dir):
            return
        for _, name, ispkg in pkgutil.iter_modules([plugins_dir]):
            if ispkg:
                continue
            mod = importlib.import_module(f"roguecheck.plugins.{name}")
            if hasattr(mod, "get_rules"):
                for ext in self.rules:
                    # plugins can choose which ext to apply by filtering path in rule
                    self.rules[ext].extend(mod.get_rules())

    def discover(self) -> List[str]:
        paths = []
        for dirpath, _, filenames in os.walk(self.root):
            if any(ex in dirpath for ex in self.exclude_dirs):
                continue
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in self.rules:
                    paths.append(os.path.join(dirpath, fn))
        return paths

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in self.discover():
            ext = os.path.splitext(path)[1].lower()
            text = read_text(path)
            if len(text.encode("utf-8", errors="ignore")) > self.max_bytes:
                findings.append(
                    Finding(
                        rule_id="SCANNER_FILE_TOO_LARGE",
                        severity="low",
                        message="File skipped due to size limit.",
                        path=relpath(path, self.root),
                        position=Position(1, 1),
                        snippet=None,
                        recommendation="Increase scanner.max_file_bytes in policy if needed.",
                    )
                )
                continue
            for rule in self.rules.get(ext, []):
                try:
                    for f in rule(path, text, self.policy):
                        # attach snippet lazily
                        if f.snippet is None:
                            f.snippet = safe_snippet(text, f.position.line)
                        f.path = relpath(f.path, self.root)
                        findings.append(f)
                except Exception as e:
                    findings.append(
                        Finding(
                            rule_id="SCANNER_RULE_ERROR",
                            severity="low",
                            message=f"Rule {getattr(rule, '__name__', 'unknown')} crashed: {e}",
                            path=relpath(path, self.root),
                            position=Position(1, 1),
                            snippet=None,
                            recommendation="Inspect rule and input file.",
                        )
                    )
        return self._apply_ignores(findings)

    @staticmethod
    def to_markdown(findings: List[Finding]) -> str:
        if not findings:
            return "✅ No issues found."
        lines = ["# RogueCheck Report", ""]
        for f in findings:
            lines.append(
                f"## [{f.severity.upper()}] {f.rule_id} — {f.path}:{f.position.line}"
            )
            lines.append(f"{f.message}\n")
            if f.snippet:
                lines.append("```\n" + f.snippet + "\n```")
            if f.recommendation:
                lines.append(f"**Fix:** {f.recommendation}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def to_json(findings: List[Finding]) -> str:
        return json.dumps(
            [f.__dict__ for f in findings], default=lambda o: o.__dict__, indent=2
        )

    @staticmethod
    def to_sarif(findings: List[Finding]) -> str:
        # minimal SARIF 2.1.0
        rules = {}
        results = []
        for f in findings:
            rules.setdefault(
                f.rule_id,
                {"id": f.rule_id, "shortDescription": {"text": f.message[:80]}},
            )
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": {
                        "low": "note",
                        "medium": "warning",
                        "high": "error",
                        "critical": "error",
                    }[f.severity],
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.path},
                                "region": {"startLine": f.position.line},
                            }
                        }
                    ],
                }
            )
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "RogueCheck", "rules": list(rules.values())}
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _apply_ignores(self, findings: List[Finding]) -> List[Finding]:
        # Support inline:  # roguecheck: ignore RULE_ID   or   # roguecheck: ignore (all)
        by_file: Dict[str, List[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.path, []).append(f)
        filtered: List[Finding] = []
        cache: Dict[str, List[str]] = {}
        for path, fs in by_file.items():
            full = os.path.join(self.root, path)
            try:
                text = read_text(full)
            except Exception:
                filtered.extend(fs)
                continue
            lines = text.splitlines()
            for f in fs:
                ln = max(1, f.position.line)
                line = lines[ln - 1] if ln - 1 < len(lines) else ""
                if "roguecheck: ignore" in line:
                    token = line.split("roguecheck: ignore", 1)[1].strip()
                    if not token or token.lower().startswith("(all"):
                        continue  # drop finding
                    if f.rule_id in token:
                        continue  # drop finding
                filtered.append(f)
        return filtered
