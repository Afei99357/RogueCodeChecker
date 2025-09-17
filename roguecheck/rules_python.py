import ast
import re
from typing import Iterable, List

from .models import Finding, Position
from .utils import extract_domain, glob_match_any, is_plain_http

REQ_CALL_RE = re.compile(
    r"^(requests\.(get|post|put|patch|delete)|urllib3?|http\.client)"
)


class PyRuleVisitor(ast.NodeVisitor):
    def __init__(self, path: str, text: str, policy):
        self.path = path
        self.text = text
        self.policy = policy
        self.findings: List[Finding] = []
        self.assignments = {}  # name -> node

    def add(self, rule_id: str, severity: str, node: ast.AST, message: str, rec: str):
        line = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                path=self.path,
                position=Position(line=line, column=1),
                snippet=None,
                recommendation=rec,
            )
        )

    def visit_Assign(self, node: ast.Assign):
        # track simple assignments for secret->print pattern
        if isinstance(node.value, ast.Call) and isinstance(
            node.value.func, ast.Attribute
        ):
            if (
                getattr(node.value.func.value, "id", None) == "dbutils"
                and node.value.func.attr == "secrets"
            ):
                # dbutils.secrets.get(...) assigned to var
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.assignments[t.id] = node
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fqname = self._fqname(node.func)
        # 1) Forbid dangerous calls
        forbidden = set(self.policy.get("python", "forbid_calls", default=[]))
        if fqname in forbidden:
            self.add(
                "DANGEROUS_EVAL_EXEC",
                "high",
                node,
                f"Dangerous code execution: {fqname}",
                "Remove/replace this API. If using yaml.load, switch to yaml.safe_load; avoid eval/exec.",
            )

        # 2) yaml.load without SafeLoader
        if fqname in ("yaml.load", "yaml.unsafe_load"):
            has_loader = any(
                (isinstance(k, ast.keyword) and k.arg and "Loader" in k.arg)
                for k in node.keywords
            )
            if not has_loader:
                self.add(
                    "UNSAFE_YAML_LOAD",
                    "high",
                    node,
                    "yaml.load without SafeLoader is unsafe.",
                    "Use yaml.safe_load or specify Loader=yaml.SafeLoader.",
                )

        # 2.1) Unsafe deserialization
        if fqname in (
            "pickle.loads",
            "pickle.load",
            "dill.loads",
            "dill.load",
            "marshal.loads",
            "joblib.load",
        ):
            self.add(
                "UNSAFE_DESERIALIZATION",
                "high",
                node,
                f"Unsafe deserialization via {fqname}.",
                "Avoid untrusted inputs; prefer safe formats (JSON/Parquet).",
            )

        # 2.2) Shell invocation and os.system
        if fqname == "os.system":
            self.add(
                "SHELL_COMMAND_INJECTION",
                "high",
                node,
                "os.system executes a shell command.",
                "Use subprocess with shell=False and explicit args.",
            )
        if fqname.startswith("subprocess."):
            for kw in node.keywords:
                if (
                    isinstance(kw, ast.keyword)
                    and kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self.add(
                        "SUBPROCESS_SHELL_INJECTION",
                        "high",
                        node,
                        "subprocess called with shell=True.",
                        "Set shell=False and pass a list of args.",
                    )

        # 3) requests/urllib/http with verify=False or non-allowlisted domains
        if isinstance(node.func, ast.Attribute):
            base = self._fqbase(node.func)
            if base and REQ_CALL_RE.match(base):
                url = self._first_arg_str(node)
                if url:
                    if self.policy.deny_plain_http() and is_plain_http(url):
                        self.add(
                            "INSECURE_HTTP_REQUEST",
                            "medium",
                            node,
                            f"Plain HTTP request: {url}",
                            "Switch to HTTPS or route through approved proxy.",
                        )
                    dom = extract_domain(url)
                    if not glob_match_any(dom, self.policy.allow_domains()):
                        self.add(
                            "UNTRUSTED_NETWORK_CALL",
                            "high",
                            node,
                            f"Outbound call to non-allowlisted domain: {dom}",
                            "Add domain to allowlist or remove the call.",
                        )
                # verify=False
                for kw in node.keywords:
                    if isinstance(kw, ast.keyword) and kw.arg == "verify":
                        if (
                            isinstance(kw.value, ast.Constant)
                            and kw.value.value is False
                        ):
                            self.add(
                                "SSL_VERIFICATION_DISABLED",
                                "medium",
                                node,
                                "requests call disables SSL verification.",
                                "Remove verify=False.",
                            )

        # 4) spark.sql / cursor.execute with concatenation or f-strings
        if fqname in ("spark.sql", "cursor.execute"):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr):
                    if self.policy.get("python", "sql_concat_blocklist", default=True):
                        self.add(
                            "SQL_INJECTION_RISK",
                            "high",
                            node,
                            f"{fqname} uses string concatenation or f-string.",
                            "Use parameterized queries or Spark SQL with bound params/templating.",
                        )

        # 5) printing secrets directly
        if fqname in ("print", "logging.info", "logging.debug"):
            for arg in node.args:
                if (
                    isinstance(arg, ast.Call)
                    and self._fqname(arg.func) == "dbutils.secrets.get"
                ):
                    self.add(
                        "SECRET_EXPOSED_IN_LOGS",
                        "critical",
                        node,
                        "Secret value printed to logs.",
                        "Do not print secrets; remove or mask.",
                    )
                if isinstance(arg, ast.Name) and arg.id in self.assignments:
                    self.add(
                        "SECRET_VARIABLE_EXPOSED",
                        "critical",
                        node,
                        f"Variable '{arg.id}' likely holds a secret and is printed.",
                        "Do not print secrets; remove or mask.",
                    )

        # 6) Simple hardcoded credentials (very lightweight, low-FP)
        if fqname in ("setenv", "os.environ.__setitem__", "os.putenv"):
            for a in node.args:
                if (
                    isinstance(a, ast.Constant)
                    and isinstance(a.value, str)
                    and ("KEY" in a.value.upper() or "TOKEN" in a.value.upper())
                ):
                    self.add(
                        "HARDCODED_CREDENTIALS",
                        "high",
                        node,
                        "Environment variable that looks like a secret is being set in code.",
                        "Use secret managers (Databricks secrets) instead.",
                    )

        self.generic_visit(node)

    def _fqname(self, func) -> str:
        # returns dotted name for attr or name
        if isinstance(func, ast.Attribute):
            base = self._fqbase(func)
            return f"{base}.{func.attr}" if base else func.attr
        elif isinstance(func, ast.Name):
            return func.id
        return ""

    def _fqbase(self, attr: ast.Attribute) -> str:
        parts = []
        cur = attr
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)

    def _first_arg_str(self, node: ast.Call):
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        return None


def run_python_rules(path: str, text: str, policy) -> Iterable[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    v = PyRuleVisitor(path, text, policy)
    v.visit(tree)
    return v.findings


def get_rules():
    # registry hook used by scanner
    return [run_python_rules]
