import os
import re
from typing import Iterable, List, Tuple


SQL_HINT = re.compile(r"\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|GRANT\s+ALL|DROP\s+TABLE|TRUNCATE\s+TABLE)\b", re.IGNORECASE)
SHELL_HINT = re.compile(r"(^#!.*\b(bash|sh)\b)|\b(curl\s+|wget\s+|rm\s+-rf\s+|chmod\s+\d{3}|sudo\s+)\b", re.IGNORECASE | re.MULTILINE)


def guess_extensions(text: str, filename: str) -> List[str]:
    """Heuristically guess likely extensions for a file based on content and name.
    Returns a list like [".py"], [".sh"], [".sql"], or multiple when ambiguous.
    """
    name = filename.lower()
    # Extension-based quick guess
    _, ext = os.path.splitext(name)
    if ext in {".py", ".sh", ".bash", ".sql", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"}:
        return [ext]
    # Shebangs
    if text.startswith("#!/"):
        if "bash" in text.splitlines()[0] or text.splitlines()[0].endswith("/sh"):
            return [".sh"]
    # Language keywords
    if re.search(r"\b(def|import|from\s+\w+\s+import)\b", text):
        return [".py"]
    if re.search(r"\b(function\s+\w+|import\s+.*from\s+['\"])\b", text):
        return [".js"]
    if re.search(r"\bpackage\s+\w+;|public\s+class\b", text):
        return [".java"]
    if re.search(r"\bpackage\s+\w+\n|func\s+\w+\(|import\s+\(\)\b", text):
        return [".go"]
    if SQL_HINT.search(text):
        return [".sql"]
    if SHELL_HINT.search(text):
        return [".sh"]
    return []


def extract_embedded_snippets(text: str) -> List[Tuple[str, str]]:
    """Extract embedded SQL or shell-like snippets from a text blob.
    Returns list of (ext, snippet_text) where ext is ".sql" or ".sh".
    Very lightweight heuristics to augment coverage across host languages.
    """
    out: List[Tuple[str, str]] = []
    # Fenced code blocks ```sql ... ``` or ```bash ... ```
    for m in re.finditer(r"```(sql|postgres|tsql|bigquery)\s*(.*?)```", text, re.IGNORECASE | re.DOTALL):
        out.append((".sql", m.group(2).strip()))
    for m in re.finditer(r"```(bash|sh|shell)\s*(.*?)```", text, re.IGNORECASE | re.DOTALL):
        out.append((".sh", m.group(2).strip()))
    # Inline SQL hints: capture lines around statements
    for m in SQL_HINT.finditer(text):
        # Grab up to next semicolon or 5 lines
        start = m.start()
        segment = text[start: start + 1000]
        semi = segment.find(";")
        snippet = segment[: semi + 1] if semi != -1 else segment.splitlines()[0]
        out.append((".sql", snippet.strip()))
    # Shell hints: capture the line
    for m in SHELL_HINT.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.start())
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        out.append((".sh", line.strip()))

    # Java-specific: Runtime.exec and ProcessBuilder("bash","-c", ...)
    for m in re.finditer(r"Runtime\.getRuntime\(\)\.exec\(\s*\"([^\"]+)\"\s*\)", text):
        out.append((".sh", m.group(1)))
    # ProcessBuilder("bash","-c","<cmd>")
    for m in re.finditer(r"ProcessBuilder\(\s*\"bash\"\s*,\s*\"-c\"\s*,\s*\"([^\"]+)\"\s*\)", text):
        out.append((".sh", m.group(1)))
    # JDBC Statement.execute("SQL...") / executeQuery / prepareStatement
    for m in re.finditer(r"\.(execute|executeQuery|prepareStatement)\(\s*\"([^\"]+)\"\s*\)", text):
        sql = m.group(2)
        if SQL_HINT.search(sql):
            out.append((".sql", sql))

    # JavaScript/TypeScript: child_process.exec/execSync and spawn('sh','-c',...)
    for m in re.finditer(r"child_process\.(exec|execSync)\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
        out.append((".sh", m.group(2)))
    for m in re.finditer(r"spawn\(\s*['\"](bash|sh)['\"]\s*,\s*\[\s*['\"]-c['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\]", text):
        out.append((".sh", m.group(2)))
    # Common SQL query usage in JS: db.query("SQL ...")
    for m in re.finditer(r"\.(query|execute)\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
        s = m.group(2)
        if SQL_HINT.search(s):
            out.append((".sql", s))
    return out
