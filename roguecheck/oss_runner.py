import os
import tempfile
from typing import List, Optional

from .models import Finding
from .utils import read_text, safe_snippet
from .policy import Policy
from .oss_nb_preprocess import preprocess_notebooks
from .sniff import guess_extensions, extract_embedded_snippets


def run_oss_tools(
    root: str,
    policy: Policy,
    tools: List[str],
    semgrep_config: str = "auto",
    files: Optional[List[str]] = None,
) -> List[Finding]:
    # Normalize files: if a single-file path was provided as root, treat it as explicit list
    if files is None and os.path.isfile(root):
        files = [os.path.abspath(root)]
    targets: List[str] = []
    if files:
        targets = [os.path.abspath(f) for f in files]
    else:
        # If no explicit list, scan the root directory
        targets = [os.path.abspath(root)]

    all_findings: List[Finding] = []

    with tempfile.TemporaryDirectory() as tmp:
        # Preprocess notebooks to additional .py/.sql files
        # Discover notebooks when scanning a directory
        discover_list: List[str] = []
        if files is None and os.path.isdir(root):
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    if fn.endswith((".ipynb", ".py")):
                        discover_list.append(os.path.join(dirpath, fn))
        else:
            discover_list = [p for p in targets if p.endswith((".ipynb", ".py"))]

        generated = preprocess_notebooks(discover_list, tmp)
        # Map of generated temp file -> (origin_abs_path, origin_start_line)
        origin_map: dict[str, tuple[str, int]] = {}
        # Generic snippet extraction for all files (SQL / Shell inside other hosts)
        for p in (files or []):
            try:
                with open(p if os.path.isabs(p) else os.path.join(root, p), "r", encoding="utf-8", errors="ignore") as fh:
                    txt = fh.read()
            except Exception:
                continue
            for ext, snippet, start_line in extract_embedded_snippets(txt):
                if not snippet:
                    continue
                base = os.path.basename(p)
                out_path = os.path.join(tmp, f"{base}__embedded{len(generated):03d}{ext}")
                try:
                    with open(out_path, "w", encoding="utf-8") as oh:
                        oh.write(snippet)
                    generated.append(out_path)
                    # Record origin path and starting line for mapping back
                    abs_origin = p if os.path.isabs(p) else os.path.abspath(os.path.join(root, p))
                    origin_map[out_path] = (abs_origin, int(start_line) if start_line else 1)
                except Exception:
                    pass
        # If files have unknown extension but look like a language, create a typed copy for Semgrep
        typed_copies: List[str] = []
        for p in (files or []):
            abs_p = p if os.path.isabs(p) else os.path.join(root, p)
            _, ext = os.path.splitext(abs_p.lower())
            if ext:
                continue
            try:
                with open(abs_p, "r", encoding="utf-8", errors="ignore") as fh:
                    txt = fh.read()
            except Exception:
                continue
            exts = guess_extensions(txt, abs_p)
            if not exts:
                continue
            # Use the first guess
            new_path = os.path.join(tmp, os.path.basename(abs_p) + exts[0])
            try:
                with open(new_path, "w", encoding="utf-8") as oh:
                    oh.write(txt)
                typed_copies.append(new_path)
                origin_map[new_path] = (abs_p, 1)
            except Exception:
                pass
        combined_files: Optional[List[str]] = None
        # Prefer explicit file list to keep Semgrep scope tight; otherwise, tools can scan root
        if files or generated or typed_copies:
            combined_files = []
            if files:
                combined_files.extend(files)
            combined_files.extend(generated)
            combined_files.extend(typed_copies)

        # Run selected tools
        if "semgrep" in tools:
            from .oss_semgrep import scan_with_semgrep

            all_findings.extend(
                scan_with_semgrep(
                    root=root, policy=policy, semgrep_config=semgrep_config, files=combined_files
                )
            )
        if "detect-secrets" in tools:
            from .oss_detect_secrets import scan_with_detect_secrets

            all_findings.extend(
                scan_with_detect_secrets(root=root, policy=policy, files=combined_files)
            )
        if "sqlfluff" in tools:
            from .oss_sqlfluff import scan_with_sqlfluff

            all_findings.extend(
                scan_with_sqlfluff(root=root, policy=policy, files=combined_files)
            )
        if "shellcheck" in tools:
            from .oss_shellcheck import scan_with_shellcheck

            all_findings.extend(
                scan_with_shellcheck(root=root, policy=policy, files=combined_files)
            )
        if "sql-strict" in tools:
            from .oss_sql_strict import scan_strict_sql

            all_findings.extend(
                scan_strict_sql(root=root, policy=policy, files=combined_files)
            )
        if "sqlcheck" in tools:
            from .oss_sqlcheck import scan_with_sqlcheck

            all_findings.extend(
                scan_with_sqlcheck(root=root, policy=policy, files=combined_files)
            )
        # Map findings produced on generated temp files back to their origin file and line
        if origin_map:
            for f in all_findings:
                # Compute absolute path for the finding relative to root
                f_abs = f.path if os.path.isabs(f.path) else os.path.abspath(os.path.join(root, f.path))
                if f_abs in origin_map:
                    origin_path, origin_start = origin_map[f_abs]
                    try:
                        # Rebase path to the origin file relative to root
                        f.path = os.path.relpath(origin_path, root)
                        # Adjust line number relative to snippet start
                        if getattr(f, "position", None):
                            f.position.line = int(origin_start) + int(getattr(f.position, "line", 1)) - 1
                            # Recompute snippet from origin file for accurate details view
                            try:
                                txt = read_text(origin_path)
                                f.snippet = safe_snippet(txt, f.position.line)
                            except Exception:
                                pass
                    except Exception:
                        pass

    return all_findings
