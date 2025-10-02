import json
import os
from typing import Iterable, List, Tuple


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _process_ipynb(src_path: str, out_dir: str) -> List[str]:
    out: List[str] = []
    try:
        with open(src_path, "r", encoding="utf-8") as f:
            nb = json.load(f)
    except Exception:
        return out
    base = os.path.splitext(os.path.basename(src_path))[0]
    cells = nb.get("cells", [])
    for idx, cell in enumerate(cells):
        if cell.get("cell_type") != "code":
            continue
        src_lines = cell.get("source", [])
        # Normalize to str
        code = "".join(src_lines)
        # Detect %sql / %%sql magic
        lines = [l.rstrip("\n") for l in src_lines]
        first_nonempty = next((l for l in lines if l.strip()), "")
        if first_nonempty.lstrip().startswith(("%sql", "%%sql")):
            # SQL is everything after first magic line
            start_idx = lines.index(first_nonempty)
            sql_text = "\n".join(lines[start_idx + 1 :]).strip()
            if sql_text:
                out_path = os.path.join(out_dir, f"{base}__cell{idx:03d}.sql")
                _write(out_path, f"-- Extracted from {os.path.basename(src_path)} cell {idx}\n" + sql_text)
                out.append(out_path)
        else:
            if code.strip():
                out_path = os.path.join(out_dir, f"{base}__cell{idx:03d}.py")
                _write(out_path, f"# Extracted from {os.path.basename(src_path)} cell {idx}\n" + code)
                out.append(out_path)
    return out


def _process_dbx_py(src_path: str, out_dir: str) -> List[str]:
    out: List[str] = []
    try:
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return out
    lines = text.splitlines()
    base = os.path.splitext(os.path.basename(src_path))[0]
    i = 0
    block_idx = 0
    while i < len(lines):
        line = lines[i].lstrip()
        if line.startswith("# MAGIC %sql"):
            # Collect subsequent # MAGIC lines until next # COMMAND or non-MAGIC marker
            sql_lines: List[str] = []
            i += 1
            while i < len(lines):
                cur = lines[i]
                cur_strip = cur.lstrip()
                if cur_strip.startswith("# COMMAND"):
                    break
                if cur_strip.startswith("# MAGIC %") and not cur_strip.startswith("# MAGIC %sql"):
                    break
                if cur_strip.startswith("# MAGIC"):
                    sql_lines.append(cur_strip.replace("# MAGIC ", "", 1).replace("# MAGIC", "", 1))
                else:
                    sql_lines.append(cur)
                i += 1
            sql_text = "\n".join(sql_lines).strip()
            if sql_text:
                out_path = os.path.join(out_dir, f"{base}__sqlblock{block_idx:03d}.sql")
                _write(out_path, f"-- Extracted from {os.path.basename(src_path)}\n" + sql_text)
                out.append(out_path)
                block_idx += 1
            continue
        i += 1
    return out


def preprocess_notebooks(targets: Iterable[str], out_dir: str) -> List[str]:
    """Extract Python and SQL from Databricks notebooks (.ipynb) and exported .py notebooks.

    Returns list of generated file paths.
    """
    generated: List[str] = []
    for path in targets:
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".ipynb":
                generated.extend(_process_ipynb(path, out_dir))
            elif ext == ".py":
                # Heuristic: only process files that look like dbx-exported notebooks
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(4096)
                if "# Databricks notebook source" in head or "# MAGIC %sql" in head:
                    generated.extend(_process_dbx_py(path, out_dir))
        except Exception:
            # Best-effort: ignore errors
            continue
    return generated

