import shutil
import subprocess
import streamlit as st


def _which(name: str) -> str:
    p = shutil.which(name)
    return p or "(not found)"


def _version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=8)
        return (out.stdout or "").strip().splitlines()[0]
    except Exception:
        return "(unavailable)"


def render_diagnostics(semgrep_packs: str) -> None:
    with st.expander("🛠 Diagnostics", expanded=False):
        st.write("Tool availability and versions:")
        col1, col2 = st.columns(2)
        with col1:
            st.caption(f"semgrep: {_which('semgrep')}")
            st.caption(f"detect-secrets: {_which('detect-secrets')}")
            st.caption(f"sqlfluff: {_which('sqlfluff')}")
            st.caption(f"shellcheck: {_which('shellcheck')}")
        with col2:
            st.caption(f"semgrep version: {_version(['semgrep', '--version'])}")
            st.caption(f"detect-secrets version: {_version(['detect-secrets', '--version'])}")
            st.caption(f"sqlfluff version: {_version(['sqlfluff', '--version'])}")
            st.caption(f"shellcheck version: {_version(['shellcheck', '--version'])}")
        st.write("Active Semgrep packs:")
        st.code(semgrep_packs or "(none)")

