"""
OSS-Only Streamlit Web Application (Semgrep)
"""

import os
import sys

import streamlit as st

# Add parent directory to path so we can import shared components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from streamlit_app_oss.components.config_panel import render_config_panel
from streamlit_app_oss.components.diagnostics import render_diagnostics
from streamlit_app_oss.components.file_upload import render_file_upload
from streamlit_app_oss.components.results_table import render_results
from streamlit_app_oss.services.scanner_service import ScannerService


def main():
    st.set_page_config(
        page_title="Security Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        '<h1 class="main-header">🔒 Security Scanner</h1>',
        unsafe_allow_html=True,
    )

    # Sidebar config (force engine=oss)
    with st.sidebar:
        st.header("⚙️ Configuration")
        config = render_config_panel()
        config["engine"] = "oss"

    col1, col2 = st.columns([1, 2])
    with col1:
        st.subheader("📁 Upload Files")
        uploaded_files = render_file_upload()
        if uploaded_files:
            st.success(f"✅ {len(uploaded_files)} files uploaded")

    with col2:
        st.subheader("🔍 Scan Results")
        if uploaded_files:
            # Create cache key based on uploaded files and config
            file_names = tuple(sorted([f.name for f in uploaded_files]))
            file_contents_hash = hash(tuple(f.getvalue() for f in uploaded_files))
            config_hash = hash(tuple(sorted(f"{k}:{v}" for k, v in config.items())))
            cache_key = f"{file_names}_{file_contents_hash}_{config_hash}"

            # Check if we need to rescan (files or config changed)
            if (
                "scan_cache_key" not in st.session_state
                or st.session_state.scan_cache_key != cache_key
            ):
                # Run scan only if files or config changed
                scanner_service = ScannerService(config)
                with st.spinner("Running security scan..."):
                    results = scanner_service.scan_uploaded_files(uploaded_files)

                # Cache results in session state
                st.session_state.scan_results = results
                st.session_state.scan_cache_key = cache_key
                st.session_state.scanner_service = scanner_service
            else:
                # Reuse cached results
                results = st.session_state.scan_results
                scanner_service = st.session_state.scanner_service

            if results.get("error"):
                st.error(f"❌ Scanning failed: {results['error']}")
            else:
                render_results(results, scanner_service)
        else:
            st.info("👆 Upload files to start scanning")

    st.markdown("---")
    render_diagnostics(
        config.get("semgrep_packs", "p/security-audit,p/python,p/javascript")
    )


if __name__ == "__main__":
    main()
