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
            scanner_service = ScannerService(config)
            with st.spinner("Running security scan..."):
                results = scanner_service.scan_uploaded_files(uploaded_files)
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
