"""
RogueCheck Streamlit Web Application
Main entry point for the web interface
"""

import os
import sys

import streamlit as st

# Add parent directory to path so we can import components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from streamlit_app.components.config_panel import render_config_panel
from streamlit_app.components.file_upload import render_file_upload
from streamlit_app.components.results_table import render_results
from streamlit_app.services.scanner_service import ScannerService


def main():
    """Main Streamlit application"""

    # Page configuration
    st.set_page_config(
        page_title="RogueCheck Security Scanner",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom CSS for better styling
    st.markdown(
        """
    <style>
    .main-header {
        font-size: 3rem;
        color: #FF6B6B;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #FF6B6B;
    }
    .severity-critical {
        color: #DC3545;
        font-weight: bold;
    }
    .severity-high {
        color: #FD7E14;
        font-weight: bold;
    }
    .severity-medium {
        color: #FFC107;
        font-weight: bold;
    }
    .severity-low {
        color: #6C757D;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # Application header
    st.markdown(
        '<h1 class="main-header">🔍 RogueCheck Security Scanner</h1>',
        unsafe_allow_html=True,
    )
    st.markdown(
        """
    <div style="text-align: center; margin-bottom: 2rem; color: #666;">
    Detect security vulnerabilities and rogue code patterns in AI-generated scripts
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        config = render_config_panel()

    # Main content area
    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("📁 Upload Files")
        uploaded_files = render_file_upload()

        # Show upload status
        if uploaded_files:
            st.success(f"✅ {len(uploaded_files)} files uploaded")

            # File details in expander
            with st.expander("📋 File Details", expanded=False):
                for file in uploaded_files:
                    file_size = len(file.getvalue())
                    st.write(f"**{file.name}** ({file_size:,} bytes)")

    with col2:
        st.subheader("🔍 Scan Results")

        if uploaded_files:
            # Initialize scanner service with config
            scanner_service = ScannerService(config)

            # Show scanning progress
            with st.spinner("Scanning files for security issues..."):
                results = scanner_service.scan_uploaded_files(uploaded_files)

            # Display results
            if results.get("error"):
                st.error(f"❌ Scanning failed: {results['error']}")
            else:
                render_results(results, scanner_service)
        else:
            st.info("👆 Upload files to start scanning")

    # Footer
    st.markdown("---")
    st.markdown(
        """
    <div style="text-align: center; color: #666; margin-top: 2rem;">
    Powered by RogueCheck Security Scanner | Built with Streamlit
    </div>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
