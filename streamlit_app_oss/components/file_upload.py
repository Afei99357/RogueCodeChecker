"""
File Upload Component
Handles multiple file upload with validation and preview
"""

from typing import List

import streamlit as st


def render_file_upload() -> List:
    """
    Render file upload widget with multiple file support and validation

    Returns:
        List of uploaded files (Streamlit UploadedFile objects)
    """

    SUPPORTED_EXTENSIONS = [
        "py",
        "sql",
        "sh",
        "bash",
        "txt",
        "md",
        "ipynb",
        "js",
        "ts",
        "java",
        "go",
        "rb",
        "php",
        "cs",
        "tf",
        "yaml",
        "yml",
    ]
    MAX_FILE_SIZE_MB = 10

    # Initialize uploader key in session state
    if "uploader_key" not in st.session_state:
        st.session_state.uploader_key = 0

    uploaded_files = st.file_uploader(
        "Choose files to scan for security issues",
        accept_multiple_files=True,
        type=SUPPORTED_EXTENSIONS,
        help=f"Supported: {', '.join([f'.{ext}' for ext in SUPPORTED_EXTENSIONS])}. Max size: {MAX_FILE_SIZE_MB}MB per file",
        key=f"file_uploader_{st.session_state.uploader_key}",
    )

    if uploaded_files:
        valid_files = []
        invalid_files = []
        for file in uploaded_files:
            file_size_mb = len(file.getvalue()) / (1024 * 1024)
            if file_size_mb > MAX_FILE_SIZE_MB:
                invalid_files.append(
                    f"**{file.name}**: Too large ({file_size_mb:.1f}MB > {MAX_FILE_SIZE_MB}MB)"
                )
                continue
            if len(file.getvalue()) == 0:
                invalid_files.append(f"**{file.name}**: Empty file")
                continue
            # Special-case Dockerfile (no extension)
            name_lower = file.name.lower()
            if name_lower == "dockerfile":
                valid_files.append(file)
            else:
                valid_files.append(file)

        if invalid_files:
            st.warning("⚠️ Some files were skipped:")
            for invalid_file in invalid_files:
                st.write(f"- {invalid_file}")

        if valid_files:
            file_types: dict = {}
            total_size = 0
            for file in valid_files:
                extension = file.name.split(".")[-1].lower()
                file_types[extension] = file_types.get(extension, 0) + 1
                total_size += len(file.getvalue())

            col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
            with col1:
                st.metric("Valid Files", len(valid_files))
            with col2:
                st.metric("Total Size", f"{total_size / 1024:.1f} KB")
            with col3:
                st.metric("Unique Types", len(file_types) or 0)
                if file_types:
                    st.caption(
                        ", ".join(sorted({ext.upper() for ext in file_types.keys()}))
                    )
            with col4:
                st.write("")  # spacing
                if st.button("🗑️ Clear", use_container_width=True):
                    st.session_state.uploader_key += 1
                    st.rerun()

            if len(file_types) > 1:
                with st.expander("📊 File Type Breakdown"):
                    for ext, count in sorted(file_types.items()):
                        st.write(
                            f"**{ext.upper()}**: {count} file{'s' if count != 1 else ''}"
                        )

        return valid_files

    else:
        st.info(
            """
        📤 **Upload files to scan:**

        - **Python** (.py)
        - **SQL** (.sql)
        - **Bash** (.sh)
        - **Plain text/Markdown** (.txt, .md) — extracts embedded SQL/Bash fences and snippets
        - **Notebooks** (.ipynb)
        - **JavaScript/TypeScript** (.js, .ts)
        - **Java/Go/Ruby/PHP/C#** (.java, .go, .rb, .php, .cs)
        - **Terraform/YAML** (.tf, .yaml, .yml)
        - **Dockerfile** (no extension; named "Dockerfile")
            """
        )
        return []
