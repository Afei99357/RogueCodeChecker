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

    SUPPORTED_EXTENSIONS = ["py", "sql", "sh", "bash", "ipynb"]
    MAX_FILE_SIZE_MB = 10

    uploaded_files = st.file_uploader(
        "Choose files to scan for security issues",
        accept_multiple_files=True,
        type=SUPPORTED_EXTENSIONS,
        help=f"Supported: {', '.join([f'.{ext}' for ext in SUPPORTED_EXTENSIONS])}. Max size: {MAX_FILE_SIZE_MB}MB per file",
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
            valid_files.append(file)

        if invalid_files:
            st.warning("⚠️ Some files were skipped:")
            for invalid_file in invalid_files:
                st.write(f"- {invalid_file}")

        if valid_files:
            file_types = {}
            total_size = 0
            for file in valid_files:
                extension = file.name.split(".")[-1].lower()
                file_types[extension] = file_types.get(extension, 0) + 1
                total_size += len(file.getvalue())

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Valid Files", len(valid_files))
            with col2:
                st.metric("Total Size", f"{total_size / 1024:.1f} KB")
            with col3:
                most_common_type = (
                    max(file_types.items(), key=lambda x: x[1]) if file_types else ("none", 0)
                )
                st.metric("Primary Type", f".{most_common_type[0]}")

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
        - **Notebooks** (.ipynb)
        """
        )
        return []

