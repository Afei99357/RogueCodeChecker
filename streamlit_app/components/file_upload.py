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

    # Supported file types
    SUPPORTED_EXTENSIONS = ["py", "sql", "sh", "bash"]
    MAX_FILE_SIZE_MB = 10

    # File uploader widget
    uploaded_files = st.file_uploader(
        "Choose files to scan for security issues",
        accept_multiple_files=True,
        type=SUPPORTED_EXTENSIONS,
        help=f"Supported file types: {', '.join([f'.{ext}' for ext in SUPPORTED_EXTENSIONS])}. Max size: {MAX_FILE_SIZE_MB}MB per file",
    )

    if uploaded_files:
        # Validate uploaded files
        valid_files = []
        invalid_files = []

        for file in uploaded_files:
            file_size_mb = len(file.getvalue()) / (1024 * 1024)

            # Check file size
            if file_size_mb > MAX_FILE_SIZE_MB:
                invalid_files.append(
                    f"**{file.name}**: Too large ({file_size_mb:.1f}MB > {MAX_FILE_SIZE_MB}MB)"
                )
                continue

            # Check if file has content
            if len(file.getvalue()) == 0:
                invalid_files.append(f"**{file.name}**: Empty file")
                continue

            valid_files.append(file)

        # Show validation results
        if invalid_files:
            st.warning("⚠️ Some files were skipped:")
            for invalid_file in invalid_files:
                st.write(f"- {invalid_file}")

        if valid_files:
            # Show file type breakdown
            file_types = {}
            total_size = 0

            for file in valid_files:
                extension = file.name.split(".")[-1].lower()
                file_types[extension] = file_types.get(extension, 0) + 1
                total_size += len(file.getvalue())

            # Display file statistics
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Valid Files", len(valid_files))

            with col2:
                st.metric("Total Size", f"{total_size / 1024:.1f} KB")

            with col3:
                most_common_type = (
                    max(file_types.items(), key=lambda x: x[1])
                    if file_types
                    else ("none", 0)
                )
                st.metric("Primary Type", f".{most_common_type[0]}")

            # File type breakdown
            if len(file_types) > 1:
                with st.expander("📊 File Type Breakdown"):
                    for ext, count in sorted(file_types.items()):
                        st.write(
                            f"**{ext.upper()}**: {count} file{'s' if count != 1 else ''}"
                        )

        return valid_files

    else:
        # Show help message when no files uploaded
        st.info(
            """
        📤 **Upload files to scan:**

        - **Python** (.py) - Check for eval/exec, unsafe imports, SQL injection
        - **SQL** (.sql) - Detect broad permissions, dangerous operations
        - **Bash** (.sh) - Find unsafe commands, network calls

        You can upload multiple files at once for batch scanning.
        """
        )

        return []


def show_file_preview(uploaded_files: List, max_lines: int = 10) -> None:
    """
    Show preview of uploaded file contents

    Args:
        uploaded_files: List of uploaded files
        max_lines: Maximum number of lines to show in preview
    """
    if not uploaded_files:
        return

    st.subheader("📄 File Previews")

    for file in uploaded_files:
        with st.expander(f"Preview: {file.name}"):
            try:
                # Decode file content
                content = file.getvalue().decode("utf-8")
                lines = content.split("\n")

                # Show first few lines
                preview_lines = lines[:max_lines]
                st.code(
                    "\n".join(preview_lines),
                    language=_get_language_from_extension(file.name),
                )

                # Show truncation message if needed
                if len(lines) > max_lines:
                    st.caption(f"... ({len(lines) - max_lines} more lines)")

            except UnicodeDecodeError:
                st.error(f"Cannot preview {file.name} - contains non-text content")
            except Exception as e:
                st.error(f"Error previewing {file.name}: {str(e)}")


def _get_language_from_extension(filename: str) -> str:
    """Get syntax highlighting language from file extension"""
    extension = filename.split(".")[-1].lower()

    language_map = {"py": "python", "sql": "sql", "sh": "bash", "bash": "bash"}

    return language_map.get(extension, "text")
