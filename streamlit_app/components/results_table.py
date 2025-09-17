"""
Results Table Component - Simple Design
Display scan results in a clean, easy-to-read format
"""

from typing import Any, Dict, List

import pandas as pd
import streamlit as st


def render_results(results: Dict[str, Any], scanner_service) -> None:
    """
    Render scan results with simple summary + table design

    Args:
        results: Scan results from scanner service
        scanner_service: Scanner service instance for data conversion
    """
    if not results or not results.get("all_findings"):
        st.success("✅ No security issues found in uploaded files!")
        return

    findings = results["all_findings"]
    summary = results["summary"]

    # Simple summary metrics
    render_summary_metrics(summary)

    # Main results table
    render_findings_table(findings, scanner_service)

    # File breakdown (optional expandable section)
    render_file_breakdown(results["findings_by_file"])


def render_summary_metrics(summary: Dict[str, Any]) -> None:
    """Display simple summary metrics in columns"""

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Issues", summary["total_issues"])

    with col2:
        critical_count = summary["by_severity"]["critical"]
        st.metric(
            "Critical",
            critical_count,
            delta=f"-{critical_count}" if critical_count > 0 else None,
            delta_color="inverse",
        )

    with col3:
        high_count = summary["by_severity"]["high"]
        st.metric(
            "High Severity",
            high_count,
            delta=f"-{high_count}" if high_count > 0 else None,
            delta_color="inverse",
        )

    with col4:
        st.metric("Files Affected", summary["files_with_issues"])

    # Show severity breakdown in a simple way
    severity_data = summary["by_severity"]
    non_zero = {k: v for k, v in severity_data.items() if v > 0}

    if non_zero:
        severity_text = " | ".join(
            [f"{k.capitalize()}: {v}" for k, v in non_zero.items()]
        )
        st.caption(f"Breakdown: {severity_text}")


def render_findings_table(findings: List, scanner_service) -> None:
    """Render simple, filterable findings table"""

    st.subheader("🔍 Issues Found")

    # Convert findings to DataFrame
    df = scanner_service.findings_to_dataframe(findings)

    if df.empty:
        st.info("No findings to display")
        return

    # Simple filter controls in one row
    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        # Severity filter
        all_severities = ["critical", "high", "medium", "low"]
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=all_severities,
            default=["critical", "high"],  # Show important ones by default
            help="Select severity levels to display",
        )

    with col2:
        # File filter
        file_filter = st.multiselect(
            "Filter by File",
            options=sorted(df["File"].unique()),
            default=[],
            help="Select specific files (leave empty for all)",
        )

    with col3:
        # Show all toggle
        show_all = st.checkbox("Show All", help="Show all severity levels")
        if show_all:
            severity_filter = all_severities

    # Apply filters
    filtered_df = df.copy()

    if severity_filter:
        filtered_df = filtered_df[filtered_df["Severity"].isin(severity_filter)]

    if file_filter:
        filtered_df = filtered_df[filtered_df["File"].isin(file_filter)]

    # Show filter results
    if len(filtered_df) != len(df):
        st.info(f"Showing {len(filtered_df)} of {len(df)} total issues")

    # Display the main table with key columns
    display_columns = [
        "File",
        "Rule ID",
        "Severity",
        "Line",
        "Message",
        "Recommendation",
    ]

    # Style the severity column with colors
    def style_severity(val):
        colors = {
            "critical": "background-color: #ffebee; color: #c62828",
            "high": "background-color: #fff3e0; color: #e65100",
            "medium": "background-color: #fffde7; color: #f57f17",
            "low": "background-color: #f3e5f5; color: #7b1fa2",
        }
        return colors.get(val, "")

    # Apply styling and display
    if not filtered_df.empty:
        styled_df = filtered_df[display_columns].style.applymap(
            style_severity, subset=["Severity"]
        )

        st.dataframe(styled_df, use_container_width=True, hide_index=True)

        # Export options
        col1, col2, col3 = st.columns([1, 1, 2])

        with col1:
            # CSV download
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name="roguecheck_results.csv",
                mime="text/csv",
            )

        with col2:
            # Show detailed view toggle
            if st.button("👁️ Show Details"):
                st.session_state.show_details = not st.session_state.get(
                    "show_details", False
                )

        # Detailed view (if requested)
        if st.session_state.get("show_details", False):
            st.subheader("📋 Detailed View")
            for idx, row in filtered_df.iterrows():
                with st.expander(f"{row['Rule ID']} - {row['File']}:{row['Line']}"):
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write(f"**Severity:** {row['Severity'].title()}")
                        st.write(f"**File:** {row['File']}")
                        st.write(f"**Line:** {row['Line']}")

                    with col2:
                        st.write(f"**Rule:** {row['Rule ID']}")
                        if row.get("Column"):
                            st.write(f"**Column:** {row['Column']}")

                    st.write("**Issue:**")
                    st.write(row["Message"])

                    if row["Recommendation"]:
                        st.write("**Recommendation:**")
                        st.info(row["Recommendation"])

                    if row.get("Snippet"):
                        st.write("**Code Context:**")
                        st.code(row["Snippet"], language="text")

    else:
        st.info("No issues match the current filters")


def render_file_breakdown(findings_by_file: Dict[str, List]) -> None:
    """Simple file-by-file breakdown in an expandable section"""

    if not findings_by_file or len(findings_by_file) <= 1:
        return

    with st.expander(
        f"📁 Issues by File ({len(findings_by_file)} files)", expanded=False
    ):

        # Create simple summary for each file
        for filename, file_findings in findings_by_file.items():
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for finding in file_findings:
                severity_counts[finding.severity] += 1

            # Display file summary in one line
            total_issues = len(file_findings)
            critical = severity_counts["critical"]
            high = severity_counts["high"]

            # Color code based on highest severity
            if critical > 0:
                emoji = "🔴"
            elif high > 0:
                emoji = "🟠"
            elif severity_counts["medium"] > 0:
                emoji = "🟡"
            else:
                emoji = "⚪"

            st.write(
                f"{emoji} **{filename}** — {total_issues} issues "
                f"(Critical: {critical}, High: {high})"
            )


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        "critical": "#DC3545",  # Red
        "high": "#FD7E14",  # Orange
        "medium": "#FFC107",  # Yellow
        "low": "#6C757D",  # Gray
    }
    return colors.get(severity, "#6C757D")
