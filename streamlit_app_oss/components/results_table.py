"""
Results Table Component - Simple Design
Display scan results in a clean, easy-to-read format
"""

import io
import zipfile
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from roguecheck.report import to_markdown


def render_results(results: Dict[str, Any], scanner_service) -> None:
    if not results:
        st.info("Upload files to scan.")
        return

    has_issues = bool(results.get("all_findings"))
    diagnostics = results.get("diagnostics", [])
    if not has_issues:
        st.info("No code issues found in uploaded files.")
        zip_bytes = _build_markdown_zip(
            results.get("findings_by_file", {}), results.get("files_scanned", [])
        )
        st.download_button(
            label="📦 Download per-file Markdown",
            data=zip_bytes,
            file_name="per_file_markdown_reports.zip",
            mime="application/zip",
        )
        if diagnostics:
            _render_diagnostics(diagnostics, scanner_service)
        return

    findings = results["all_findings"]
    summary = results["summary"]

    render_summary_metrics(summary)
    render_findings_table(
        findings,
        scanner_service,
        results.get("findings_by_file", {}),
        results.get("files_scanned", []),
    )
    render_file_breakdown(results["findings_by_file"])
    if diagnostics:
        _render_diagnostics(diagnostics, scanner_service)


def _render_diagnostics(diags: List, scanner_service) -> None:
    with st.expander("🛠 Engine Diagnostics", expanded=False):
        st.caption("Environment or engine advisories that are not tied to a file.")
        if not diags:
            st.write("No diagnostics.")
            return
        df = scanner_service.findings_to_dataframe(diags)
        if df.empty:
            st.write("No diagnostics.")
            return
        display_columns = ["Rule ID", "Severity", "Message", "Recommendation"]
        st.dataframe(df[display_columns], use_container_width=True, hide_index=True)


def render_summary_metrics(summary: Dict[str, Any]) -> None:
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
    severity_data = summary["by_severity"]
    non_zero = {k: v for k, v in severity_data.items() if v > 0}
    if non_zero:
        severity_text = " | ".join(
            [f"{k.capitalize()}: {v}" for k, v in non_zero.items()]
        )
        st.caption(f"Breakdown: {severity_text}")


def render_findings_table(
    findings: List,
    scanner_service,
    findings_by_file: Dict[str, List],
    files_scanned: List[str],
) -> None:
    st.subheader("🔍 Issues Found")
    df = scanner_service.findings_to_dataframe(findings)
    if df.empty:
        st.info("No findings to display")
        return
    col1, col2 = st.columns([2, 2])
    with col1:
        all_severities = ["critical", "high", "medium", "low"]
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=all_severities,
            default=all_severities,
            help="Select severity levels to display",
        )
    with col2:
        file_filter = st.multiselect(
            "Filter by File",
            options=sorted(df["File"].unique()),
            default=[],
            help="Select specific files (leave empty for all)",
        )
    filtered_df = df.copy()
    if severity_filter:
        filtered_df = filtered_df[filtered_df["Severity"].isin(severity_filter)]
    if file_filter:
        filtered_df = filtered_df[filtered_df["File"].isin(file_filter)]
    if len(filtered_df) != len(df):
        st.caption(f"Showing {len(filtered_df)} of {len(df)} issues")
    display_columns = [
        "File",
        "Rule ID",
        "Severity",
        "Line",
        "Message",
        "Recommendation",
    ]

    # View mode: Combined table or per-file tables
    view_mode = st.radio(
        "View Mode",
        options=["Combined", "By File"],
        index=0,
        horizontal=True,
        help="Switch between a single combined table or one table per file",
    )

    def style_severity(val):
        colors = {
            "critical": "background-color: #ffebee; color: #c62828",
            "high": "background-color: #fff3e0; color: #e65100",
            "medium": "background-color: #fffde7; color: #f57f17",
            "low": "background-color: #f3e5f5; color: #7b1fa2",
        }
        return colors.get(val, "")

    if not filtered_df.empty:
        if view_mode == "Combined":
            styled_df = filtered_df[display_columns].style.map(
                style_severity, subset=["Severity"]
            )
            st.dataframe(styled_df, width="stretch", hide_index=True)
        else:
            # Per-file tables
            for file_name in sorted(filtered_df["File"].unique()):
                sub = filtered_df[filtered_df["File"] == file_name]
                st.markdown(f"**File:** {file_name} — {len(sub)} issue(s)")
                styled_df = sub[display_columns].style.map(
                    style_severity, subset=["Severity"]
                )
                st.dataframe(styled_df, width="stretch", hide_index=True)

        col1, col2 = st.columns([1, 1])
        with col1:
            zip_bytes = _build_markdown_zip(findings_by_file, files_scanned)
            st.download_button(
                label="📦 Download per-file Markdown",
                data=zip_bytes,
                file_name="per_file_markdown_reports.zip",
                mime="application/zip",
            )
        with col2:
            if st.button("👁️ Show Details"):
                st.session_state.show_details = not st.session_state.get(
                    "show_details", False
                )
        if st.session_state.get("show_details", False):
            st.subheader("📋 Detailed View")
            for idx, row in filtered_df.iterrows():
                with st.expander(f"{row['Rule ID']} - {row['File']}:{row['Line']}"):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write(f"**Severity:** {row['Severity'].title()}")
                        st.write(f"**File:** {row['File']}")
                        st.write(f"**Line:** {row['Line']}")
                    with c2:
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
    if not findings_by_file or len(findings_by_file) <= 1:
        return
    with st.expander(
        f"📁 Issues by File ({len(findings_by_file)} files)", expanded=False
    ):
        for filename, file_findings in findings_by_file.items():
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in file_findings:
                severity_counts[finding.severity] += 1
            total_issues = len(file_findings)
            critical = severity_counts["critical"]
            high = severity_counts["high"]
            if critical > 0:
                emoji = "🔴"
            elif high > 0:
                emoji = "🟠"
            elif severity_counts["medium"] > 0:
                emoji = "🟡"
            else:
                emoji = "⚪"
            st.write(
                f"{emoji} **{filename}** — {total_issues} issues (Critical: {critical}, High: {high})"
            )


def get_severity_color(severity: str) -> str:
    colors = {
        "critical": "#DC3545",
        "high": "#FD7E14",
        "medium": "#FFC107",
        "low": "#6C757D",
    }
    return colors.get(severity, "#6C757D")


def _build_markdown_zip(
    findings_by_file: Dict[str, List], files_scanned: List[str]
) -> bytes:
    buf = io.BytesIO()
    counts: Dict[str, int] = {}
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        ordered_files = files_scanned or list(findings_by_file.keys())
        for file_name in ordered_files:
            findings = findings_by_file.get(file_name, [])
            content = to_markdown(findings)
            safe_name = file_name.replace("/", "_").replace("\\", "_")
            if not safe_name.lower().endswith("_report.md"):
                safe_name = f"{safe_name}_report.md"
            counts[safe_name] = counts.get(safe_name, 0) + 1
            final_name = safe_name
            if counts[safe_name] > 1:
                stem, ext = safe_name.rsplit(".", 1)
                final_name = f"{stem}_{counts[safe_name]-1}.{ext}"
            zf.writestr(final_name, content)
    return buf.getvalue()
