"""
Configuration Panel Component
Simple sidebar configuration for scanner settings
"""

from typing import Dict, List

import streamlit as st


def render_config_panel() -> Dict:
    """
    Render simple configuration panel in sidebar

    Returns:
        Dict containing user configuration settings
    """

    config = {}

    # Scanner Settings
    st.subheader("⚙️ Scanner Settings")

    # Engine selection (OSS app forces engine=oss in caller but keep UI consistent)
    config["engine"] = st.selectbox(
        "Scanner Engine",
        options=["oss"],
        index=0,
        help="OSS-only app uses open-source tools",
    )

    # Severity threshold for highlighting
    config["fail_threshold"] = st.selectbox(
        "Priority Focus",
        options=["critical", "high", "medium", "low"],
        index=1,  # Default to "high"
        help="Highlight issues at this severity level and above",
    )

    # File size limit (UI-only hint)
    config["max_file_size_mb"] = st.number_input(
        "Max File Size (MB)",
        min_value=1,
        max_value=50,
        value=10,
        help="Skip files larger than this size",
    )

    st.divider()

    # Network Settings
    st.subheader("🌐 Network Rules")

    # Custom allowed domains (affects Semgrep custom rules if applicable)
    st.write("**Additional Allowed Domains**")
    custom_domains_text = st.text_area(
        "Domains to whitelist (one per line)",
        height=80,
        placeholder="api.mycompany.com\n*.trusted-cdn.net\nlocalhost:8080",
        help="Add domains that should be allowed for network calls (used in custom rules)",
    )

    config["custom_domains"] = [
        domain.strip() for domain in custom_domains_text.split("\n") if domain.strip()
    ]

    # HTTP policy (UI-only hint)
    config["allow_http"] = st.checkbox(
        "Allow HTTP (non-HTTPS) requests",
        value=False,
        help="Check to allow plain HTTP requests (not recommended for production)",
    )

    st.divider()

    # Semgrep Packs
    st.subheader("🧩 Semgrep Packs")
    packs_default = "p/security-audit,p/python,p/bash"
    config["semgrep_packs"] = st.text_input(
        "Packs (comma-separated)",
        value=packs_default,
        help="Registry packs like p/python,p/security-audit,p/bash or 'auto'",
    )

    st.divider()

    # Strict SQL checks (raw .sql)
    config["sql_strict"] = st.checkbox(
        "Strict SQL checks (raw .sql)",
        value=False,
        help="Flag GRANT ALL, DELETE without WHERE, and DROP TABLE in raw .sql",
    )

    # Display current configuration summary
    st.subheader("📊 Current Settings")

    settings_summary = []
    settings_summary.append(
        f"• **Focus:** {config['fail_threshold'].title()} priority and above"
    )
    settings_summary.append(f"• **File limit:** {config['max_file_size_mb']} MB")
    settings_summary.append(f"• **Engine:** {config['engine']}")
    settings_summary.append(f"• **Semgrep packs:** {config['semgrep_packs']}")
    if config["sql_strict"]:
        settings_summary.append("• **SQL strict:** Enabled")

    if config["custom_domains"]:
        settings_summary.append(
            f"• **Custom domains:** {len(config['custom_domains'])} added"
        )

    if config["allow_http"]:
        settings_summary.append("• **HTTP:** Allowed ⚠️")
    else:
        settings_summary.append("• **HTTP:** Blocked ✅")

    for setting in settings_summary:
        st.caption(setting)

    # Reset button
    if st.button("🔄 Reset to Defaults", help="Reset all settings to default values"):
        for key in list(st.session_state.keys()):
            if key.startswith("config_"):
                del st.session_state[key]
        st.rerun()

    return config


def validate_domains(domains: List[str]) -> List[str]:
    valid_domains = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        if " " in domain:
            st.warning(f"⚠️ Invalid domain (contains space): '{domain}'")
            continue
        if domain.startswith("http"):
            st.warning(f"⚠️ Domain should not include protocol: '{domain}'")
            domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        valid_domains.append(domain)
    return valid_domains
