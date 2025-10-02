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

    # Engine selection
    config["engine"] = st.selectbox(
        "Scanner Engine",
        options=["builtin", "oss"],
        index=0,
        help="Use built-in rules or open-source tools (Semgrep).",
    )

    # Severity threshold for highlighting
    config["fail_threshold"] = st.selectbox(
        "Priority Focus",
        options=["critical", "high", "medium", "low"],
        index=1,  # Default to "high"
        help="Highlight issues at this severity level and above",
    )

    # File size limit
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

    # Custom allowed domains
    st.write("**Additional Allowed Domains**")
    custom_domains_text = st.text_area(
        "Domains to whitelist (one per line)",
        height=80,
        placeholder="api.mycompany.com\n*.trusted-cdn.net\nlocalhost:8080",
        help="Add domains that should be allowed for network calls",
    )

    config["custom_domains"] = [
        domain.strip() for domain in custom_domains_text.split("\n") if domain.strip()
    ]

    # HTTP policy
    config["allow_http"] = st.checkbox(
        "Allow HTTP (non-HTTPS) requests",
        value=False,
        help="Check to allow plain HTTP requests (not recommended for production)",
    )

    st.divider()

    # Policy Upload
    st.subheader("📋 Custom Policy")

    # Policy file upload
    policy_file = st.file_uploader(
        "Upload custom policy.yaml",
        type=["yaml", "yml"],
        help="Override default security policies",
    )
    config["custom_policy_file"] = policy_file

    # Allowlist file upload
    allowlist_file = st.file_uploader(
        "Upload custom allowlists.yaml",
        type=["yaml", "yml"],
        help="Override default allowlists",
    )
    config["custom_allowlist_file"] = allowlist_file

    if policy_file or allowlist_file:
        st.info("📝 Custom files will override defaults")

    st.divider()

    # Display current configuration summary
    st.subheader("📊 Current Settings")

    settings_summary = []
    settings_summary.append(
        f"• **Focus:** {config['fail_threshold'].title()} priority and above"
    )
    settings_summary.append(f"• **File limit:** {config['max_file_size_mb']} MB")
    settings_summary.append(f"• **Engine:** {config['engine']}")

    if config["custom_domains"]:
        settings_summary.append(
            f"• **Custom domains:** {len(config['custom_domains'])} added"
        )

    if config["allow_http"]:
        settings_summary.append("• **HTTP:** Allowed ⚠️")
    else:
        settings_summary.append("• **HTTP:** Blocked ✅")

    if policy_file:
        settings_summary.append("• **Policy:** Custom file uploaded")

    if allowlist_file:
        settings_summary.append("• **Allowlist:** Custom file uploaded")

    for setting in settings_summary:
        st.caption(setting)

    # Reset button
    if st.button("🔄 Reset to Defaults", help="Reset all settings to default values"):
        # Clear session state for this component
        for key in list(st.session_state.keys()):
            if key.startswith("config_"):
                del st.session_state[key]
        st.rerun()

    return config


def validate_domains(domains: List[str]) -> List[str]:
    """
    Validate and clean domain list

    Args:
        domains: List of domain strings

    Returns:
        List of validated domains
    """
    valid_domains = []

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue

        # Basic validation - just check for obviously invalid patterns
        if " " in domain:
            st.warning(f"⚠️ Invalid domain (contains space): '{domain}'")
            continue

        if domain.startswith("http"):
            st.warning(f"⚠️ Domain should not include protocol: '{domain}'")
            # Try to extract just the domain part
            domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        valid_domains.append(domain)

    return valid_domains


def show_policy_preview(policy_file) -> None:
    """
    Show preview of uploaded policy file

    Args:
        policy_file: Uploaded policy file
    """
    if not policy_file:
        return

    try:
        content = policy_file.getvalue().decode("utf-8")
        with st.expander("👁️ Preview uploaded policy"):
            st.code(content, language="yaml")
    except Exception as e:
        st.error(f"Cannot preview policy file: {e}")


def get_config_help() -> None:
    """Display help information about configuration options"""

    with st.expander("❓ Configuration Help"):
        st.markdown(
            """
        ### Scanner Settings
        - **Priority Focus**: Determines which severity levels are highlighted by default
        - **Max File Size**: Files larger than this will be skipped to avoid performance issues

        ### Network Rules
        - **Custom Domains**: Add your organization's trusted domains
        - **HTTP Policy**: Whether to allow unencrypted HTTP requests

        ### Custom Files
        - **Policy YAML**: Override default security rules and severity levels
        - **Allowlist YAML**: Override default allowed domains and paths

        ### Domain Format Examples
        ```
        api.mycompany.com
        *.cdn.example.org
        localhost:8080
        192.168.1.0/24
        ```
        """
        )


# Add help section to the config panel
def render_config_panel_with_help() -> Dict:
    """Render config panel with integrated help"""
    config = render_config_panel()
    get_config_help()
    return config
