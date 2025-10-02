import os
import tempfile
from typing import List, Optional

from .models import Finding
from .policy import Policy
from .oss_nb_preprocess import preprocess_notebooks


def run_oss_tools(
    root: str,
    policy: Policy,
    tools: List[str],
    semgrep_config: str = "auto",
    files: Optional[List[str]] = None,
) -> List[Finding]:
    targets: List[str] = []
    if files:
        targets = [os.path.abspath(f) for f in files]
    else:
        # If no explicit list, scan the root directory
        targets = [os.path.abspath(root)]

    all_findings: List[Finding] = []

    with tempfile.TemporaryDirectory() as tmp:
        # Preprocess notebooks to additional .py/.sql files
        # Discover notebooks when scanning a directory
        discover_list: List[str] = []
        if files is None and os.path.isdir(root):
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    if fn.endswith((".ipynb", ".py")):
                        discover_list.append(os.path.join(dirpath, fn))
        else:
            discover_list = [p for p in targets if p.endswith((".ipynb", ".py"))]

        generated = preprocess_notebooks(discover_list, tmp)
        combined_files: Optional[List[str]] = None
        # Prefer explicit file list to keep Semgrep scope tight; otherwise, tools can scan root
        if files or generated:
            combined_files = []
            if files:
                combined_files.extend(files)
            combined_files.extend(generated)

        # Run selected tools
        if "semgrep" in tools:
            from .oss_semgrep import scan_with_semgrep

            all_findings.extend(
                scan_with_semgrep(
                    root=root, policy=policy, semgrep_config=semgrep_config, files=combined_files
                )
            )
        if "detect-secrets" in tools:
            from .oss_detect_secrets import scan_with_detect_secrets

            all_findings.extend(
                scan_with_detect_secrets(root=root, policy=policy, files=combined_files)
            )
        if "sqlfluff" in tools:
            from .oss_sqlfluff import scan_with_sqlfluff

            all_findings.extend(
                scan_with_sqlfluff(root=root, policy=policy, files=combined_files)
            )

    return all_findings

