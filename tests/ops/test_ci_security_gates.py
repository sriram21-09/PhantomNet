"""
Test suite verifying OPS-02 CI/CD Security Quality Gates.
Enforces that:
1. .github/workflows/security_quality_gates.yml is well-formed YAML.
2. Contains all five mandatory security gates:
   - Gitleaks (Secrets detection)
   - Bandit (Python SAST)
   - Semgrep (OWASP Top 10)
   - pip-audit (CVE dependency checking)
   - Trivy (Container configuration and CVE auditing)
3. Direct execution of Bandit SAST scanner confirms zero High-severity vulnerabilities in production API & services.
"""

import os
import yaml
import pytest
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = ROOT_DIR / ".github" / "workflows" / "security_quality_gates.yml"


@pytest.fixture(scope="module")
def workflow_config():
    assert WORKFLOW_PATH.exists(), f"Workflow file not found at {WORKFLOW_PATH}"
    with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_workflow_structure_and_triggers(workflow_config):
    """Verify workflow triggers on push/PR for main and develop branches."""
    triggers = workflow_config.get("on") or workflow_config.get(True, {})
    assert "push" in triggers or "pull_request" in triggers, "Workflow must trigger on git events"
    push_branches = triggers.get("push", {}).get("branches", [])
    pr_branches = triggers.get("pull_request", {}).get("branches", [])
    assert "main" in push_branches or "main" in pr_branches, "Workflow must monitor main branch"


def test_five_security_gates_defined(workflow_config):
    """Verify that all five required security gates exist as distinct jobs."""
    jobs = workflow_config.get("jobs", {})
    expected_gates = [
        "gitleaks-secret-scan",
        "bandit-sast",
        "semgrep-owasp",
        "pip-audit-cve",
        "trivy-container-scan",
    ]
    for gate in expected_gates:
        assert gate in jobs, f"Mandatory security gate '{gate}' missing from workflow jobs"


def test_local_bandit_sast_on_production_code():
    """Run local Bandit SAST audit against backend/api and backend/services to verify 0 High vulnerabilities."""
    import bandit
    from bandit.core import config as b_config
    from bandit.core import manager as b_manager

    b_conf = b_config.BanditConfig()
    mgr = b_manager.BanditManager(b_conf, "file")

    # Discover files in backend/api and backend/services
    targets = [
        str(ROOT_DIR / "backend" / "api"),
        str(ROOT_DIR / "backend" / "services"),
    ]
    mgr.discover_files(targets, recursive=True)
    mgr.run_tests()

    # Filter high severity issues
    high_issues = [
        issue for issue in mgr.get_issue_list()
        if issue.severity == "HIGH"
    ]

    assert len(high_issues) == 0, (
        f"Detected {len(high_issues)} HIGH severity vulnerabilities in backend/api and backend/services: "
        f"{[f'{i.test_id}: {i.fname}:{i.lineno} - {i.text}' for i in high_issues]}"
    )
