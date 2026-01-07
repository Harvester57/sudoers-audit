import os
import pytest
from sudoers_audit.auditor import SudoersAuditor

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def get_vector_path(filename):
    return os.path.join(DATA_DIR, filename)


@pytest.fixture
def auditor():
    return SudoersAuditor()


def test_clean_sudoers(auditor):
    result = auditor.audit_file(get_vector_path("clean.sudoers"))
    assert result.error is None
    assert len(result.findings) == 0


def test_malicious_nopasswd(auditor):
    result = auditor.audit_file(get_vector_path("malicious_nopasswd.sudoers"))
    assert result.error is None
    assert len(result.findings) > 0
    # Check for specific NOPASSWD warning
    assert any(
        "WARNING: 'NOPASSWD' tag used" in issue
        for finding in result.findings
        for issue in finding.issues
    )


def test_malicious_wildcard(auditor):
    result = auditor.audit_file(get_vector_path("malicious_wildcard.sudoers"))
    assert result.error is None
    assert len(result.findings) > 0
    assert any(
        "HIGH: Wildcard '*' detected" in issue
        for finding in result.findings
        for issue in finding.issues
    )


def test_malicious_all_cmd(auditor):
    result = auditor.audit_file(get_vector_path("malicious_all_cmd.sudoers"))
    assert result.error is None
    assert len(result.findings) > 0
    assert any(
        "CRITICAL: 'ALL' command granted" in issue
        for finding in result.findings
        for issue in finding.issues
    )


def test_malicious_gtfobins(auditor):
    result = auditor.audit_file(get_vector_path("malicious_gtfobins.sudoers"))
    assert result.error is None
    assert len(result.findings) > 0
    # Search for GTFOBins text
    assert any(
        "CRITICAL: GTFOBins detected" in issue
        for finding in result.findings
        for issue in finding.issues
    )

    # Check specifically for vim and bash
    all_issues = [issue for finding in result.findings for issue in finding.issues]
    combined_issues = " ".join(all_issues)
    assert "vim" in combined_issues
    assert "bash" in combined_issues


def test_malicious_mixed(auditor):
    result = auditor.audit_file(get_vector_path("malicious_mixed.sudoers"))
    assert result.error is None
    assert (
        len(result.findings) >= 4
    )  # We expect at least 4 findings based on the file content

    all_issues = [issue for finding in result.findings for issue in finding.issues]
    combined_issues = " ".join(all_issues)

    assert "NOPASSWD" in combined_issues
    assert "Wildcard" in combined_issues
    assert "GTFOBins" in combined_issues
    assert "!requiretty" in combined_issues
    assert "Recursive file operation" in combined_issues
