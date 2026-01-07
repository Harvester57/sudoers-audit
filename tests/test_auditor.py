import pytest
import sys
import os

# Ensure src is in path so we can import sudoers_audit without installation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from sudoers_audit.auditor import SudoersAuditor


@pytest.fixture
def auditor():
    return SudoersAuditor()


def test_analyze_line_all(auditor):
    findings = auditor.analyze_line(1, "root ALL=(ALL:ALL) ALL")
    assert any("CRITICAL: 'ALL' command granted" in f for f in findings)


def test_analyze_line_nopasswd(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) NOPASSWD: /bin/ls")
    assert any("WARNING: 'NOPASSWD' tag used" in f for f in findings)


def test_analyze_line_wildcard(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) /usr/bin/*")
    assert any("HIGH: Wildcard '*' detected" in f for f in findings)


def test_analyze_line_risky_binary(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) /usr/bin/vim")
    assert any("WARNING: GTFOBins detected" in f for f in findings)
    assert "vim: https://gtfobins.github.io/gtfobins/vim/#sudo" in findings[0]


def test_analyze_line_safe(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) /usr/bin/ls")
    # ls is not in the risky list
    assert not findings


def test_analyze_line_multiple_risky(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) /usr/bin/vim /usr/bin/bash")
    # Both vim and bash are risky
    combined_msg = "".join(findings)
    assert "vim: https://gtfobins.github.io/gtfobins/vim/#sudo" in combined_msg
    assert "bash: https://gtfobins.github.io/gtfobins/bash/#sudo" in combined_msg


def test_audit_file(auditor, tmp_path):
    d = tmp_path / "sudoers"
    d.write_text("root ALL=(ALL:ALL) ALL\n")

    result = auditor.audit_file(str(d))

    assert result.file_path == str(d)
    assert not result.error
    assert len(result.findings) > 0
    assert any(
        "CRITICAL: 'ALL' command granted" in issue
        for finding in result.findings
        for issue in finding.issues
    )
