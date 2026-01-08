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
    assert any("CRITICAL: Wildcard detected in binary path" in f for f in findings)


def test_analyze_line_risky_binary(auditor):
    findings = auditor.analyze_line(1, "user ALL=(ALL) /usr/bin/vim")
    assert any("WARNING: GTFOBins detected" in f for f in findings)
    combined_msg = "".join(findings)
    assert "vim: https://gtfobins.github.io/gtfobins/vim/#sudo" in combined_msg


def test_analyze_line_safe(auditor):
    findings = auditor.analyze_line(1, "user ALL=(root) /usr/bin/ls")
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


def test_analyze_line_nopasswd_relative_path(auditor):
    # Regression test for NOPASSWD being mistaken for a relative path
    findings = auditor.analyze_line(1, "user ALL=(ALL) NOPASSWD: /usr/bin/ls")
    # Should NOT have "Relative path detected"
    assert not any("Relative path detected" in f for f in findings)
    # Should have NOPASSWD warning
    assert any("WARNING: 'NOPASSWD' tag used" in f for f in findings)


def test_analyze_line_option_relative_path(auditor):
    # Regression test for options like !requiretty being mistaken for a relative path
    findings = auditor.analyze_line(
        1, "bad_script ALL=(ALL) !requiretty /opt/db/cleanup.sh"
    )
    # Should NOT have "Relative path detected"
    assert not any("Relative path detected" in f for f in findings)
    # Should have !requiretty warning
    assert any("!requiretty" in f for f in findings)


def test_analyze_line_complex_stripping(auditor):
    # Test multiple tags and options
    line = "complex ALL=(ALL) NOPASSWD: EXEC: !requiretty !visiblepw env_reset=true /bin/ls"
    findings = auditor.analyze_line(1, line)
    # Should NOT have "Relative path detected"
    assert not any("Relative path detected" in f for f in findings)
    # Should have NOPASSWD warning
    assert any("WARNING: 'NOPASSWD' tag used" in f for f in findings)
    # Should have !requiretty warning
    assert any("!requiretty" in f for f in findings)


def test_analyze_line_option_relative_path_no_command(auditor):
    # Regression test for options like !requiretty being mistaken for a relative path
    findings = auditor.analyze_line(1, "bad_script ALL=(ALL) !requiretty")
    # Should NOT have "Relative path detected"
    assert not any("Relative path detected" in f for f in findings)
    # Should have !requiretty warning
    assert any("!requiretty" in f for f in findings)


def test_analyze_line_risky_binary_runas_stripping(auditor):
    # Regression test for RunAs prefix stripping check (e.g. (ALL) (ALL))
    findings = auditor.analyze_line(1, "user2 ALL=(ALL) (ALL) /bin/bash")
    assert any("WARNING: GTFOBins detected" in f for f in findings)
    combined_msg = "".join(findings)
    assert "bash: https://gtfobins.github.io/gtfobins/bash/#sudo" in combined_msg


def test_analyze_line_relative_path_with_nopasswd(auditor):
    # Regression test for relative path with NOPASSWD prefix
    findings = auditor.analyze_line(1, "user ALL=(ALL) NOPASSWD: relative/path")
    assert any("HIGH: Relative path detected" in f for f in findings)
    assert any("WARNING: 'NOPASSWD' tag used" in f for f in findings)


def test_analyze_line_risky_binary_with_nopasswd(auditor):
    # Regression test for risky binary with NOPASSWD prefix
    findings = auditor.analyze_line(1, "user ALL=(ALL:ALL) NOPASSWD: /bin/sh")
    assert any("WARNING: GTFOBins detected" in f for f in findings)
    assert any("WARNING: 'NOPASSWD' tag used" in f for f in findings)
    combined_msg = "".join(findings)
    assert "sh: https://gtfobins.github.io/gtfobins/sh/#sudo" in combined_msg
