import os
import sys
import pytest
from unittest.mock import patch

# Ensure src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from sudoers_audit.cli import main


@pytest.fixture
def scan_dir_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "data/scan_dir"))


def test_cli_directory_scan(scan_dir_path, capsys):
    """Test that the CLI correctly scans a directory and finds issues in multiple files."""

    # Mock sys.argv
    test_args = ["sudoers-audit", scan_dir_path]
    with patch.object(sys, "argv", test_args):
        try:
            main()
        except SystemExit:
            # main() might not exit, but if it does (e.g. error), catch it.
            # In successful run without --output, it prints and returns None (implicit)
            pass

    captured = capsys.readouterr()
    output = captured.out

    # Check that both files were scanned
    assert "clean.sudoers" in output
    assert "malicious.sudoers" in output

    # Check for specific findings
    # clean.sudoers has "root ALL=(ALL:ALL) ALL" -> CRITICAL: 'ALL' command granted
    assert "CRITICAL: 'ALL' command granted" in output

    # malicious.sudoers has "user ALL=(ALL) NOPASSWD: /bin/sh" -> WARNING: 'NOPASSWD' tag used
    assert "WARNING: 'NOPASSWD' tag used" in output
