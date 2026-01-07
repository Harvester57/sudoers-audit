import unittest
from unittest.mock import patch, MagicMock
from sudoers_audit.auditor import SudoersAuditor
import stat


class TestHardeningChecks(unittest.TestCase):
    def setUp(self):
        self.auditor = SudoersAuditor()

    def test_wildcard_in_binary_path(self):
        line = "bob ALL=(ALL) /usr/bin/*"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("Wildcard detected in binary path" in i for i in issues))

    def test_privilege_scope_runas_all(self):
        line = "bob ALL=(ALL:ALL) ALL"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("ALL=(ALL) ALL" in i for i in issues))

    def test_privilege_scope_runas_other(self):
        line = "bob ALL=(ALL) /bin/ls"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("'ALL' User (RunAs) granted" in i for i in issues))

    def test_negation_rule(self):
        line = "bob ALL=(ALL) /bin/ls, !/bin/sh"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("Negation rule '!' detected" in i for i in issues))

    def test_authenticate_disabled(self):
        line = "Defaults:bob !authenticate"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("!authenticate" in i for i in issues))

    def test_env_keep_leakage(self):
        line = 'Defaults env_keep += "LD_PRELOAD"'
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("Risky environment variables" in i for i in issues))

    def test_defaults_issues(self):
        line = "Defaults !use_pty, visiblepw"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("!use_pty" in i for i in issues))
        self.assertTrue(any("visiblepw" in i for i in issues))

    def test_relative_path(self):
        line = "bob ALL=(ALL) script.sh"
        issues = self.auditor.analyze_line(1, line)
        self.assertTrue(any("Relative path detected" in i for i in issues))

    @patch("os.stat")
    @patch("os.path.exists")
    @patch("os.path.isabs")
    def test_permission_checks_bad_owner(self, mock_isabs, mock_exists, mock_stat):
        mock_isabs.return_value = True
        mock_exists.return_value = True
        # Mock stat for file
        file_stat = MagicMock()
        file_stat.st_uid = 1000  # Not root
        file_stat.st_mode = stat.S_IFREG | 0o755

        # Mock stat for parent dir (needed because check accesses parent)
        parent_stat = MagicMock()
        parent_stat.st_uid = 0
        parent_stat.st_mode = stat.S_IFDIR | 0o755

        def side_effect(path):
            if path == "/bin/badowner":
                return file_stat
            return parent_stat

        mock_stat.side_effect = side_effect

        issues = self.auditor.check_file_permissions("/bin/badowner")
        self.assertTrue(any("not owned by root" in i for i in issues))

    @patch("os.stat")
    @patch("os.path.exists")
    @patch("os.path.isabs")
    def test_permission_checks_writable_others(
        self, mock_isabs, mock_exists, mock_stat
    ):
        mock_isabs.return_value = True
        mock_exists.return_value = True

        file_stat = MagicMock()
        file_stat.st_uid = 0
        file_stat.st_mode = stat.S_IFREG | stat.S_IWOTH

        parent_stat = MagicMock()
        parent_stat.st_uid = 0
        parent_stat.st_mode = stat.S_IFDIR | 0o755

        mock_stat.side_effect = (
            lambda p: file_stat if p == "/bin/writable" else parent_stat
        )

        issues = self.auditor.check_file_permissions("/bin/writable")
        self.assertTrue(any("writable by others" in i for i in issues))
