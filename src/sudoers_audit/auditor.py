import re
import os
from dataclasses import dataclass, field


@dataclass
class Finding:
    line_number: int
    line_content: str
    issues: list[str]


@dataclass
class FileAuditResult:
    file_path: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class SudoersAuditor:
    """
    Auditor for sudoers files to detect security risks.
    """

    def __init__(self):
        from .rules import get_all_rules, get_all_path_rules

        self.rules = get_all_rules()
        self.path_rules = get_all_path_rules()

    def analyze_line(self, line_num: int, line: str) -> list[str]:
        """
        Analyze a single line for security issues.
        """
        issues = []
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            return issues

        for rule in self.rules:
            issues.extend(rule.check(line))

        return issues

    def check_file_permissions(self, path: str) -> list[str]:
        """
        Check file system permissions for a given path.
        """
        issues = []
        try:
            if not os.path.isabs(path):
                return issues

            if not os.path.exists(path):
                issues.append(
                    f"LOW: Referenced file '{path}' not found on this system."
                )
                return issues

            for rule in self.path_rules:
                issues.extend(rule.check_path(path))

        except OSError as e:
            issues.append(f"WARNING: Could not check permissions for '{path}': {e}")

        return issues

    def audit_file(
        self, filepath: str, check_permissions: bool = False
    ) -> FileAuditResult:
        """
        Audit a specific file and return findings.
        """
        result = FileAuditResult(file_path=filepath)

        try:
            with open(filepath, "r") as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                # Handle continued lines (trailing \)
                if line.strip().endswith("\\"):
                    pass

                issues = self.analyze_line(i + 1, line)

                if check_permissions and "=" in line:
                    # Extract command path
                    parts = line.split("=", 1)
                    if len(parts) > 1:
                        cmd_part = parts[1].strip()
                        # Simple extraction: binary is the first token
                        # This works for "ALL = /bin/ls"
                        # But also "ALL = (ALL) /bin/ls"
                        # We need to handle optional (RunAs)

                        cmd_path = cmd_part
                        # Remove RunAs (user:group) or (user)
                        cmd_path = re.sub(r"^\([\w\:\.\-]+\)\s+", "", cmd_path)
                        # Take the first token as the binary
                        cmd_path = cmd_path.split(" ")[0]

                        if cmd_path.startswith("/"):
                            perm_issues = self.check_file_permissions(cmd_path)
                            issues.extend(perm_issues)

                if issues:
                    result.findings.append(
                        Finding(
                            line_number=i + 1, line_content=line.strip(), issues=issues
                        )
                    )

        except PermissionError:
            result.error = "Permission denied. Run with sudo?"
        except FileNotFoundError:
            result.error = "File not found."
        except Exception as e:
            result.error = f"Error reading file: {str(e)}"

        return result
