import re
from typing import List
from .base import AuditRule
from sudoers_audit.utils import clean_command_string


class AllCommandRule(AuditRule):
    def check(self, line: str) -> List[str]:
        if re.search(r"=(?:.*)\s+ALL\s*$", line):
            return ["CRITICAL: 'ALL' command granted. Allows execution of any binary."]
        return []


class WildcardRule(AuditRule):
    def check(self, line: str) -> List[str]:
        issues = []
        if "*" in line:
            # Wildcard in binary path check
            if re.search(r"/\S*\*(?:$|\s)", line.split("=")[1] if "=" in line else ""):
                issues.append(
                    "CRITICAL: Wildcard detected in binary path. Potential for high-risk binary execution."
                )
            else:
                issues.append(
                    "HIGH: Wildcard '*' detected. Potentially vulnerable to argument injection."
                )
        return issues


class RecursiveOperationRule(AuditRule):
    def check(self, line: str) -> List[str]:
        if "cp -r" in line or "chown -R" in line or "chmod -R" in line:
            return [
                "HIGH: Recursive file operation detected. Race condition/Symlink attack risk."
            ]
        return []


class RelativePathRule(AuditRule):
    def check(self, line: str) -> List[str]:
        # Extract just the command part of the sudo rule (after the '=')
        # Skip Defaults lines as they don't contain commands in the same format
        if "=" not in line or line.strip().startswith("Defaults"):
            return []

        parts = line.split("=", 1)
        if len(parts) <= 1:
            return []

        command_part = parts[1]
        clean_command_part = clean_command_string(command_part)

        if not clean_command_part:
            # No command specified, just options
            cmd_start = "ALL"
        else:
            cmd_start = clean_command_part.split(" ")[0]

        if not cmd_start.startswith("/") and cmd_start != "ALL":
            return [
                f"HIGH: Relative path detected for command '{cmd_start}'. Vulnerable to path interception."
            ]

        return []
