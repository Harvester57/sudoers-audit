import re
from typing import List
from .base import AuditRule


class NopasswdRule(AuditRule):
    def check(self, line: str) -> List[str]:
        if "NOPASSWD:" in line:
            return ["WARNING: 'NOPASSWD' tag used. Allows usage without password."]
        return []


class FullPrivilegeRule(AuditRule):
    def check(self, line: str) -> List[str]:
        issues = []
        if re.search(r"\(ALL(?::ALL)?\)\s+ALL", line):
            issues.append("HIGH: 'ALL=(ALL) ALL' grant. Grants full root acts.")
        if re.search(r"\(ALL(?::ALL)?\)\s+(?!ALL)", line) and "=" in line:
            # Check if it's not (ALL) ALL
            issues.append(
                "MEDIUM: 'ALL' User (RunAs) granted. User can impersonate any account."
            )
        return issues


class NegationRule(AuditRule):
    def check(self, line: str) -> List[str]:
        if ", !" in line or "!/" in line:
            return [
                "HIGH: Negation rule '!' detected. Deny-lists are ineffective against symlinks/relative paths."
            ]
        return []


class AuthenticateRule(AuditRule):
    def check(self, line: str) -> List[str]:
        if "!authenticate" in line:
            return [
                "CRITICAL: '!authenticate' detected. Globally disables authentication."
            ]
        return []
