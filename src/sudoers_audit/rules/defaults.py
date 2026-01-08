from typing import List
from .base import AuditRule


class SudoDefaultsRule(AuditRule):
    def check(self, line: str) -> List[str]:
        issues = []
        if "Defaults" in line:
            if "!use_pty" in line:
                issues.append(
                    "MEDIUM: '!use_pty' detected. Risk of TIOCSTI terminal hijacking."
                )
            if "visiblepw" in line:
                issues.append("LOW: 'visiblepw' enabled. Password may be visible.")

        return issues


class RequireTtyRule(AuditRule):
    def check(self, line: str) -> List[str]:
        issues = []
        if "!requiretty" in line:
            issues.append(
                "MEDIUM: '!requiretty' detected. May facilitate automated attacks/scripts."
            )
        return issues
