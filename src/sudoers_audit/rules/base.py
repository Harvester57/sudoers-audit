from typing import Protocol, List
from dataclasses import dataclass
import os


@dataclass
class AuditResult:
    issues: List[str]


class AuditRule(Protocol):
    def check(self, line: str) -> List[str]: ...


class PathRule(Protocol):
    def check_path(
        self, path: str, stat_info: "os.stat_result | None" = None
    ) -> List[str]: ...
