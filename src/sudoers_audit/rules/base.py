from typing import Protocol, List
import os


class AuditRule(Protocol):
    def check(self, line: str) -> List[str]: ...


class PathRule(Protocol):
    def check_path(
        self, path: str, stat_info: "os.stat_result | None" = None
    ) -> List[str]: ...
