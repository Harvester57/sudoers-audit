import os
import stat
from typing import List
from .base import PathRule


class FileOwnerRule(PathRule):
    def check_path(self, path: str) -> List[str]:
        try:
            st = os.stat(path)
            if st.st_uid != 0:
                return [
                    f"CRITICAL: File '{path}' is not owned by root (owner uid: {st.st_uid}). Mutable by non-root."
                ]
        except OSError:
            pass  # Handled by error catching in parent or unlikely here if exists checked
        return []


class FileWriteRule(PathRule):
    def check_path(self, path: str) -> List[str]:
        issues = []
        try:
            st = os.stat(path)
            if st.st_mode & stat.S_IWGRP:
                issues.append(
                    f"CRITICAL: File '{path}' is writable by group. Potential for modification."
                )
            if st.st_mode & stat.S_IWOTH:
                issues.append(
                    f"CRITICAL: File '{path}' is writable by others. Potential for modification."
                )
        except OSError:
            pass
        return issues


class ParentDirectoryRule(PathRule):
    def check_path(self, path: str) -> List[str]:
        issues = []
        parent_dir = os.path.dirname(path)
        if os.path.exists(parent_dir):
            try:
                parent_st = os.stat(parent_dir)
                if parent_st.st_uid != 0:
                    issues.append(
                        f"HIGH: Parent directory '{parent_dir}' is not owned by root. Risk of file replacement."
                    )
                if parent_st.st_mode & stat.S_IWOTH:
                    issues.append(
                        f"HIGH: Parent directory '{parent_dir}' is writable by others. Risk of file replacement."
                    )
            except OSError:
                pass
        return issues
