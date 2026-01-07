import re
import os
import stat
from dataclasses import dataclass, field
from .data import RISKY_BINARIES


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

    def analyze_line(self, line_num: int, line: str) -> list[str]:
        """
        Analyze a single line for security issues.
        """
        issues = []
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            return issues

        # 1. Detection of 'ALL' command grant
        if re.search(r"=(?:.*)\s+ALL\s*$", line):
            issues.append(
                "CRITICAL: 'ALL' command granted. Allows execution of any binary."
            )

        # 2. Detection of NOPASSWD
        if "NOPASSWD:" in line:
            issues.append(
                "WARNING: 'NOPASSWD' tag used. Allows usage without password."
            )

        # 3. Detection of Wildcards in path or arguments
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

        # 4. Privilege Scope: RunAs ALL or Negation rules
        if re.search(r"\(ALL(?::ALL)?\)\s+ALL", line):
            issues.append("HIGH: 'ALL=(ALL) ALL' grant. Grants full root acts.")
        if re.search(r"\(ALL(?::ALL)?\)\s+(?!ALL)", line) and "=" in line:
            # Check if it's not (ALL) ALL
            issues.append(
                "MEDIUM: 'ALL' User (RunAs) granted. User can impersonate any account."
            )

        if ", !" in line or "!/" in line:
            issues.append(
                "HIGH: Negation rule '!' detected. Deny-lists are ineffective against symlinks/relative paths."
            )

        # 5. Authentication: !authenticate
        if "!authenticate" in line:
            issues.append(
                "CRITICAL: '!authenticate' detected. Globally disables authentication."
            )

        # 6. Environment Variable Leakage
        if "env_keep" in line:
            risky_envs = [
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "PYTHONPATH",
                "PERL5LIB",
                "RUBYLIB",
                "http_proxy",
            ]
            found_envs = [env for env in risky_envs if env in line]
            if found_envs:
                issues.append(
                    f"HIGH: Risky environment variables in env_keep: {', '.join(found_envs)}. Potential for code injection/MITM."
                )

        # 7. Sudo Configuration Defaults
        if "Defaults" in line:
            if "!use_pty" in line:
                issues.append(
                    "MEDIUM: '!use_pty' detected. Risk of TIOCSTI terminal hijacking."
                )
            if "visiblepw" in line:
                issues.append("LOW: 'visiblepw' enabled. Password may be visible.")
            # Missing logfile is hard to detect in a single line context without state, skipping for line-by-line analysis for now or would need full file context.

        # 8. Detection of Risky Binaries
        found_binaries = []

        # Extract just the command part of the sudo rule (after the '=')
        # Skip Defaults lines as they don't contain commands in the same format
        if "=" in line and not line.strip().startswith("Defaults"):
            parts = line.split("=", 1)
            if len(parts) > 1:
                command_part = parts[1]

                # Check for relative paths
                clean_command_part = command_part.strip()

                # Iteratively strip prefixes until no change
                while True:
                    original = clean_command_part
                    # Strip RunAs
                    clean_command_part = re.sub(
                        r"^\([\w\:\.\-]+\)\s+", "", clean_command_part
                    )
                    # Strip sudo tags (e.g. NOPASSWD:, EXEC:, SETENV:)
                    clean_command_part = re.sub(r"^[A-Z_]+:\s*", "", clean_command_part)
                    # Strip overrides (e.g. !requiretty, env_reset)
                    clean_command_part = re.sub(
                        r"^\![\w]+(?:$|\s+)", "", clean_command_part
                    )
                    clean_command_part = re.sub(
                        r"^\w+=\w+(?:$|\s+)", "", clean_command_part
                    )  # Key=value settings

                    if clean_command_part == original:
                        break

                if not clean_command_part:
                    # No command specified, just options
                    cmd_start = "ALL"
                else:
                    cmd_start = clean_command_part.split(" ")[0]

                if not cmd_start.startswith("/") and cmd_start != "ALL":
                    issues.append(
                        f"HIGH: Relative path detected for command '{cmd_start}'. Vulnerable to path interception."
                    )

                # Check against every risky binary
                for binary in RISKY_BINARIES:
                    # Regex Explanation:
                    # 1. (?:^|\/|\s) -> Match start of string, a forward slash, or whitespace
                    # 2. binary     -> The binary name
                    # 3. (?:\s|$)   -> Match whitespace or end of string
                    pattern = r"(?:^|\/|\s){}(?:\s|$)".format(re.escape(binary))
                    if re.search(pattern, command_part):
                        found_binaries.append(binary)

        if found_binaries:
            # Format: binary: URL
            binaries_with_urls = [f"{b}: {RISKY_BINARIES[b]}" for b in found_binaries]
            issues.append(
                f"WARNING: GTFOBins detected ({', '.join(binaries_with_urls)}). Known shell escape/privesc vectors."
            )

        # 9. Detection of !requiretty
        if "!requiretty" in line:
            issues.append(
                "MEDIUM: '!requiretty' detected. May facilitate automated attacks/scripts."
            )

        # 10. Recursive Directory Operations
        if "cp -r" in line or "chown -R" in line or "chmod -R" in line:
            issues.append(
                "HIGH: Recursive file operation detected. Race condition/Symlink attack risk."
            )

        return issues

    def check_file_permissions(self, path: str) -> list[str]:
        """
        Check file system permissions for a given path.
        """
        issues = []
        try:
            if not os.path.isabs(path):
                # We can't robustly check relative paths without knowing CWD context of execution,
                # but we can try if it exists relative to CWD or just skip/warn.
                # The regex check already warns about relative paths.
                return issues

            if not os.path.exists(path):
                # Warning is enough, might be a valid command not on this system
                issues.append(
                    f"LOW: Referenced file '{path}' not found on this system."
                )
                return issues

            st = os.stat(path)

            # Check 1: Owner should be root (uid 0)
            if st.st_uid != 0:
                issues.append(
                    f"CRITICAL: File '{path}' is not owned by root (owner uid: {st.st_uid}). Mutable by non-root."
                )

            # Check 2: Writable by Group or Others
            if st.st_mode & stat.S_IWGRP:
                issues.append(
                    f"CRITICAL: File '{path}' is writable by group. Potential for modification."
                )
            if st.st_mode & stat.S_IWOTH:
                issues.append(
                    f"CRITICAL: File '{path}' is writable by others. Potential for modification."
                )

            # Check 3: Parent Directory Permissions
            parent_dir = os.path.dirname(path)
            if os.path.exists(parent_dir):
                parent_st = os.stat(parent_dir)
                if parent_st.st_uid != 0:
                    issues.append(
                        f"HIGH: Parent directory '{parent_dir}' is not owned by root. Risk of file replacement."
                    )
                if parent_st.st_mode & stat.S_IWOTH:
                    issues.append(
                        f"HIGH: Parent directory '{parent_dir}' is writable by others. Risk of file replacement."
                    )

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
