import re
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
        if not line or line.startswith('#'):
            return issues

        # 1. Detection of 'ALL' command grant
        if re.search(r'=(?:.*)\s+ALL\s*$', line):
            issues.append("CRITICAL: 'ALL' command granted. Allows execution of any binary.")

        # 2. Detection of NOPASSWD
        if "NOPASSWD:" in line:
            issues.append("WARNING: 'NOPASSWD' tag used. Removes authentication barrier.")

        # 3. Detection of Wildcards in path or arguments
        if "*" in line:
            issues.append("HIGH: Wildcard '*' detected. Vulnerable to path traversal/argument injection.")

        # 4. Detection of Risky Binaries
        found_binaries = []
        
        # Extract just the command part of the sudo rule (after the '=')
        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) > 1:
                command_part = parts[1]
                
                # Check against every risky binary
                for binary in RISKY_BINARIES:
                    # Regex Explanation:
                    # 1. (?:^|\/|\s) -> Match start of string, a forward slash, or whitespace
                    # 2. binary     -> The binary name
                    # 3. (?:\s|$)   -> Match whitespace or end of string
                    pattern = r'(?:^|\/|\s){}(?:\s|$)'.format(re.escape(binary))
                    if re.search(pattern, command_part):
                        found_binaries.append(binary)

        if found_binaries:
            issues.append(f"CRITICAL: GTFOBins detected ({', '.join(found_binaries)}). Known shell escape/privesc vectors.")

        # 5. Detection of !requiretty
        if "!requiretty" in line:
            issues.append("MEDIUM: '!requiretty' detected. May facilitate automated attacks/scripts.")

        # 6. Recursive Directory Operations
        if "cp -r" in line or "chown -R" in line or "chmod -R" in line:
            issues.append("HIGH: Recursive file operation detected. Race condition/Symlink attack risk.")

        return issues

    def audit_file(self, filepath: str) -> FileAuditResult:
        """
        Audit a specific file and return findings.
        """
        result = FileAuditResult(file_path=filepath)
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines):
                # Handle continued lines (trailing \)
                # Logic kept simple here as before
                if line.strip().endswith('\\'):
                    pass 
                    
                issues = self.analyze_line(i + 1, line)
                if issues:
                    result.findings.append(Finding(
                        line_number=i + 1,
                        line_content=line.strip(),
                        issues=issues
                    ))
                    
        except PermissionError:
            result.error = "Permission denied. Run with sudo?"
        except FileNotFoundError:
            result.error = "File not found."
        except Exception as e:
            result.error = f"Error reading file: {str(e)}"

        return result
