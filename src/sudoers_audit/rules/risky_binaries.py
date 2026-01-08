import re
from typing import List
from .base import AuditRule
from ..data import RISKY_BINARIES


class RiskyBinariesRule(AuditRule):
    def check(self, line: str) -> List[str]:
        issues = []
        found_binaries = []

        # Extract just the command part of the sudo rule (after the '=')
        # Skip Defaults lines as they don't contain commands in the same format
        if "=" in line and not line.strip().startswith("Defaults"):
            parts = line.split("=", 1)
            if len(parts) > 1:
                command_part = parts[1]

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

        return issues
