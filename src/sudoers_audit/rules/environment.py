from typing import List
from .base import AuditRule


class EnvKeepRule(AuditRule):
    def check(self, line: str) -> List[str]:
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
                return [
                    f"HIGH: Risky environment variables in env_keep: {', '.join(found_envs)}. Potential for code injection/MITM."
                ]
        return []
