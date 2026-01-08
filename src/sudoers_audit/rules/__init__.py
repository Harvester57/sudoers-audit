from typing import List
from .base import AuditRule, PathRule
from .commands import (
    AllCommandRule,
    WildcardRule,
    RecursiveOperationRule,
    RelativePathRule,
)
from .privileges import NopasswdRule, FullPrivilegeRule, NegationRule, AuthenticateRule
from .environment import EnvKeepRule
from .defaults import SudoDefaultsRule
from .risky_binaries import RiskyBinariesRule
from .permissions import FileOwnerRule, FileWriteRule, ParentDirectoryRule


def get_all_rules() -> List[AuditRule]:
    return [
        AllCommandRule(),
        WildcardRule(),
        RecursiveOperationRule(),
        RelativePathRule(),
        NopasswdRule(),
        FullPrivilegeRule(),
        NegationRule(),
        AuthenticateRule(),
        EnvKeepRule(),
        SudoDefaultsRule(),
        RiskyBinariesRule(),
    ]


def get_all_path_rules() -> List[PathRule]:
    return [
        FileOwnerRule(),
        FileWriteRule(),
        ParentDirectoryRule(),
    ]
