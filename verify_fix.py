from sudoers_audit.rules.risky_binaries import RiskyBinariesRule
from sudoers_audit.rules.commands import RelativePathRule


def test_risky_binaries_regression():
    rule = RiskyBinariesRule()

    # Case 1: Standard NOPASSWD prefix
    line = "user ALL=(ALL:ALL) NOPASSWD: /bin/sh"
    findings = rule.check(line)
    print(f"Findings for '{line}': {findings}")
    assert len(findings) > 0, f"Failed to detect risky binary in '{line}'"
    assert "GTFOBins" in findings[0]

    # Case 2: RunAs prefix stripping check
    # command_part here would be "(ALL) /bin/bash"
    line2 = "user2 ALL=(ALL) (ALL) /bin/bash"
    findings2 = rule.check(line2)
    print(f"Findings for '{line2}': {findings2}")
    assert len(findings2) > 0, f"Failed to detect risky binary in '{line2}'"

    # Case 3: Simple case
    line3 = "user ALL=(ALL) /bin/vi"
    findings3 = rule.check(line3)
    print(f"Findings for '{line3}': {findings3}")
    assert len(findings3) > 0, f"Failed to detect risky binary in '{line3}'"


def test_relative_path_regression():
    rule = RelativePathRule()

    # Case 1: Relative path with prefixes
    line = "user ALL=(ALL) NOPASSWD: relative/path"
    findings = rule.check(line)
    print(f"Findings for '{line}': {findings}")
    assert len(findings) > 0, f"Failed to detect relative path in '{line}'"
    assert "Relative path detected" in findings[0]

    # Case 2: Absolute path (should be clean)
    line_clean = "user ALL=(ALL) NOPASSWD: /absolute/path"
    findings_clean = rule.check(line_clean)
    print(f"Findings for '{line_clean}': {findings_clean}")
    assert len(findings_clean) == 0, f"False positive for '{line_clean}'"


if __name__ == "__main__":
    try:
        test_risky_binaries_regression()
        test_relative_path_regression()
        print("\nAll regression tests passed!")
    except AssertionError as e:
        print(f"\nTest failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        exit(1)
