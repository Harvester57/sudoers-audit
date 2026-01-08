import re


def clean_command_string(command_part: str) -> str:
    """
    Strips sudo-specific prefixes (e.g., RunAs, tags, overrides) from a command string.
    Returns the cleaned command string.
    """
    clean_command_part = command_part.strip()

    # Iteratively strip prefixes until no change
    while True:
        original = clean_command_part
        # Strip RunAs
        clean_command_part = re.sub(r"^\([\w\:\.\-]+\)\s+", "", clean_command_part)
        # Strip sudo tags (e.g. NOPASSWD:, EXEC:, SETENV:)
        clean_command_part = re.sub(r"^[A-Z_]+:\s*", "", clean_command_part)
        # Strip overrides (e.g. !requiretty, env_reset)
        clean_command_part = re.sub(r"^\![\w]+(?:$|\s+)", "", clean_command_part)
        clean_command_part = re.sub(
            r"^\w+=\w+(?:$|\s+)", "", clean_command_part
        )  # Key=value settings

        if clean_command_part == original:
            break

    return clean_command_part
