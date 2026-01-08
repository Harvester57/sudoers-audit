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
        clean_command_part = re.sub(
            r"^\([\w\:\.\-,\s]+\)\s+", "", clean_command_part
        )  # Updated to include commas and spaces
        # Strip sudo tags (e.g. NOPASSWD:, EXEC:, SETENV:)
        clean_command_part = re.sub(r"^[A-Z_]+:\s*", "", clean_command_part)
        # Strip overrides (e.g. !requiretty, env_reset)
        clean_command_part = re.sub(r"^\![\w]+(?:$|\s+)", "", clean_command_part)
        clean_command_part = re.sub(
            r"^\w+=\w+(?:$|\s+)", "", clean_command_part
        )  # Key=value settings
        # Strip digests (sha224:...)
        clean_command_part = re.sub(
            r"^[a-z0-9]+:[a-zA-Z0-9+/=]+\s+", "", clean_command_part
        )

        if clean_command_part == original:
            break

    return clean_command_part


def split_sudoers_commands(line: str) -> list[str]:
    """
    Splits a sudoers rule line into a list of individual commands.
    Handles lines like:
    user host = /bin/cmd1, /bin/cmd2
    user host = (user) /bin/cmd1, /bin/cmd2

    Returns a list of command strings (e.g. ["/bin/cmd1", "/bin/cmd2"])
    Note: The returned strings may still contain tags/RunAs specifiers.
    """
    if "=" not in line:
        return []

    # Simple split on first = to get RHS
    _, rhs = line.split("=", 1)
    rhs = rhs.strip()

    # Sudoers doesn't support quoting for command lists in a way that shlex handles perfectly
    # (commas are separators unless escaped).
    # But a simple split by comma is usually sufficient UNLESS there are commas inside parens (RunAs).
    # E.g. user ALL = (root, bin) /bin/ls, /bin/cat

    commands = []
    current_command = []
    paren_depth = 0

    for char in rhs:
        if char == "(":
            paren_depth += 1
            current_command.append(char)
        elif char == ")":
            if paren_depth > 0:
                paren_depth -= 1
            current_command.append(char)
        elif char == "," and paren_depth == 0:
            # Split point
            cmd_str = "".join(current_command).strip()
            if cmd_str:
                commands.append(cmd_str)
            current_command = []
        else:
            current_command.append(char)

    # Append last command
    cmd_str = "".join(current_command).strip()
    if cmd_str:
        commands.append(cmd_str)

    return commands
