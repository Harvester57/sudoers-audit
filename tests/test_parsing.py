import sys
import os

# Ensure src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from sudoers_audit.utils import clean_command_string, split_sudoers_commands


def test_split_commands_simple():
    line = "user ALL = /bin/ls"
    assert split_sudoers_commands(line) == ["/bin/ls"]


def test_split_commands_multiple():
    line = "user ALL = /bin/ls, /bin/cat"
    assert split_sudoers_commands(line) == ["/bin/ls", "/bin/cat"]


def test_split_commands_with_runas_list():
    # Commas inside runas should not split the command
    line = "user ALL = (user1, user2) /bin/ls, (root) /bin/cat"
    split = split_sudoers_commands(line)
    # The first part is "(user1, user2) /bin/ls"
    # The second part is "(root) /bin/cat"
    assert len(split) == 2
    assert split[0] == "(user1, user2) /bin/ls"
    assert split[1] == "(root) /bin/cat"


def test_clean_command_simple():
    assert clean_command_string("/bin/ls") == "/bin/ls"


def test_clean_command_tags():
    assert clean_command_string("NOPASSWD: /bin/ls") == "/bin/ls"
    assert clean_command_string("EXEC: NOPASSWD: /bin/ls") == "/bin/ls"


def test_clean_command_runas():
    assert clean_command_string("(root) /bin/ls") == "/bin/ls"
    assert clean_command_string("(user:group) /bin/ls") == "/bin/ls"
    assert clean_command_string("(user, group) /bin/ls") == "/bin/ls"


def test_clean_command_overrides():
    assert clean_command_string("!requiretty /bin/ls") == "/bin/ls"
    assert clean_command_string("env_reset=true /bin/ls") == "/bin/ls"


def test_clean_command_digest():
    assert clean_command_string("sha224:abcdef123123 /bin/ls") == "/bin/ls"
