"""Shell command indicators for context-based detection."""

# POSIX shell built-ins - universal commands available in all POSIX shells
SHELL_COMMAND_INDICATORS = {
    "echo",
    "cd",
    "exit",
    "pwd",
    "true",
    "false",
    "test",
    "exec",
    "set",
    "export",
    "unset",
    "shift",
    "read",
    "break",
    "continue",
    "eval",
    "trap",
    "return",
    "wait",
    "times",
    "umask",
    "ulimit",
}
