"""Shell completion script generation for mbake."""

import sys
from enum import Enum
from pathlib import Path
from typing import Optional


class ShellType(str, Enum):
    """Supported shell types for completion generation."""

    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"


def get_command_name() -> str:
    """Get the command name to use for completions.

    This checks user preferences and build configuration to determine
    which command name should be used for completions.
    """
    from .config import get_active_command_name

    return get_active_command_name()


def get_bash_completion(command_name: str) -> str:
    """Get bash completion script for the specified command name."""
    return f"""# bash completion for {command_name}

_{command_name}_completion() {{
    local cur prev opts cmds
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    
    # Available commands
    cmds="init config validate format update completions"
    
    # Available options for main command
    opts="--version --help"
    
    # Command-specific options
    case "${{prev}}" in
        init)
            COMPREPLY=( $(compgen -W "--force --config --help" -- "${{cur}}") )
            return 0
            ;;
        config)
            COMPREPLY=( $(compgen -W "--path --config --help" -- "${{cur}}") )
            return 0
            ;;
        validate)
            COMPREPLY=( $(compgen -W "--config --verbose -v --help" -- "${{cur}}") )
            return 0
            ;;
        format)
            COMPREPLY=( $(compgen -W "--check -c --diff -d --verbose -v --debug --config --backup -b --validate --stdin --help" -- "${{cur}}") )
            return 0
            ;;
        update)
            COMPREPLY=( $(compgen -W "--force --check --yes -y --help" -- "${{cur}}") )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish --help" -- "${{cur}}") )
            return 0
            ;;
        --config)
            # Complete with files
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;
        --version|--help)
            return 0
            ;;
    esac
    
    # If completing the command itself
    if [[ ${{cur}} == * ]] ; then
        COMPREPLY=( $(compgen -W "${{cmds}} ${{opts}}" -- "${{cur}}") )
        return 0
    fi
}}

complete -F _{command_name}_completion {command_name}
"""


def get_zsh_completion(command_name: str) -> str:
    """Get zsh completion script for the specified command name."""
    return f"""#compdef {command_name}

_{command_name}() {{
    local -a commands options format_opts validate_opts shell_opts
    commands=(
        'format:Format Makefiles according to style rules'
        'validate:Validate Makefile syntax using GNU make'
        'init:Initialize configuration file with defaults'
        'config:Show current configuration'
        'update:Update {command_name} to the latest version'
        'completions:Generate shell completion scripts'
    )
    format_opts=(
        '--check[Check formatting rules without making changes]'
        '--diff[Show diff of changes that would be made]'
        '--backup[Create backup files before formatting]'
        '--validate[Validate syntax after formatting]'
        '--verbose[Enable verbose output]'
        '--config[Path to configuration file]'
        '--stdin[Read from stdin and write to stdout]'
    )
    validate_opts=(
        '--verbose[Enable verbose output]'
        '--config[Path to configuration file]'
    )
    shell_opts=(
        'bash:Generate Bash completion script'
        'zsh:Generate Zsh completion script'
        'fish:Generate Fish completion script'
    )

    _arguments -C \
        '--version[Show version and exit]' \
        '--help[Show help message and exit]' \
        '1: :_describe "command" commands' \
        '*:: :->args'

    case $state in
        args)
            case $words[1] in
                format)
                    _arguments $format_opts
                    ;;
                validate)
                    _arguments $validate_opts
                    ;;
                completions)
                    _describe 'shell' shell_opts
                    ;;
            esac
            ;;
    esac
}}

_{command_name}
"""


def get_fish_completion(command_name: str) -> str:
    """Get fish completion script for the specified command name."""
    return f"""
complete -c {command_name} -f

# Main commands
complete -c {command_name} -n "__fish_use_subcommand" -a format -d "Format Makefiles according to style rules"
complete -c {command_name} -n "__fish_use_subcommand" -a validate -d "Validate Makefile syntax using GNU make"
complete -c {command_name} -n "__fish_use_subcommand" -a init -d "Initialize configuration file with defaults"
complete -c {command_name} -n "__fish_use_subcommand" -a config -d "Show current configuration"
complete -c {command_name} -n "__fish_use_subcommand" -a update -d "Update {command_name} to the latest version"
complete -c {command_name} -n "__fish_use_subcommand" -a completions -d "Generate shell completion scripts"

# Global options
complete -c {command_name} -n "__fish_use_subcommand" -l version -d "Show version and exit"
complete -c {command_name} -n "__fish_use_subcommand" -l help -d "Show help message and exit"

# Format command options
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l check -d "Check formatting rules without making changes"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l diff -d "Show diff of changes that would be made"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l backup -d "Create backup files before formatting"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l validate -d "Validate syntax after formatting"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l verbose -d "Enable verbose output"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l config -d "Path to configuration file"
complete -c {command_name} -n "__fish_seen_subcommand_from format" -l stdin -d "Read from stdin and write to stdout"

# Validate command options
complete -c {command_name} -n "__fish_seen_subcommand_from validate" -l verbose -d "Enable verbose output"
complete -c {command_name} -n "__fish_seen_subcommand_from validate" -l config -d "Path to configuration file"

# Completions command options
complete -c {command_name} -n "__fish_seen_subcommand_from completions" -a "bash" -d "Generate Bash completion script"
complete -c {command_name} -n "__fish_seen_subcommand_from completions" -a "zsh" -d "Generate Zsh completion script"
complete -c {command_name} -n "__fish_seen_subcommand_from completions" -a "fish" -d "Generate Fish completion script"
"""


def get_completion_script(shell: ShellType) -> str:
    """Get the completion script for the specified shell."""
    # Always generate completions for mbake since that's the actual command
    # User aliases will work with mbake completions automatically
    if shell == ShellType.BASH:
        return get_bash_completion("mbake").strip()
    elif shell == ShellType.ZSH:
        return get_zsh_completion("mbake").strip()
    elif shell == ShellType.FISH:
        return get_fish_completion("mbake").strip()
    else:
        raise ValueError(f"Unsupported shell: {shell}")


def write_completion_script(
    shell: ShellType, output_file: Optional[Path] = None
) -> None:
    """Write completion script to a file or stdout."""
    script = get_completion_script(shell)
    if output_file:
        output_file.write_text(script + "\n")
    else:
        sys.stdout.write(script + "\n")
