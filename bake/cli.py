"""Command-line interface for bake."""

import logging
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from . import __version__
from .config import Config
from .core.formatter import MakefileFormatter
from .utils.version_utils import (
    VersionError,
    check_for_updates,
    is_development_install,
    update_package,
)

app = typer.Typer(
    name="bake",
    help="Format and lint Makefiles according to best practices.",
    no_args_is_help=True,
)
console = Console()


def get_console(config: Optional[Config] = None) -> Console:
    """Get console with appropriate configuration."""
    if config and not config.wrap_error_messages:
        # Disable line wrapping for better IDE integration
        return Console(width=None, legacy_windows=False)
    return console


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"mbake version {__version__}")

        # Check for updates (non-blocking)
        try:
            update_available, latest_version, _ = check_for_updates()
            if update_available and latest_version:
                console.print(f"[dim]💡 New version available: v{latest_version}[/dim]")
                console.print("[dim]   Run 'bake update' to upgrade[/dim]")
        except Exception:
            # Silently ignore update check errors when showing version
            pass

        raise typer.Exit()


# Add version option to the main app
@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Main callback for version handling."""
    pass


DEFAULT_CONFIG = """# mbake configuration file
# Generated with: bake init

# Global settings
debug = false
verbose = false

# Error message formatting
gnu_error_format = true  # Use GNU standard error format (file:line: Error: message)
wrap_error_messages = false  # Wrap long error messages (can interfere with IDE parsing)

[formatter]
# Indentation settings
use_tabs = true
tab_width = 4

# Spacing settings
space_around_assignment = true
space_before_colon = false
space_after_colon = true

# Line continuation settings
normalize_line_continuations = true
max_line_length = 120

# PHONY settings
group_phony_declarations = true
phony_at_top = true
auto_insert_phony_declarations = false

# General settings
remove_trailing_whitespace = true
ensure_final_newline = true
normalize_empty_lines = true
max_consecutive_empty_lines = 2
fix_missing_recipe_tabs = true
"""


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file (default: ~/.bake.toml)."
    ),
) -> None:
    """Initialize configuration file with defaults."""
    config_path = config_file or Path.home() / ".bake.toml"

    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration already exists at {config_path}[/yellow]")
        console.print("Use [bold]--force[/bold] to overwrite")
        console.print("Run [bold]bake config[/bold] to view current settings")
        return

    try:
        config_path.write_text(DEFAULT_CONFIG)
        console.print(
            f"[green]✓[/green] Created configuration at [bold]{config_path}[/bold]"
        )
        console.print("\nNext steps:")
        console.print("  • Edit the config file to customize formatting rules")
        console.print("  • Run [bold]bake config[/bold] to view current settings")
        console.print(
            "  • Run [bold]bake format Makefile[/bold] to format your first file"
        )
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to create config: {e}")
        raise typer.Exit(1) from e


@app.command()
def config(
    show_path: bool = typer.Option(False, "--path", help="Show config file path."),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file."
    ),
) -> None:
    """Show current configuration."""
    config_path = config_file or Path.home() / ".bake.toml"

    if show_path:
        console.print(str(config_path))
        return

    if not config_path.exists():
        console.print(f"[red]Configuration file not found at {config_path}[/red]")
        console.print("Run [bold]bake init[/bold] to create one with defaults")
        raise typer.Exit(1)

    try:
        config = Config.load(config_file)
        console.print(f"[bold]Configuration from {config_path}[/bold]\n")

        # Display config settings
        console.print("[bold cyan]Formatter Settings:[/bold cyan]")

        settings = [
            ("use_tabs", config.formatter.use_tabs, "Use tabs for indentation"),
            ("tab_width", config.formatter.tab_width, "Tab width in spaces"),
            (
                "space_around_assignment",
                config.formatter.space_around_assignment,
                "Add spaces around = := += ?=",
            ),
            (
                "space_before_colon",
                config.formatter.space_before_colon,
                "Add space before target colon",
            ),
            (
                "space_after_colon",
                config.formatter.space_after_colon,
                "Add space after target colon",
            ),
            (
                "normalize_line_continuations",
                config.formatter.normalize_line_continuations,
                "Clean up line continuations",
            ),
            (
                "max_line_length",
                config.formatter.max_line_length,
                "Maximum line length",
            ),
            (
                "group_phony_declarations",
                config.formatter.group_phony_declarations,
                "Group .PHONY declarations",
            ),
            (
                "phony_at_top",
                config.formatter.phony_at_top,
                "Place .PHONY at top of file",
            ),
            (
                "auto_insert_phony_declarations",
                config.formatter.auto_insert_phony_declarations,
                "Auto-insert .PHONY declarations",
            ),
            (
                "remove_trailing_whitespace",
                config.formatter.remove_trailing_whitespace,
                "Remove trailing whitespace",
            ),
            (
                "ensure_final_newline",
                config.formatter.ensure_final_newline,
                "Ensure file ends with newline",
            ),
            (
                "normalize_empty_lines",
                config.formatter.normalize_empty_lines,
                "Normalize empty lines",
            ),
            (
                "max_consecutive_empty_lines",
                config.formatter.max_consecutive_empty_lines,
                "Max consecutive empty lines",
            ),
            (
                "fix_missing_recipe_tabs",
                config.formatter.fix_missing_recipe_tabs,
                "Fix recipe lines missing tab separator",
            ),
        ]

        for name, value, desc in settings:
            console.print(
                f"  [cyan]{name:<30}[/cyan] [green]{str(value):<8}[/green] [dim]{desc}[/dim]"
            )

        console.print("\n[bold]Global Settings[/bold]")
        console.print(f"  debug: {config.debug}")
        console.print(f"  verbose: {config.verbose}")
        console.print(f"  gnu_error_format: {config.gnu_error_format}")
        console.print(f"  wrap_error_messages: {config.wrap_error_messages}")

    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to load config: {e}")
        raise typer.Exit(1) from e


@app.command()
def validate(
    files: list[Path] = typer.Argument(..., help="Makefile(s) to validate."),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output."
    ),
) -> None:
    """Validate Makefile syntax using GNU make."""
    setup_logging(verbose)

    try:
        Config.load_or_default(
            config_file, explicit=config_file is not None
        )  # Just check config is valid

        any_errors = False

        for file_path in files:
            if not file_path.exists():
                console.print(f"[red]Error:[/red] File not found: {file_path}")
                any_errors = True
                continue

            # Validate syntax using make
            try:
                result = subprocess.run(
                    ["make", "-f", str(file_path), "--dry-run", "--just-print"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    console.print(f"[green]✓[/green] {file_path}: Valid syntax")
                else:
                    console.print(f"[red]✗[/red] {file_path}: Invalid syntax")
                    if result.stderr:
                        console.print(f"  [dim]{result.stderr.strip()}[/dim]")
                    any_errors = True

            except subprocess.TimeoutExpired:
                console.print(f"[yellow]?[/yellow] {file_path}: Validation timed out")
            except FileNotFoundError:
                console.print(
                    f"[yellow]?[/yellow] {file_path}: 'make' not found - skipping syntax validation"
                )

        if any_errors:
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {e}")
        raise typer.Exit(2) from e


@app.command()
def format(
    files: list[Path] = typer.Argument(..., help="Makefile(s) to format."),
    check: bool = typer.Option(
        False,
        "--check",
        "-c",
        help="Check formatting rules without making changes.",
    ),
    diff: bool = typer.Option(
        False, "--diff", "-d", help="Show diff of changes that would be made."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output."
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output."),
    config_file: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file (default: ~/.bake.toml)."
    ),
    backup: bool = typer.Option(
        False, "--backup", "-b", help="Create backup files before formatting."
    ),
    validate_syntax: bool = typer.Option(
        False, "--validate", help="Validate syntax after formatting."
    ),
) -> None:
    """Format Makefiles according to style rules (use 'validate' command for syntax checking)."""
    setup_logging(verbose, debug)

    try:
        # Load configuration with fallback to defaults
        config = Config.load_or_default(config_file, explicit=config_file is not None)
        config.verbose = verbose or config.verbose
        config.debug = debug or config.debug

        # Get appropriately configured console
        output_console = get_console(config)

        # Initialize formatter
        formatter = MakefileFormatter(config)

        # Process files with progress indication
        any_changed = False
        any_errors = False

        with console.status("Processing files...") as status:
            for i, file_path in enumerate(files):
                status.update(f"Processing {file_path.name} ({i + 1}/{len(files)})")

                if not file_path.exists():
                    output_console.print(
                        f"[red]Error:[/red] File not found: {file_path}"
                    )
                    any_errors = True
                    continue

                # Create timestamped backup if requested
                if backup and not check:
                    from datetime import datetime

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = file_path.with_suffix(
                        f"{file_path.suffix}.{timestamp}.bak"
                    )
                    backup_path.write_text(file_path.read_text(encoding="utf-8"))
                    if verbose:
                        output_console.print(
                            f"[dim]Created backup: {backup_path}[/dim]"
                        )

                # Show diff if requested
                if diff:
                    original_content = file_path.read_text(encoding="utf-8")
                    formatted_lines, errors = formatter.format_lines(
                        original_content.splitlines()
                    )
                    formatted_content = "\n".join(formatted_lines)
                    if (
                        config.formatter.ensure_final_newline
                        and not formatted_content.endswith("\n")
                    ):
                        formatted_content += "\n"

                    if formatted_content != original_content:
                        console.print(f"\n[bold]Diff for {file_path}:[/bold]")
                        # Simple diff display
                        original_lines = original_content.splitlines()
                        formatted_lines_list = formatted_content.splitlines()

                        for orig, fmt in zip(original_lines, formatted_lines_list):
                            if orig != fmt:
                                console.print(f"[red]- {orig}[/red]")
                                console.print(f"[green]+ {fmt}[/green]")
                    continue

                # Format file
                changed, errors = formatter.format_file(file_path, check_only=check)

                if errors:
                    any_errors = True
                    for error in errors:
                        if config.gnu_error_format:
                            # GNU standard format: filename:line: Error: message
                            if ":" in error and error.split(":")[0].isdigit():
                                # Error already has line number, prepend filename
                                output_console.print(f"[red]{file_path}:{error}[/red]")
                            else:
                                # Error doesn't have line number, add generic format
                                output_console.print(
                                    f"[red]{file_path}: Error: {error}[/red]"
                                )
                        else:
                            # Traditional format
                            output_console.print(f"[red]Error:[/red] {error}")

                if changed:
                    any_changed = True
                    if check:
                        output_console.print(
                            f"[yellow]Would reformat:[/yellow] {file_path}"
                        )
                    else:
                        output_console.print(f"[green]Formatted:[/green] {file_path}")

                        # Validate syntax if requested
                        if validate_syntax:
                            try:
                                result = subprocess.run(
                                    ["make", "-f", str(file_path), "--dry-run"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5,
                                )
                                if result.returncode != 0:
                                    output_console.print(
                                        "[red]Warning:[/red] Formatted file has syntax errors"
                                    )
                                    any_errors = True
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                pass  # Skip validation if make not available

                elif verbose:
                    output_console.print(f"[dim]Already formatted:[/dim] {file_path}")

        # Show summary
        if len(files) > 1:
            output_console.print(
                f"\n[bold]Summary:[/bold] Processed {len(files)} files"
            )
            if any_changed:
                action = "would be reformatted" if check else "reformatted"
                output_console.print(f"[green]✓[/green] Files {action}")

        # Exit with appropriate code
        if any_errors:
            raise typer.Exit(2)  # Error
        elif check and any_changed:
            raise typer.Exit(1)  # Check failed
        else:
            return  # Success

    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print(
            "[yellow]Hint:[/yellow] Run [bold]bake init[/bold] to create a configuration file"
        )
        raise typer.Exit(1) from None
    except typer.Exit:
        # Re-raise typer exits without wrapping them
        raise
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {e}")
        if debug:
            console.print_exception()
        raise typer.Exit(2) from None


@app.command()
def update(
    force: bool = typer.Option(
        False, "--force", help="Force update even if up to date."
    ),
    check_only: bool = typer.Option(False, "--check", help="Only check, don't update."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Update mbake to the latest version from PyPI."""
    if check_only:
        console.print("🔍 Checking for updates...", style="dim")

        try:
            update_available, latest_version, current_ver = check_for_updates()

            if update_available and latest_version:
                console.print("[green]✨ Update available![/green]")
                console.print(f"Current version: [yellow]{current_ver}[/yellow]")
                console.print(f"Latest version:  [green]{latest_version}[/green]")

                if is_development_install():
                    console.print(
                        "\n[yellow]Note:[/yellow] You appear to be using a development installation."
                    )
                    console.print(
                        "Consider updating your local repository and reinstalling."
                    )
                else:
                    console.print("\nTo update, run: [bold]bake update[/bold]")

            elif latest_version is None:
                console.print(
                    "[yellow]⚠️[/yellow] Unable to check for updates (network error)"
                )
                console.print("Check your internet connection and try again later.")
            else:
                console.print(f"[green]✅ You're up to date![/green] (v{current_ver})")

        except VersionError as e:
            console.print(f"[red]Error checking version:[/red] {e}")
            raise typer.Exit(1) from e
        return

    console.print("🔍 Checking for updates...", style="dim")

    try:
        update_available, latest_version, current_ver = check_for_updates()

        if latest_version is None:
            console.print("[red]❌ Unable to check for updates[/red]")
            console.print("Check your internet connection and try again later.")
            raise typer.Exit(1)

        if not update_available and not force:
            console.print(f"[green]✅ Already up to date![/green] (v{current_ver})")
            return

        # Check if this is a development install
        if is_development_install():
            console.print("[yellow]⚠️ Development installation detected[/yellow]")
            console.print("This appears to be an editable/development installation.")
            console.print(
                "Please update manually by pulling the latest changes and reinstalling:"
            )
            console.print("  git pull")
            console.print("  pip install -e .")
            return

        if update_available:
            console.print("[green]✨ Update available![/green]")
            console.print(f"Current version: [yellow]{current_ver}[/yellow]")
            console.print(f"Latest version:  [green]{latest_version}[/green]")
        else:
            console.print(
                f"[yellow]Forcing update...[/yellow] (current: v{current_ver})"
            )

        # Confirmation prompt
        if not yes:
            proceed = typer.confirm(
                f"Do you want to update mbake to v{latest_version}?"
            )
            if not proceed:
                console.print("Update cancelled.")
                return

        # Perform update
        console.print("📦 Updating mbake...", style="dim")

        with console.status("Installing update..."):
            success = update_package("mbake")

        if success:
            console.print(
                f"[green]🎉 Successfully updated to v{latest_version}![/green]"
            )
            console.print(
                "\n[dim]Note: You may need to restart your terminal or reload your shell for changes to take effect.[/dim]"
            )
        else:
            console.print("[red]❌ Update failed[/red]")
            console.print(
                "Try updating manually with: [bold]pip install --upgrade mbake[/bold]"
            )
            raise typer.Exit(1)

    except VersionError as e:
        console.print(f"[red]Error during update:[/red] {e}")
        raise typer.Exit(1) from e


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
