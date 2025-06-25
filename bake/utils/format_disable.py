"""Utility for handling format disable/enable regions."""

import re
from dataclasses import dataclass
from re import Pattern


@dataclass
class FormatRegion:
    """Represents a region where formatting is disabled."""

    start_line: int  # 0-based line index
    end_line: int  # 0-based line index (exclusive)
    original_lines: list[str]  # Original lines in the region


class FormatDisableHandler:
    """Handles format disable/enable regions in Makefile content."""

    def __init__(self) -> None:
        # Pattern to match format disable comments
        self.disable_pattern: Pattern[str] = re.compile(
            r"^\s*#\s*bake-format\s+off\b", re.IGNORECASE
        )
        # Pattern to match format enable comments
        self.enable_pattern: Pattern[str] = re.compile(
            r"^\s*#\s*bake-format\s+on\b", re.IGNORECASE
        )

    def find_disabled_regions(self, lines: list[str]) -> list[FormatRegion]:
        """Find all regions where formatting is disabled.

        Args:
            lines: List of lines to scan

        Returns:
            List of FormatRegion objects representing disabled regions
        """
        regions = []
        i = 0

        while i < len(lines):
            line = lines[i]

            # Check for format disable comment
            if self.disable_pattern.match(line):
                start_line = i
                # Find the corresponding enable comment
                end_line = len(lines)  # Default to end of file

                for j in range(i + 1, len(lines)):
                    if self.enable_pattern.match(lines[j]):
                        end_line = j + 1  # Include the enable comment line
                        break

                # Store the original lines for this region
                original_lines = lines[start_line:end_line]
                regions.append(FormatRegion(start_line, end_line, original_lines))

                # Move past this region
                i = end_line
            else:
                i += 1

        return regions

    def apply_disabled_regions(
        self,
        original_lines: list[str],
        formatted_lines: list[str],
        disabled_regions: list[FormatRegion],
    ) -> list[str]:
        """Apply the original content back to disabled regions.

        Args:
            original_lines: Original unformatted lines
            formatted_lines: Formatted lines
            disabled_regions: List of regions to preserve

        Returns:
            Lines with disabled regions restored to original content
        """
        if not disabled_regions:
            return formatted_lines

        result = formatted_lines.copy()

        # Apply regions in reverse order to maintain correct indices
        for region in reversed(disabled_regions):
            # Replace the region with original content
            result[region.start_line : region.end_line] = region.original_lines

        return result

    def is_format_disabled_line(self, line: str) -> bool:
        """Check if a line is a format disable/enable comment.

        Args:
            line: Line to check

        Returns:
            True if the line is a format control comment
        """
        return (
            self.disable_pattern.match(line) is not None
            or self.enable_pattern.match(line) is not None
        )
