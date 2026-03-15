#!/usr/bin/env python3
"""Moonlight control skill handler.

This module provides programmatic control over Apollo multi-instance streaming
via Python subprocess calls. Integrates with Claude CLI skill system.
"""

import subprocess
import json
import os
import sys
from pathlib import Path


class MoonlightControl:
    """Control Apollo streaming instances."""

    def __init__(self):
        """Initialize with Apollo repo path from environment or default."""
        # Try environment variable first
        repo_env = os.getenv("APOLLO_REPO")

        if repo_env:
            self.repo_root = Path(repo_env).resolve()
        else:
            # Default to standard location
            self.repo_root = Path("C:/Users/odd61/apollo-multi-instance-launcher").resolve()

        self.cli_dir = self.repo_root / "cli"

        # Validate repo exists
        if not self.cli_dir.exists():
            raise FileNotFoundError(
                f"Apollo repo not found at {self.repo_root}. "
                f"Set APOLLO_REPO environment variable or clone to default location."
            )

    def status(self) -> str:
        """Get status of all Apollo instances.

        Returns:
            str: Formatted status output from moonlight_status.py
        """
        result = subprocess.run(
            [sys.executable, str(self.cli_dir / "moonlight_status.py")],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout if result.stdout else result.stderr

    def screenshot(self, monitor: int = 0) -> str:
        """Take screenshot from specified monitor.

        Args:
            monitor: Monitor index (0-based)

        Returns:
            str: Status message with filename
        """
        result = subprocess.run(
            [sys.executable, str(self.cli_dir / "screenshot.py"), str(monitor)],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout if result.stdout else result.stderr

    def launch(self) -> str:
        """Launch Apollo instances in background.

        Returns:
            str: Status message
        """
        result = subprocess.run(
            [sys.executable, str(self.cli_dir / "launch_background.py")],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout if result.stdout else result.stderr

    def list_profiles(self) -> str:
        """List all configured Apollo profiles.

        Returns:
            str: List of profiles found in ProgramData
        """
        apollo_config_dir = Path("C:\\ProgramData\\ApolloLauncher")

        if not apollo_config_dir.exists():
            return "No Apollo configuration found at C:\\ProgramData\\ApolloLauncher"

        profiles = sorted(apollo_config_dir.glob("*.conf"))

        if not profiles:
            return "No profiles configured yet"

        output = f"Found {len(profiles)} Apollo profile(s):\n"
        for profile_path in profiles:
            output += f"  • {profile_path.name}\n"

        return output


def main():
    """CLI entry point for testing handler directly."""
    if len(sys.argv) < 2:
        print("Usage: handler.py <command> [args]")
        print("Commands: status, screenshot [monitor], launch, list-profiles")
        sys.exit(1)

    try:
        ctrl = MoonlightControl()
        command = sys.argv[1]

        if command == "status":
            print(ctrl.status())
        elif command == "screenshot":
            monitor = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            print(ctrl.screenshot(monitor))
        elif command == "launch":
            print(ctrl.launch())
        elif command == "list-profiles":
            print(ctrl.list_profiles())
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
