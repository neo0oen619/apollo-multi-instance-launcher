#!/usr/bin/env python3
"""Launch Apollo instances in background."""

import subprocess
import sys
import os


def launch_background():
    """Start Apollo launcher in background mode."""
    launcher_path = os.path.join(os.path.dirname(__file__), "..", "apollo_multi_launcher.py")

    try:
        # Use Popen to launch without blocking
        subprocess.Popen([sys.executable, launcher_path, "--background"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
        print("[OK] Launched Apollo instances in background")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to launch: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(launch_background())
