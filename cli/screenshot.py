#!/usr/bin/env python3
"""Screenshot utility for Apollo multi-instance setup."""

import sys
import os
from datetime import datetime
from pathlib import Path

try:
    import mss
    HAS_MSS = True
except ImportError:
    HAS_MSS = False
    import pyautogui


def take_screenshot(monitor: int = 0) -> str:
    """Capture screenshot from specified monitor."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"screenshot_monitor{monitor}_{timestamp}.png"

    try:
        if HAS_MSS:
            # Multi-monitor support with mss
            with mss.mss() as sct:
                if monitor < len(sct.monitors):
                    monitor_obj = sct.monitors[monitor + 1]  # +1 to skip primary aggregate
                    screenshot = sct.grab(monitor_obj)
                    mss.tools.to_png(screenshot.rgb, screenshot.size, output=filename)
                else:
                    return f"✗ Monitor {monitor} not found (available: {len(sct.monitors) - 1})"
        else:
            # Fallback to pyautogui (primary monitor only)
            import pyautogui
            pyautogui.screenshot(filename)

        return f"[OK] Saved: {filename}"
    except Exception as e:
        return f"[ERROR] {e}"


if __name__ == "__main__":
    monitor = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    result = take_screenshot(monitor)
    print(result)
    sys.exit(0 if "Saved" in result else 1)
