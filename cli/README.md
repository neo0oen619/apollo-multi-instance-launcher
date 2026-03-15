# Apollo CLI Tools

Command-line utilities for managing Apollo multi-instance streaming.

## Tools

### screenshot.py
Capture screenshot from specified monitor.

**Usage:**
```bash
python cli/screenshot.py [monitor_index]
```

**Example:**
```bash
python cli/screenshot.py 0  # Capture monitor 0
python cli/screenshot.py 1  # Capture monitor 1
```

**Output:** `screenshot_monitor{N}_{TIMESTAMP}.png`

**Requirements:** mss (installed automatically) or pyautogui

---

### moonlight_status.py
Check status of all Apollo instances.

**Usage:**
```bash
python cli/moonlight_status.py
```

**Output:**
```
Apollo Instance Status:
----------------------------------------
  Port 47990: [UP]
  Port 48090: [UP]
  Port 48190: [DOWN]
----------------------------------------
Total: 2/5 instances running
```

---

### launch_background.py
Launch all Apollo instances in background (headless mode).

**Usage:**
```bash
python cli/launch_background.py
```

**Notes:**
- Launches without GUI window
- Instances run on configured ports
- See moonlight_status.py to verify startup

---

## Quick Start

```bash
# Install dependencies (if not already done)
pip install mss requests

# Launch Apollo in background
python cli/launch_background.py

# Check status
python cli/moonlight_status.py

# Take a screenshot
python cli/screenshot.py 0
```

---

## Troubleshooting

**"Port X: DOWN"**
- Check if apollo_multi_launcher.py is running
- Run `python cli/launch_background.py` to start instances

**"Monitor N not found"**
- Check available monitors: `python -c "import mss; m = mss.mss(); print(len(m.monitors) - 1)"`
- Use valid index (0-based)

**Screenshot quality**
- Ensure native resolution and refresh rate are set in Apollo config
