# Moonlight Control Skill

Control Apollo streaming instances for Moonlight remote desktop.

## Overview

This skill provides unified control over Apollo multi-instance streaming through Claude CLI. Monitor status, capture screenshots, and manage profiles without leaving the command line.

## Commands

### status
Show status of all Apollo instances across configured ports.

```
claude-code moonlight-control:status
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

### screenshot [monitor]
Capture screenshot from specified monitor (default: 0).

```
claude-code moonlight-control:screenshot 0
claude-code moonlight-control:screenshot 1
```

**Output:**
```
✓ Saved: screenshot_monitor1_20260315_112045.png
```

---

### launch
Start all Apollo instances in background.

```
claude-code moonlight-control:launch
```

**Output:**
```
✓ Launched Apollo instances in background
```

---

### list-profiles
List all configured Apollo profiles and their ports.

```
claude-code moonlight-control:list-profiles
```

---

## Requirements

- Apollo instances available (configured via apollo_multi_launcher.py)
- Port accessibility (localhost)
- Python 3.8+
- Dependencies: mss, requests, psutil

## Integration

This skill requires the `apollo-multi-instance-launcher` repository to be cloned locally. Set the `APOLLO_REPO` environment variable to point to the repository root:

```bash
export APOLLO_REPO=/path/to/apollo-multi-instance-launcher
```

If not set, defaults to: `C:/Users/odd61/apollo-multi-instance-launcher`

## Implementation Details

- **Status:** Checks HTTP ports 47990, 48090, 48190, 48290, 48390
- **Screenshot:** Uses mss library for multi-monitor capture
- **Launch:** Spawns apollo_multi_launcher.py with --background flag
- **Profiles:** Reads from `C:\ProgramData\ApolloLauncher\` configuration

## Examples

```bash
# Check if Apollo is running
claude-code moonlight-control:status

# If down, launch instances
claude-code moonlight-control:launch

# Wait 5 seconds, check again
sleep 5 && claude-code moonlight-control:status

# Capture monitor 0 for verification
claude-code moonlight-control:screenshot 0
```

## Troubleshooting

**"Port X: DOWN"**
- Apollo not running. Execute `moonlight-control:launch`

**"Monitor N not found"**
- Invalid monitor index. Check available monitors with `moonlight-control:list-profiles`

**"APOLLO_REPO not found"**
- Set environment variable or ensure repository is in default location
