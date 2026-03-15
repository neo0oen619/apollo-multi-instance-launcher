
<img width="1113" height="434" alt="{CDE4F7F3-B876-49EE-8BD3-C64E9DD72789}" src="https://github.com/user-attachments/assets/c53bbbc3-e8e9-4b6a-9769-00a28c571222" />

<img width="1122" height="675" alt="{FFC97B36-05D7-4034-9301-D3650A1A5912}" src="https://github.com/user-attachments/assets/9d81193e-76fc-4927-b4ad-7124fd6d495c" />


# Apollo Multi-Instance Launcher (a.k.a. "Why run one Sunshine when you can juggle several?")

- **Apollo** by **ClassicOldSong**: https://github.com/ClassicOldSong/Apollo  

Welcome to a small GUI that keeps Apollo/Sunshine wrangled on Windows. It builds one sandbox per profile, rewrites configs, and launches **multiple Apollo/Sunshine instances on the same PC under the same Windows user**—each instance isolated so your setup doesn’t dissolve into shared logs and shared sins.

A single instance of Sunshine is like a single cookie—useless once the family arrives. We automate the second, third, and yes… fifth cookie.

## What “multi-instance” means here
One machine, one user session, **multiple independent Apollo/Sunshine processes**:
- Instance A can be configured to stream Monitor 1.
- Instance B can be configured to stream Monitor 2.
- Instance C can be configured to stream Monitor 3.
…and nobody tramples each other’s runtime files, ports, TLS keys, or logs.

(You’re not creating new Windows users or “seats” in the OS sense—just **separate Apollo/Sunshine instances** with separate runtimes.)

## Feature Primer
- **One PC / One User / Many Instances** – Run multiple Apollo/Sunshine instances under the **same Windows user**, each with its own isolated runtime.
- **Multi-Monitor Friendly** – Make separate instances and aim them at different screens (2nd/3rd/4th monitor) via per-profile settings/config.
- **Profile Sandboxing** – Each profile gets unique filenames (`apps_[slug].json`, `sunshine_state_[slug].json`, etc.) inside `C:\ProgramData\ApolloLauncher\runtime`.
- **Per-Profile Config Rendering** – Each profile writes its own rendered config (`<slug>.conf`) so every instance can point at its own files, name, ports, and display settings.
- **Clean Slate Creation** – On first launch we seed brand-new JSON with fresh salts, UUIDs, and empty app lists. If the files already exist, we leave them alone.
- **Port-Family Aware Multi-Instance** – Apollo/Sunshine `port = ...` is a **base port** that expands into a **family of TCP/UDP ports**. The launcher checks the whole family before launch to avoid collisions.
- **Safe Base-Port Spacing** – Base ports auto-space by `SUNSHINE_PORT_STRIDE` (default: `100`) so multiple instances don’t fight over neighbors like `48000` / `48010`.
- **Correct Web UI Shortcut** – “Open Web UI” uses `https://localhost:(base port + 1)` (because the UI typically lives there).
- **Silent Launch** – Hides the Sunshine console by default for current-user launches. Toggle it off if you miss blinking cursors.
- **Tray / Background Mode** – Optional system tray support:
  - `--tray` = close-to-tray behavior
  - `--background` = start hidden in tray
- **Easy Administrator Launch (Windows)** – `--elevate` relaunches the launcher with UAC. Also includes `ApolloLauncher_Admin.cmd` for double-click convenience.
- **Dependency Auto-Heal** – Missing `PySide6` or `psutil`? The launcher self-installs them via `pip` and tattles via MessageBox when the network is gone.
- **Logging** – Every session logs to `C:\ProgramData\ApolloLauncher\logs\launcher_YYYYMMDD_HHMMSS.log`.
- **Optional Runtime Cleanup** – Deleting a profile politely asks if you want its runtime folder nuked too.

---

## CLI Tools

Command-line utilities are provided in the `cli/` directory for automated control and monitoring.

### screenshot.py
Capture screenshot from specified monitor.

```bash
python cli/screenshot.py 0  # Monitor 0
python cli/screenshot.py 1  # Monitor 1
```

Output: `screenshot_monitor{N}_{TIMESTAMP}.png`

### moonlight_status.py
Check status of all Apollo instances.

```bash
python cli/moonlight_status.py
```

Output:
```
Apollo Instance Status:
----------------------------------------
  Port 47990: [UP]
  Port 48090: [UP]
  Port 48190: [DOWN]
----------------------------------------
Total: 2/5 instances running
```

### launch_background.py
Launch all instances in headless mode.

```bash
python cli/launch_background.py
```

See `cli/README.md` for detailed documentation.

---

## Moonlight Remote Desktop Setup

Stream Apollo instances to Moonlight clients over LAN using NVIDIA NVENC hardware encoding.

### Quick Setup (5 Minutes)

**On Host PC (This One):**
1. Run GUI launcher: `python apollo_multi_launcher.py`
2. Create profile per monitor (Screen1 → port 47989, Screen2 → 48089, etc.)
3. Open `http://localhost:47990` → Configuration → Video:
   - Encoder: **NVENC**
   - Codec: **H.265/HEVC**
   - Bitrate: **50 Mbps** (adjust for your LAN)
4. Enable pairing for each instance

**On Client PC (Moonlight 100.70.191.47):**
1. Open Moonlight Desktop
2. Add host: `<HOST_IP>:47990`
3. Apollo shows PIN → enter in Moonlight
4. Stream any profile → verify display appears
5. Test mouse/keyboard input

### Port Allocation

| Instance | Port | Web UI | Display |
|----------|------|--------|---------|
| Screen 1 | 47989 | 47990  | Monitor 0 |
| Screen 2 | 48089 | 48090  | Monitor 1 |
| Screen 3 | 48189 | 48190  | Monitor 2 |

Port stride: `+100` per instance (configurable)

### Configuration Template

A reference configuration is available at `configs/apollo-nvenc-template.conf`. Copy and customize for your setup:

```bash
cp configs/apollo-nvenc-template.conf my-profile.conf
# Edit my-profile.conf with your bitrate, codecs, etc.
```

### Troubleshooting

**"Moonlight can't connect"**
- Verify Apollo instances are running: `python cli/moonlight_status.py`
- Check firewall allows TCP/UDP on Apollo ports (47989+)
- Ensure client has network path to host

**"Lag or frame drops"**
- Reduce bitrate in Apollo settings
- Check LAN speed: target 50-100 Mbps for 1080p@60
- Switch to H.264 if H.265 unsupported on client

**"Black screen after pairing"**
- Verify monitor index matches Apollo profile
- Restart instance: `python apollo_multi_launcher.py` → right-click profile → Restart

### Network Requirements

- **LAN:** Host and client must be on same network (or routable IP)
- **Bandwidth:** 50 Mbps minimum for 1080p@60 (hardware dependent)
- **Latency:** <30 ms ideal (100+ ms starts feeling sluggish)

---

## Claude CLI Integration (Swarm Skill)

Control Apollo from Claude CLI using the `moonlight-control` skill.

```bash
# Check status
claude-code moonlight-control:status

# Take screenshot
claude-code moonlight-control:screenshot 0

# Launch instances
claude-code moonlight-control:launch

# List profiles
claude-code moonlight-control:list-profiles
```

See `skills/moonlight-control/skill.md` for full documentation.

To enable: set `APOLLO_REPO` environment variable:
```bash
export APOLLO_REPO=$(pwd)
```

---

## Installation (Windows)
```powershell
# Optional: use a virtualenv if you’re into healthy habits
python -m pip install --upgrade pip
python -m pip install PySide6 psutil
```

Then launch the GUI:
```powershell
python apolloluncher.py
```

If you double-click the script without dependencies present, it will attempt to install them automatically and display a Windows message box when it can’t.

---

## Quick Start: Multiple Monitors on the Same PC (same user, multiple instances)
Want one Windows login to stream multiple monitors to multiple Moonlight clients?

1. Hit **New** and name the profile (e.g. `Instance-1`, `Instance-2`, `Couch`, `Desk2`, `The Third Monitor™`).
2. Launcher auto-detects `sunshine.exe` and `sunshine.conf` from `C:\Program Files\Apollo\` (adjust in settings if yours lives elsewhere).
3. In the profile editor, pick the **target monitor/display** for this instance (2nd, 3rd, …) if your build supports it.
4. Choose a **base port** (or let the launcher auto-space it).
5. Launch the instance.
6. Click **Open Web UI** → configure apps/settings for that instance.
7. Repeat for each monitor you want to stream.

Result: multiple Apollo/Sunshine instances, all under the same Windows user, each mapped to its own runtime + ports (and optionally its own monitor).

---

## Creating Profiles
1. Hit **New** and name the profile.
2. Launcher auto-detects `sunshine.exe` and `sunshine.conf` from `C:\Program Files\Apollo\`.
3. Unique filenames are generated for `apps`, `state`, `credentials`, `log`, `pkey`, and `cert`.
4. First launch writes clean JSON + empty log.
5. Subsequent launches reuse whatever the instance created through the Web UI.

---

## Launching Instances
- **Silent Launch** (default): Sunshine runs without a console window; output goes to the per-profile log in runtime.
- **Open Web UI**: Opens `https://localhost:(base port + 1)` for the selected instance.
- **Check Ports**: Verifies the required TCP/UDP port family for that instance (not just a single port).
- **Same User, Separate Instances**: Each instance is isolated by profile/runtime—so you can run multiple instances without shared-state collisions.
- **Run-As / Admin**:
  - By default, profiles launch as the current user.
  - Use **Edit** to configure advanced options (paths, ports, display selection, console visibility, etc.).
  - If you need Admin (firewall rules, privileged paths, etc.), launch the launcher with `--elevate` or use `ApolloLauncher_Admin.cmd`.

---

## Ports & Collisions (aka “why 48000 keeps yelling at you”)
In Apollo/Sunshine, `port = X` is a **base port**, not “one port”. It fans out into a **family** of ports (TCP + UDP).  
That means two instances with base ports that are “close” can still collide and fail to bind (classic symptoms: errors about `48000` / `48010` and friends).

The launcher helps by:
- checking the whole port family before launch
- spacing base ports using `SUNSHINE_PORT_STRIDE` (default `100`)
- suggesting a safe base port if something is already taken

If Windows Firewall is enabled, you may need to allow the required TCP/UDP ports for each instance base port.

---

## CLI Flags (optional but handy)
```powershell
# Tray icon + close-to-tray behavior
python apolloluncher.py --tray

# Start hidden in tray
python apolloluncher.py --background

# Relaunch the launcher as Administrator (UAC prompt)
python apolloluncher.py --elevate
```

---

## File Layout
```
C:\ProgramData\ApolloLauncher\
 ├─ profiles.json                 # saved profiles
 ├─ logs\launcher_*.log           # session logs
 └─ runtime\<profile-slug>\
      ├─ apps_<slug>.json
      ├─ sunshine_state_<slug>.json
      ├─ credentials_<slug>.json
      ├─ sunshine_<slug>.log
      ├─ pkey_<slug>.pem
      ├─ cert_<slug>.pem
      └─ <slug>.conf              # rendered config
```

Delete a profile → choose whether to keep or remove this runtime folder.

---

## Troubleshooting
| Symptom | Fix |
| --- | --- |
| “ModuleNotFoundError: PySide6” | Launcher auto-installs, but if offline run `pip install PySide6`. |
| “Couldn't bind … port 48000 / 48010 / etc.” | Your instances’ **port families** overlap. Increase the base port, rely on auto-spacing (`SUNSHINE_PORT_STRIDE`), or use **Check Ports** to get a safe suggestion. |
| Web UI looks “wrong” / stuck login page | Make sure you opened `https://localhost:(base port + 1)` for *that* instance. |
| Two instances “show the same screen” | Edit the profiles and ensure each one targets a different monitor/display setting, then relaunch. |

---

## FAQ
**Q: Can we run more than two Suns?**  
A: Yes. Sunshine is the star; we’re just the stage crew.

**Q: Can the same Windows user run multiple instances and stream multiple monitors at once?**  
A: Yep. That’s the whole point: **multiple isolated instances** under the same user, each with its own runtime + ports, and (optionally) its own target display.

**Q: Why the jokes?**  
A: Because if you’re launching multiple headless GPUs at 3 AM, humor is the only thing preventing registry edits.

**Q: Does this work on Linux/macOS?**  
A: Most logic is cross-platform, but the GUI focus and silent launch polish target Windows. Patches welcome.

---

## Contributing & Logging Bugs
1. Fork, branch, send PR.  
2. Run `python -m compileall apolloluncher.py` and `python apolloluncher.py --self-test` before pushing.  
3. Attach a session log when reporting issues; it’s the difference between “funny bug” and “haunting bug”.

---

## License
MIT-ish (check `MDFILES/LICENSE.txt`). Share, break, improve—just don’t pawn it off as your own without buying us coffee. (that was a joke XD) feel free to use it as you wish humans :]

---

## File Structure

```
apollo-multi-instance-launcher/
├── apollo_multi_launcher.py          # Main GUI launcher
├── ApolloLauncher_Admin.cmd          # Admin launcher shortcut
├── README.md                         # This file
├── cli/                              # Command-line tools
│   ├── __init__.py
│   ├── screenshot.py                 # Screenshot capture
│   ├── moonlight_status.py           # Instance health check
│   ├── launch_background.py          # Headless launcher
│   └── README.md                     # CLI documentation
├── configs/                          # Configuration templates
│   └── apollo-nvenc-template.conf    # NVENC reference config
└── skills/                           # Claude CLI integration
    └── moonlight-control/
        ├── skill.md                  # Skill documentation
        └── handler.py                # Python skill handler

Runtime data: C:\ProgramData\ApolloLauncher\
```

---

## Credits
- **Apollo** by **ClassicOldSong**: https://github.com/ClassicOldSong/Apollo  
- *This launcher* made with <3 by **neo0oen** — across a purple neon label at the bottom-left of the window.  
- Hazardous code clean-up performed by Codex CLI, powered by GPT-5-class LLMs that never sleep and seldom blink.

Stay weird, stay multi-instance.

