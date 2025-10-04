# Apollo Multi-Seat Launcher (a.k.a. "Why run one Sunshine when you can juggle several?")

Welcome to the small GUI that keeps Sunshine/Apollo wrangled on Windows. It builds one sandbox per seat, rewrites configs, and launches each instance with its own baggage so your living room LAN party doesn’t dissolve into shared logs and shared sins.

 A single instance of Sunshine is like a single cookie—useless once the family arrives. We automate the second, third, and yes… fifth cookie.

## Feature Primer
- **Profile Sandboxing** – Each profile gets unique filenames (`apps_[slug].json`, `sunshine_state_[slug].json`, etc.) inside `C:\ProgramData\ApolloLauncher\runtime`.
- **Clean Slate Creation** – On first launch we seed brand-new JSON with fresh salts, UUIDs, and empty app lists. If the files already exist, we leave them alone.
- **Silent Launch** – Hides the Sunshine console by default for current-user launches. Toggle it off if you miss blinking cursors.
- **Dependency Auto-Heal** – Missing `PySide6` or `psutil`? The launcher self-installs them via `pip` and tattles via MessageBox when the network is gone.
- **Logging** – Every session logs to `C:\ProgramData\ApolloLauncher\logs\launcher_YYYYMMDD_HHMMSS.log`.
- **Optional Runtime Cleanup** – Deleting a profile now politely asks if you want its runtime folder nuked too.

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

## Creating Profiles
1. Hit **New** and name the profile.
2. Launcher auto-detects `sunshine.exe` and `sunshine.conf` from `C:\Program Files\Apollo\`.
3. Unique filenames are generated for `apps`, `state`, `credentials`, `log`, `pkey`, and `cert`.
4. First launch writes clean JSON + empty log.
5. Subsequent launches reuse whatever the instance created through the Web UI.

---

## Launching Instances
- **Silent Launch** (default): Sunshine runs without a console window; output goes to the per-profile log in runtime.
- **No Run-As** just yet: All new profiles default to current user. Use the full profile editor (Edit) to configure 

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

---

## FAQ
**Q: Can we run more than two Suns?**  
A: Yes. Sunshine is the star; we’re just the stage crew.

**Q: Why the jokes?**  
A: Because if you’re launching multiple headless GPUs at 3 AM, humor is the only thing preventing registry edits.

**Q: Does this work on Linux/macOS?**  
A: Most logic is cross-platform, but the GUI focus and silent launch polish target Windows. Patches welcome.

---

## Contributing & Logging Bugs
1. Fork, branch, send PR.  
2. Run `python -m compileall apolloluncher.py` and `python apolloluncher.py --self-test` before pushing.  
3. Attach a session log when reporting issues; it’s the difference between “funny bug” and “haunting bug”.

---

## License
MIT-ish (check `MDFILES/LICENSE.txt`). Share, break, improve—just don’t pawn it off as your own without buying us coffee.

---

## Credits
*Made with <3 by neo0oen* — across a purple neon label at the bottom-left of the window.  
Hazardous code clean-up performed by Codex CLI, powered by GPT-5-class LLMs that never sleep and seldom blink.

Stay weird, stay multi-seat.
