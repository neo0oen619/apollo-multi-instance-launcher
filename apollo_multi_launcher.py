#!/usr/bin/env python3
"""
Apollo/Sunshine Multi-Instance Launcher - v3
===========================================

Super user-friendly GUI to launch multiple Apollo/Sunshine instances, each with
its own config + files (apps/state/credentials/log/pkey/cert) and ports.

New in v3
---------
* **Automatic local user discovery** (Windows, Linux, macOS) + dropdown picker.
* (Windows) **Active session list** (via `query user`) to see who's logged in.
* One-click **Open Web UI** and **Check Port** buttons.
* Polished UI layout + safer defaults to ProgramData (/var/lib) when possible.
* All per-instance files are set explicitly: file_apps, file_state,
  credentials_file, log_path, pkey, cert (plus port, sunshine_name).

Usage
-----
1) `pip install PySide6 psutil`
2) `python apollo_multi_launcher_v3.py`
3) Create a profile per seat. Pick a user from the dropdown if launching as a
   different user (Windows RunAs or Linux sudo -u). Unique ports per instance.

Notes
-----
* On Windows, RunAs will prompt unless you've used /savecred before.
* Place runtime paths in a location accessible by the target user (we default
  to ProgramData/var-lib to help). You can override paths in the editor.
* The launcher does not generate TLS keys/certs; point to existing ones or let
  the app generate its own defaults if supported.

"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
import logging
import shutil
import time
import uuid
import secrets
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

APPS_TEMPLATE = {
    "version": 2,
    "apps": [
        {
            "allow-client-commands": False,
            "image-path": "desktop.png",
            "name": "Desktop",
            "uuid": "E372AB64-CE95-F80D-031E-53F8D21DBF58"
        },
        {
            "detached": ["steam://open/bigpicture"],
            "image-path": "steam.png",
            "name": "Steam Big Picture",
            "prep-cmd": [
                {
                    "do": "",
                    "elevated": False,
                    "undo": "steam://close/bigpicture"
                }
            ],
            "uuid": "67D9F399-E94F-2006-5180-435DF3D8DCF6"
        }
    ],
    "env": {}
}

STATE_TEMPLATE = {
    "username": "",
    "password": "",
    "salt": None,
    "root": {"named_devices": [], "uniqueid": None}
}

CREDENTIALS_TEMPLATE = {
    "username": "",
    "password": ""
}

REQUIRED_MODULES = [
    ("psutil", "psutil"),
    ("PySide6", "PySide6"),
]


def _show_startup_error(title: str, message: str) -> None:
    displayed = False
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
            displayed = True
        except Exception:
            pass
    if not displayed:
        try:
            print(f"{title}: {message}", file=sys.stderr)
        except Exception:
            pass


def ensure_dependencies() -> None:
    missing: list[tuple[str, str]] = []
    for package, import_name in REQUIRED_MODULES:
        try:
            __import__(import_name)
        except ImportError:
            missing.append((package, import_name))
    if not missing:
        return
    for package, import_name in missing:
        try:
            print(f"Installing required package: {package}")
        except Exception:
            pass
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode != 0:
            _show_startup_error("Apollo Launcher", f"Failed to install {package}:\n{result.stdout}")
            raise SystemExit(1)
        try:
            __import__(import_name)
        except ImportError:
            _show_startup_error("Apollo Launcher", f"Dependency {import_name} still missing after installation.")
            raise SystemExit(1)


ensure_dependencies()

from PySide6 import QtCore, QtGui, QtWidgets
import psutil


# --------------------- Storage roots (shared if possible) ---------------------
if os.name == "nt":
    _shared_root = Path(os.getenv("PROGRAMDATA", r"C:\\ProgramData")) / "ApolloLauncher"
else:
    _shared_root = Path("/var/lib/ApolloLauncher")

_user_root = Path.home() / ".apollo_multi_launcher"

BASE_DIR = _shared_root if _shared_root.parent.exists() and os.access(_shared_root.parent, os.W_OK) else _user_root
RUNTIME_DIR = BASE_DIR / "runtime"
STATE_PATH = BASE_DIR / "profiles.json"
BASE_DIR.mkdir(parents=True, exist_ok=True)
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
SESSION_LOG_PATH = LOG_DIR / f"launcher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
ACTIVE_LOG_PATH = SESSION_LOG_PATH


def _configure_logging() -> logging.Logger:
    global ACTIVE_LOG_PATH
    root = logging.getLogger()
    if not root.handlers:
        root.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s")
        stream_handler = logging.StreamHandler(stream=sys.stdout)
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)
        log_path = SESSION_LOG_PATH
        try:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
        except OSError:
            log_path = BASE_DIR / "launcher.log"
            ACTIVE_LOG_PATH = log_path
            stream_handler.stream.write(f"[apollo_launcher] Falling back to {log_path} for logging\n")
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
        else:
            ACTIVE_LOG_PATH = log_path
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    logger = logging.getLogger("apollo_launcher")
    logger.info("Log file: %s", ACTIVE_LOG_PATH)
    return logger


LOGGER = _configure_logging()


def _log_uncaught(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    LOGGER.exception("Uncaught exception", exc_info=(exc_type, exc_value, exc_tb))
    sys.__excepthook__(exc_type, exc_value, exc_tb)


sys.excepthook = _log_uncaught


def _qt_message_handler(mode, context, message):
    qt = QtCore.QtMsgType
    if mode == qt.QtDebugMsg:
        LOGGER.debug("Qt: %s", message)
    elif hasattr(qt, 'QtInfoMsg') and mode == qt.QtInfoMsg:
        LOGGER.info("Qt: %s", message)
    elif mode == qt.QtWarningMsg:
        LOGGER.warning("Qt: %s", message)
    elif mode == qt.QtCriticalMsg:
        LOGGER.error("Qt: %s", message)
    elif hasattr(qt, 'QtFatalMsg') and mode == qt.QtFatalMsg:
        LOGGER.critical("Qt fatal: %s", message)
    else:
        LOGGER.info("Qt: %s", message)


QtCore.qInstallMessageHandler(_qt_message_handler)

APP_NAME = "Apollo Multi-Instance Launcher"

# ----------------------------- Helpers & utils -------------------------------

def safe_slug(name: str) -> str:
    s = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name).strip("_")
    return s or "instance"


def normpath(p: str) -> str:
    return str(Path(p)).replace("\\", "/")


def find_free_port(start: int = 47989, limit: int = 200) -> int:
    import socket
    for port in range(start, start + limit):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start


def detect_default_exec_and_config() -> Tuple[Optional[Path], Optional[Path]]:
    env_exec = os.environ.get("APOLLO_EXECUTABLE") or os.environ.get("SUNSHINE_EXECUTABLE")
    exec_candidate = Path(env_exec) if env_exec else None
    if exec_candidate and not exec_candidate.exists():
        exec_candidate = None

    env_conf = os.environ.get("APOLLO_CONFIG") or os.environ.get("SUNSHINE_CONFIG")
    config_candidate = Path(env_conf) if env_conf else None
    if config_candidate and not config_candidate.exists():
        config_candidate = None

    if exec_candidate is None:
        if os.name == "nt":
            pf = Path(os.environ.get("ProgramFiles", r"C:/Program Files"))
            pf_alt = Path(os.environ.get("ProgramFiles(x86)", r"C:/Program Files (x86)"))
            search_dirs = [pf / "Apollo", pf / "Sunshine", pf_alt / "Sunshine"]
            for base in search_dirs:
                cand = base / "sunshine.exe"
                if cand.exists():
                    exec_candidate = cand
                    break
        else:
            for cand in [Path("/usr/bin/sunshine"), Path("/usr/local/bin/sunshine"), Path("/opt/sunshine/sunshine")]:
                if cand.exists():
                    exec_candidate = cand
                    break

    if config_candidate is None and exec_candidate is not None:
        possible = [
            exec_candidate.parent / "config" / "sunshine.conf",
            exec_candidate.parent / "sunshine.conf",
        ]
        for cand in possible:
            if cand.exists():
                config_candidate = cand
                break

    return exec_candidate, config_candidate


def next_available_port(preferred: int, existing_ports: List[int]) -> int:
    port = max(preferred, 1024)
    while True:
        candidate = find_free_port(port)
        if candidate not in existing_ports:
            return candidate
        port = candidate + 1



def ensure_profile_unique_files(profile: InstanceProfile) -> None:
    slug = safe_slug(profile.name) or "instance"
    def needs_update(value: str, keywords: tuple[str, ...]) -> bool:
        v = (value or "").lower().replace("\\", "/")
        return any(v == kw or v.endswith(f"/{kw}") for kw in keywords)

    if needs_update(profile.apps_file, ("apps.json",)):
        profile.apps_file = f"apps_{slug}.json"
    if needs_update(profile.state_file, ("sunshine_state.json",)):
        profile.state_file = f"sunshine_state_{slug}.json"
    if needs_update(profile.credentials_file, ("sunshine_state.json", "credentials.json", "sunshine_credentials.json")):
        profile.credentials_file = f"credentials_{slug}.json"
    if needs_update(profile.log_file, ("sunshine.log",)):
        profile.log_file = f"sunshine_{slug}.log"
    if needs_update(profile.pkey_file, ("pkey.pem",)):
        profile.pkey_file = f"pkey_{slug}.pem"
    if needs_update(profile.cert_file, ("cert.pem",)):
        profile.cert_file = f"cert_{slug}.pem"
    if not profile.sunshine_name or profile.sunshine_name.lower() in ("apollo", "sunshine"):
        profile.sunshine_name = profile.name


def auto_profile_from_name(name: str, existing: List[InstanceProfile]) -> Optional[InstanceProfile]:
    exec_path, base_config = detect_default_exec_and_config()
    if exec_path is None or base_config is None:
        return None
    existing_ports = [p.web_port for p in existing]
    suggested_port = next_available_port(47989 + len(existing) * 2, existing_ports)
    cleaned_name = name.strip() or "Seat"
    slug = safe_slug(cleaned_name)
    sunshine_name = cleaned_name
    profile = InstanceProfile(
        name=cleaned_name,
        exec_path=str(exec_path),
        base_config=str(base_config),
        web_port=suggested_port,
        sunshine_name=sunshine_name,
        apps_file=f"apps_{slug}.json",
        state_file=f"sunshine_state_{slug}.json",
        credentials_file=f"credentials_{slug}.json",
        log_file=f"sunshine_{slug}.log",
        pkey_file=f"pkey_{slug}.pem",
        cert_file=f"cert_{slug}.pem",
        run_as_mode="current",
        other_user="",
    )
    ensure_profile_unique_files(profile)
    return profile


def repair_profile_defaults(profile: InstanceProfile) -> None:
    exec_path = profile.exec_path.strip() if profile.exec_path else ""
    base_config = profile.base_config.strip() if profile.base_config else ""
    detected_exec, detected_conf = detect_default_exec_and_config()
    if exec_path in {"", "."} and detected_exec is not None:
        profile.exec_path = str(detected_exec)
    if base_config in {"", "."} and detected_conf is not None:
        profile.base_config = str(detected_conf)
    if profile.web_port < 1024:
        profile.web_port = find_free_port(47989)
    if not profile.sunshine_name:
        profile.sunshine_name = profile.name
    ensure_profile_unique_files(profile)

# ----------------------------- User enumeration ------------------------------

def list_local_users() -> List[str]:
    sysname = platform.system().lower()
    LOGGER.info("Enumerating local users for platform '%s'", sysname)
    users: List[str] = []
    try:
        if sysname.startswith("win"):
            try:
                ps_cmd = [
                    "powershell", "-NoProfile", "-Command",
                    "Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object -ExpandProperty Name"
                ]
                out = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=5)
                if out.returncode == 0 and out.stdout.strip():
                    users = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
                    LOGGER.info("Discovered %d users via Get-LocalUser", len(users))
                else:
                    LOGGER.debug("Get-LocalUser returned code %s; falling back", out.returncode)
                    raise RuntimeError("fallback")
            except Exception as exc:
                LOGGER.debug("PowerShell user query failed: %s", exc)
                out = subprocess.run(["cmd", "/c", "net user"], capture_output=True, text=True, timeout=5)
                if out.returncode == 0:
                    lines = [l.rstrip() for l in out.stdout.splitlines()]
                    block: list[str] = []
                    sep_seen = 0
                    for l in lines:
                        if set(l.strip()) == {"-"}:
                            sep_seen += 1
                            continue
                        if sep_seen == 1 and l.strip():
                            block.append(l)
                    joined = " ".join(block)
                    users = [u for u in joined.split() if u.lower() not in {"the", "command", "completed", "successfully."}]
                    LOGGER.info("Discovered %d users via net user fallback", len(users))
        elif sysname == "linux":
            import pwd
            for entry in pwd.getpwall():
                if entry.pw_uid >= 1000 and not entry.pw_name.startswith("nobody"):
                    shell = (entry.pw_shell or "").rsplit("/", 1)[-1]
                    if shell not in ("false", "nologin"):
                        users.append(entry.pw_name)
            LOGGER.info("Discovered %d users via pwd", len(users))
        elif sysname == "darwin":
            try:
                out = subprocess.run(["dscl", ".", "-list", "/Users"], capture_output=True, text=True, timeout=5)
                candidates = [u.strip() for u in out.stdout.splitlines() if u.strip()]
                for candidate in candidates:
                    try:
                        uid_out = subprocess.run(["id", "-u", candidate], capture_output=True, text=True, timeout=2)
                        uid = int(uid_out.stdout.strip() or -1)
                        if uid >= 500:
                            users.append(candidate)
                    except Exception as inner_exc:
                        LOGGER.debug("Failed to query uid for %s: %s", candidate, inner_exc)
                        continue
                LOGGER.info("Discovered %d users via dscl", len(users))
            except Exception as exc:
                LOGGER.debug("dscl user query failed: %s", exc)
    except Exception as exc:
        LOGGER.warning("Local user enumeration failed: %s", exc)
        users = []

    blacklist = {"Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"}
    filtered = [u for u in users if u not in blacklist]
    if len(filtered) != len(users):
        LOGGER.debug("Filtered users by blacklist; %d removed", len(users) - len(filtered))
    LOGGER.info("Returning %d visible users", len(filtered))
    return filtered




def list_windows_sessions() -> List[Tuple[str, str, str]]:
    """Return list of (USERNAME, SESSIONNAME/ID, STATE) for Windows. Empty on other OS."""
    if os.name != "nt":
        return []
    try:
        out = subprocess.run(["query", "user"], capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            LOGGER.debug("query user exited with code %s", out.returncode)
            return []
        lines = [l for l in out.stdout.splitlines() if l.strip()]
        if not lines:
            LOGGER.debug("query user produced no output")
            return []
        data: List[Tuple[str, str, str]] = []
        for row in lines[1:]:
            parts = row.split()
            if len(parts) >= 4:
                user = parts[0]
                sess = parts[1] if not parts[1].isdigit() else f"ID:{parts[1]}"
                state = parts[3] if parts[3].isalpha() else parts[2]
                data.append((user, sess, state))
        LOGGER.info("Detected %d active Windows sessions", len(data))
        return data
    except Exception as exc:
        LOGGER.debug("Windows session enumeration failed: %s", exc)
        return []

# ------------------------------ Data model -----------------------------------
@dataclass
class InstanceProfile:
    name: str
    exec_path: str
    base_config: str
    web_port: int = 47989
    sunshine_name: str = "Apollo"

    # Config files
    apps_file: str = "apps.json"
    state_file: str = "sunshine_state.json"
    credentials_file: str = "sunshine_state.json"
    log_file: str = "sunshine.log"
    pkey_file: str = "pkey.pem"
    cert_file: str = "cert.pem"

    # Launch options
    run_as_mode: str = "current"   # current | other
    other_user: str = ""            # filled from user dropdown
    use_savecred: bool = True       # Windows only
    extra_args: str = ""

    last_pid: int = 0

    def runtime_dir(self) -> Path:
        return RUNTIME_DIR / safe_slug(self.name)

    def rendered_config_path(self) -> Path:
        return self.runtime_dir() / f"{safe_slug(self.name)}.conf"

    def _pp(self, val: str) -> Path:
        p = Path(val)
        return p if p.is_absolute() else self.runtime_dir() / val

    def apps_path(self) -> Path: return self._pp(self.apps_file)
    def state_path(self) -> Path: return self._pp(self.state_file)
    def creds_path(self) -> Path: return self._pp(self.credentials_file)
    def log_path(self) -> Path: return self._pp(self.log_file)
    def pkey_path(self) -> Path: return self._pp(self.pkey_file)
    def cert_path(self) -> Path: return self._pp(self.cert_file)

# ------------------------------ Persistence ----------------------------------

def load_profiles() -> List[InstanceProfile]:
    if not STATE_PATH.exists():
        LOGGER.info("No profiles file at %s; starting new", STATE_PATH)
        return []
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        profiles = [InstanceProfile(**d) for d in data]
        LOGGER.info("Loaded %d profile(s) from %s", len(profiles), STATE_PATH)
        return profiles
    except Exception as exc:
        LOGGER.error("Failed to load profiles from %s: %s", STATE_PATH, exc)
        return []


def save_profiles(profiles: List[InstanceProfile]):
    try:
        STATE_PATH.write_text(json.dumps([asdict(p) for p in profiles], indent=2), encoding="utf-8")
    except OSError as exc:
        LOGGER.error("Failed to save profiles to %s: %s", STATE_PATH, exc)
        raise
    else:
        LOGGER.info("Saved %d profile(s) to %s", len(profiles), STATE_PATH)

# ------------------------------ Config writer --------------------------------

def upsert_conf(base_text: str, kv: dict[str, str]) -> str:
    lines = base_text.splitlines()
    found = {k: False for k in kv}
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k = s.split("=", 1)[0].strip()
        if k in kv:
            lines[i] = f"{k} = {kv[k]}"
            found[k] = True
    if not all(found.values()):
        lines.append("")
        lines.append("# --- Updated by Apollo Launcher v3 ---")
        for k, v in kv.items():
            if not found[k]:
                lines.append(f"{k} = {v}")
    return "\n".join(lines) + "\n"


def _resolve_source_file(profile: InstanceProfile, value: str) -> Optional[Path]:
    p = Path(value)
    if p.is_absolute():
        return p if p.exists() else None
    base_candidates: list[Path] = []
    base_config_path = Path(profile.base_config)
    if base_config_path.exists():
        base_candidates.append(base_config_path.parent / p)
    exec_path = Path(profile.exec_path)
    if exec_path.exists():
        base_candidates.append(exec_path.parent / p)
    if base_config_path.parent.name.lower() != 'config':
        config_dir = base_config_path.parent / 'config' / p
        base_candidates.append(config_dir)
    for candidate in base_candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.exists():
            return resolved
    return None


def prepare_profile_runtime(profile: InstanceProfile) -> None:
    runtime_dir = profile.runtime_dir()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    targets = [
        (profile.apps_path(), profile.apps_file, True),
        (profile.state_path(), profile.state_file, True),
        (profile.creds_path(), profile.credentials_file, True),
        (profile.log_path(), profile.log_file, True),
        (profile.pkey_path(), profile.pkey_file, False),
        (profile.cert_path(), profile.cert_file, False),
    ]
    for target, original_value, create_empty in targets:
        target = target.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target_exists = target.exists()
        source = _resolve_source_file(profile, original_value)
        copied = False
        if source and source.exists() and not target_exists:

            try:
                shutil.copy2(source, target)
                copied = True
                LOGGER.debug("Seeded %s from template %s", target, source)
            except Exception as exc:
                LOGGER.warning("Failed to copy %s to %s: %s", source, target, exc)
        if create_empty:
            try:
                suffix = target.suffix.lower()
                stem = target.stem.lower()
                if suffix == ".json":
                    if target_exists:
                        LOGGER.debug("Keeping existing JSON %s", target)
                    else:
                        if "apps" in stem:
                            data = json.loads(json.dumps(APPS_TEMPLATE))
                        elif "state" in stem:
                            data = {
                                "username": "",
                                "password": "",
                                "salt": secrets.token_urlsafe(12),
                                "root": {"named_devices": [], "uniqueid": str(uuid.uuid4())}
                            }
                        elif "cred" in stem:
                            data = CREDENTIALS_TEMPLATE
                        else:
                            data = {}
                        target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                elif suffix in {".log"}:
                    if not target_exists:
                        target.write_text("", encoding="utf-8")
                else:
                    if not target_exists:
                        target.touch(exist_ok=True)
                LOGGER.debug("Prepared runtime file %s", target)
            except OSError as exc:
                LOGGER.warning("Unable to create placeholder file %s: %s", target, exc)

def render_profile_config(profile: InstanceProfile) -> Path:
    prepare_profile_runtime(profile)
    runtime_dir = profile.runtime_dir()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    base_path = Path(profile.base_config)
    if base_path.is_file():
        base_text = base_path.read_text(encoding="utf-8", errors="ignore")
    else:
        LOGGER.warning("Base config %s missing or unreadable for profile '%s'; using blank template", base_path, profile.name)
        base_text = ""
    kv = {
        "port": str(profile.web_port),
        "sunshine_name": profile.sunshine_name,
        "file_apps": normpath(str(profile.apps_path())),
        "file_state": normpath(str(profile.state_path())),
        "credentials_file": normpath(str(profile.creds_path())),
        "log_path": normpath(str(profile.log_path())),
        "pkey": normpath(str(profile.pkey_path())),
        "cert": normpath(str(profile.cert_path())),
    }
    final_text = upsert_conf(base_text, kv)
    out_path = profile.rendered_config_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(final_text, encoding="utf-8")
    LOGGER.info("Rendered config for profile '%s' at %s", profile.name, out_path)
    return out_path


def build_launch_commands(profile: InstanceProfile, cfg_path: Path) -> Tuple[List[str], Optional[List[str]]]:
    direct = [profile.exec_path, str(cfg_path)]
    if profile.extra_args:
        direct.extend(shlex.split(profile.extra_args))
    if profile.run_as_mode == "other" and profile.other_user:
        if os.name == "nt":
            quoted = []
            for arg in direct:
                if any(ch in arg for ch in (' ', '&', '^', '(', ')', '[', ']')):
                    quoted.append(f'"{arg}"')
                else:
                    quoted.append(arg)
            command_str = " ".join(quoted)
            runas = ["runas"]
            if profile.use_savecred:
                runas.append("/savecred")
            runas.append(f"/user:{profile.other_user}")
            runas.append(command_str)
            LOGGER.info("Prepared Windows runas launch for profile '%s'", profile.name)
            LOGGER.debug("runas command: %s", runas)
            return direct, runas
        else:
            sudo_cmd = ["sudo", "-u", profile.other_user] + direct
            LOGGER.info("Prepared sudo launch for profile '%s'", profile.name)
            LOGGER.debug("sudo command: %s", sudo_cmd)
            return sudo_cmd, None
    LOGGER.info("Prepared direct launch for profile '%s'", profile.name)
    LOGGER.debug("Direct command: %s", direct)
    return direct, None

def run_self_test(exec_override: Optional[str] = None, config_override: Optional[str] = None) -> int:
    """Smoke test the launcher without GUI."""
    LOGGER.info("Starting self-test")
    if exec_override:
        exec_path = Path(exec_override)
    else:
        exec_detect, _ = detect_default_exec_and_config()
        exec_path = exec_detect
    if exec_path is None or not exec_path.exists():
        LOGGER.error("Executable not found for self-test: %s", exec_path)
        print(f"Self-test failed: executable not found at {exec_path}")
        return 1

    if config_override:
        base_config = Path(config_override)
    else:
        _, conf_detect = detect_default_exec_and_config()
        base_config = conf_detect if conf_detect is not None else exec_path.parent / "config" / "sunshine.conf"
    if not base_config.exists():
        LOGGER.error("Base config not found for self-test: %s", base_config)
        print(f"Self-test failed: base config not found at {base_config}")
        return 1

    profile = InstanceProfile(
        name=f"SelfTest-{datetime.now().strftime('%H%M%S')}",
        exec_path=str(exec_path),
        base_config=str(base_config),
        web_port=find_free_port(47000),
        sunshine_name=f"Apollo SelfTest {datetime.now().strftime('%H:%M:%S')}",
        apps_file="apps.json",
        state_file="sunshine_state.json",
        credentials_file="sunshine_state.json",
        log_file="sunshine.log",
        pkey_file="pkey.pem",
        cert_file="cert.pem",
        run_as_mode="current",
        extra_args=""
    )

    prepare_profile_runtime(profile)
    cfg_path = render_profile_config(profile)
    contents = cfg_path.read_text(encoding="utf-8")
    required_keys = ["port", "sunshine_name", "file_apps", "file_state", "credentials_file", "log_path", "pkey", "cert"]
    missing = [key for key in required_keys if f"{key} =" not in contents]
    if missing:
        LOGGER.error("Rendered config missing keys: %s", missing)
        print(f"Self-test failed: config missing keys {missing}")
        return 1

    files_to_check = [profile.apps_path(), profile.state_path(), profile.creds_path(), profile.log_path(), profile.pkey_path(), profile.cert_path()]
    missing_files = [str(p) for p in files_to_check if not p.exists()]
    if missing_files:
        LOGGER.warning("Some runtime files were not created: %s", missing_files)

    direct_cmd, runas_cmd = build_launch_commands(profile, cfg_path)
    LOGGER.info("Direct command: %s", direct_cmd)
    if runas_cmd:
        LOGGER.info("Run-as command: %s", runas_cmd)

    print("Self-test passed. Rendered config at", cfg_path)
    return 0


# ------------------------------ Qt Models/Views ------------------------------
class ProfileTable(QtCore.QAbstractTableModel):
    HEAD = ["Name", "Exec", "Base Conf", "Port", "Name in UI", "User", "PID"]
    def __init__(self, items: List[InstanceProfile]):
        super().__init__()
        self.items = items
    def rowCount(self, parent=None): return len(self.items)
    def columnCount(self, parent=None): return len(self.HEAD)
    def headerData(self, s, o, r):
        if r == QtCore.Qt.DisplayRole and o == QtCore.Qt.Horizontal: return self.HEAD[s]
        return None
    def data(self, idx, role):
        if not idx.isValid() or role != QtCore.Qt.DisplayRole: return None
        p = self.items[idx.row()]
        c = idx.column()
        return [p.name, p.exec_path, p.base_config, str(p.web_port), p.sunshine_name, (p.other_user or "(current)"), (str(p.last_pid) if p.last_pid else "-")][c]

# ------------------------------ Dialog: Edit Profile -------------------------
class EditDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, profile: Optional[InstanceProfile]=None):
        super().__init__(parent)
        self.setWindowTitle("Profile Editor")
        self.setMinimumWidth(820)

        # Top inputs
        self.name = QtWidgets.QLineEdit()
        self.exec_path_edit = QtWidgets.QLineEdit()
        self.exec_btn = QtWidgets.QPushButton("Browse...")
        self.cfg = QtWidgets.QLineEdit()
        self.cfg_btn = QtWidgets.QPushButton("Browse...")

        self.port = QtWidgets.QSpinBox(); self.port.setRange(1024, 65535); self.port.setValue(find_free_port())
        self.display_name = QtWidgets.QLineEdit("Apollo")

        # User/RunAs
        self.run_mode = QtWidgets.QComboBox(); self.run_mode.addItems(["current", "other"]) 
        self.user_combo = QtWidgets.QComboBox(); self.refresh_users_btn = QtWidgets.QPushButton("Refresh users")
        self.savecred = QtWidgets.QCheckBox("Use /savecred (Windows)"); self.savecred.setChecked(True)
        self.sessions_box = QtWidgets.QGroupBox("Active sessions (Windows)"); self.sessions_list = QtWidgets.QListWidget()
        self.sessions_refresh = QtWidgets.QPushButton("Refresh sessions")
        slay = QtWidgets.QVBoxLayout(self.sessions_box); slay.addWidget(self.sessions_list); slay.addWidget(self.sessions_refresh)

        # Config files
        self.apps = QtWidgets.QLineEdit("apps.json"); self.apps_btn = QtWidgets.QPushButton("...")
        self.state = QtWidgets.QLineEdit("sunshine_state.json"); self.state_btn = QtWidgets.QPushButton("...")
        self.creds = QtWidgets.QLineEdit("sunshine_state.json"); self.creds_btn = QtWidgets.QPushButton("...")
        self.log = QtWidgets.QLineEdit("sunshine.log"); self.log_btn = QtWidgets.QPushButton("...")
        self.pkey = QtWidgets.QLineEdit("pkey.pem"); self.pkey_btn = QtWidgets.QPushButton("...")
        self.cert = QtWidgets.QLineEdit("cert.pem"); self.cert_btn = QtWidgets.QPushButton("...")

        self.args = QtWidgets.QLineEdit()

        # Buttons
        ok = QtWidgets.QPushButton("Save")
        cancel = QtWidgets.QPushButton("Cancel")

        # Layout
        form = QtWidgets.QFormLayout()
        ex_l = h(self.exec_path_edit, self.exec_btn)
        cf_l = h(self.cfg, self.cfg_btn)
        form.addRow("Profile name:", self.name)
        form.addRow("Executable:", ex_l)
        form.addRow("Base config:", cf_l)
        form.addRow("Web UI port:", self.port)
        form.addRow("sunshine_name:", self.display_name)

        # RunAs row
        run_l = QtWidgets.QHBoxLayout()
        run_l.addWidget(QtWidgets.QLabel("Launch as:"))
        run_l.addWidget(self.run_mode)
        run_l.addWidget(self.user_combo)
        run_l.addWidget(self.refresh_users_btn)
        run_l.addWidget(self.savecred)
        runW = QtWidgets.QWidget(); runW.setLayout(run_l)
        form.addRow(runW)

        # Sessions (Windows only)
        if os.name == "nt":
            form.addRow(self.sessions_box)

        form.addRow("Apps file (file_apps):", h(self.apps, self.apps_btn))
        form.addRow("State file (file_state):", h(self.state, self.state_btn))
        form.addRow("Credentials file:", h(self.creds, self.creds_btn))
        form.addRow("Log file (log_path):", h(self.log, self.log_btn))
        form.addRow("Private key (pkey):", h(self.pkey, self.pkey_btn))
        form.addRow("Certificate (cert):", h(self.cert, self.cert_btn))
        form.addRow("Extra CLI args:", self.args)

        btns = QtWidgets.QHBoxLayout(); btns.addStretch(1); btns.addWidget(ok); btns.addWidget(cancel)

        lay = QtWidgets.QVBoxLayout(self)
        lay.addLayout(form)
        lay.addLayout(btns)

        # Hooks
        self.exec_btn.clicked.connect(lambda: pick_open(self.exec_path_edit))
        self.cfg_btn.clicked.connect(lambda: pick_open(self.cfg, filt="Config files (*.conf *.cfg *.txt);;All files (*)"))
        self.apps_btn.clicked.connect(lambda: pick_save(self.apps))
        self.state_btn.clicked.connect(lambda: pick_save(self.state))
        self.creds_btn.clicked.connect(lambda: pick_save(self.creds))
        self.log_btn.clicked.connect(lambda: pick_save(self.log))
        self.pkey_btn.clicked.connect(lambda: pick_save(self.pkey))
        self.cert_btn.clicked.connect(lambda: pick_save(self.cert))
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)
        self.refresh_users_btn.clicked.connect(self._load_users)
        if os.name == "nt":
            self.sessions_refresh.clicked.connect(self._load_sessions)

        # Init
        self._load_users()
        if os.name == "nt":
            self._load_sessions()

        if profile:
            self.load(profile)

        self.run_mode.currentTextChanged.connect(self._toggle_user_controls)
        self._toggle_user_controls(self.run_mode.currentText())

    def _toggle_user_controls(self, mode: str):
        is_other = (mode == "other")
        self.user_combo.setEnabled(is_other)
        self.refresh_users_btn.setEnabled(is_other)
        self.savecred.setEnabled(is_other and os.name == "nt")

    def _load_users(self):
        users = list_local_users() or []
        self.user_combo.clear()
        self.user_combo.addItem("(select user)")
        for u in users:
            self.user_combo.addItem(u)

    def _load_sessions(self):
        self.sessions_list.clear()
        for user, sess, state in list_windows_sessions():
            self.sessions_list.addItem(f"{user}  -  {sess}  -  {state}")

    def to_profile(self) -> InstanceProfile:
        user_sel = self.user_combo.currentText().strip()
        return InstanceProfile(
            name=self.name.text().strip() or "Instance",
            exec_path=self.exec_path_edit.text().strip(),
            base_config=self.cfg.text().strip(),
            web_port=int(self.port.value()),
            sunshine_name=self.display_name.text().strip() or "Apollo",
            apps_file=self.apps.text().strip() or "apps.json",
            state_file=self.state.text().strip() or "sunshine_state.json",
            credentials_file=self.creds.text().strip() or "sunshine_state.json",
            log_file=self.log.text().strip() or "sunshine.log",
            pkey_file=self.pkey.text().strip() or "pkey.pem",
            cert_file=self.cert.text().strip() or "cert.pem",
            run_as_mode=self.run_mode.currentText(),
            other_user=("" if self.run_mode.currentText()=="current" or user_sel.startswith("(") else user_sel),
            use_savecred=self.savecred.isChecked(),
            extra_args=self.args.text().strip(),
        )

    def load(self, p: InstanceProfile):
        self.name.setText(p.name)
        self.exec_path_edit.setText(p.exec_path)
        self.cfg.setText(p.base_config)
        self.port.setValue(p.web_port)
        self.display_name.setText(p.sunshine_name)
        self.apps.setText(p.apps_file)
        self.state.setText(p.state_file)
        self.creds.setText(p.credentials_file)
        self.log.setText(p.log_file)
        self.pkey.setText(p.pkey_file)
        self.cert.setText(p.cert_file)
        self.run_mode.setCurrentText(p.run_as_mode)
        # Try to select user in combo
        if p.other_user:
            idx = self.user_combo.findText(p.other_user)
            if idx >= 0:
                self.user_combo.setCurrentIndex(idx)
        self.savecred.setChecked(p.use_savecred)
        self.args.setText(p.extra_args)



# ------------------------------ Main Window ----------------------------------
class Main(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1120, 640)

        self.profiles: List[InstanceProfile] = load_profiles()
        used_ports: List[int] = []
        for profile in self.profiles:
            repair_profile_defaults(profile)
            if profile.web_port in used_ports:
                profile.web_port = next_available_port(profile.web_port + 1, used_ports)
            used_ports.append(profile.web_port)
        LOGGER.info("Loaded %d profile(s)", len(self.profiles))
        self.model = ProfileTable(self.profiles)

        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        self.setCentralWidget(self.table)

        tb = self.addToolBar("Actions")
        tb.setMovable(False)
        a_add = QtGui.QAction("New", self);          a_add.triggered.connect(self.add)
        a_edit = QtGui.QAction("Edit", self);         a_edit.triggered.connect(self.edit)
        a_del = QtGui.QAction("Delete", self);        a_del.triggered.connect(self.delete)
        tb.addAction(a_add); tb.addAction(a_edit); tb.addAction(a_del)
        tb.addSeparator()
        self.silent_launch_action = QtGui.QAction("Silent Launch", self)
        self.silent_launch_action.setCheckable(True)
        self.silent_launch_action.setChecked(True)
        tb.addAction(self.silent_launch_action)
        tb.addSeparator()
        a_launch = QtGui.QAction("Launch", self);     a_launch.triggered.connect(self.launch)
        a_stop = QtGui.QAction("Stop", self);         a_stop.triggered.connect(self.stop)
        a_open = QtGui.QAction("Open Config Dir", self); a_open.triggered.connect(self.open_dir)
        a_openweb = QtGui.QAction("Open Web UI", self); a_openweb.triggered.connect(self.open_web)
        a_checkport = QtGui.QAction("Check Port", self); a_checkport.triggered.connect(self.check_port)
        a_save = QtGui.QAction("Save", self);         a_save.triggered.connect(self.save)
        a_openlog = QtGui.QAction("Open Log", self);  a_openlog.triggered.connect(self.open_log)
        for action in (a_launch, a_stop, a_open, a_openweb, a_checkport, a_save, a_openlog):
            tb.addAction(action)

        self.status = self.statusBar()
        self.credit_label = QtWidgets.QLabel("made with <3 by neo0oen")
        self.credit_label.setStyleSheet("color:#a855f7; font-weight:bold; letter-spacing:1px; font-size:36px;")
        self.credit_label.setContentsMargins(8, 0, 12, 0)
        self.credit_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        try:
            self.status.insertPermanentWidget(0, self.credit_label)
        except Exception:
            self.status.addPermanentWidget(self.credit_label)
        status_text = f"Profiles: {STATE_PATH} | Log: {ACTIVE_LOG_PATH}"
        self.status.showMessage(status_text)
        self.status.setToolTip(status_text)
        LOGGER.info(status_text)

        self.setStyleSheet("""
        QMainWindow { background: #0f1115; }
        QTableView { background: #0f1115; color: #e6edf3; gridline-color:#23262d; }
        QHeaderView::section { background: #161a22; color:#9fb3c8; padding:6px; border: 0; }
        QToolBar { background:#0b0d12; border:0; spacing:6px; }
        QToolButton { color:#d7e0ea; padding:6px 10px; }
        QToolButton:hover { background:#1a1f29; border-radius:8px; }
        QLineEdit, QSpinBox { background:#0b0d12; color:#d7e0ea; border:1px solid #2a303b; border-radius:8px; padding:6px; }
        QPushButton, QComboBox { background:#1f2633; color:#e6edf3; border:1px solid #29313e; border-radius:10px; padding:6px 10px; }
        QPushButton:hover, QComboBox:hover { background:#253042; }
        QStatusBar { background:#0b0d12; color:#9fb3c8; }
        """)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self.refresh_pids)
        self.timer.start()

    # ---- helpers ----
    def selected_row(self) -> int:
        sel = self.table.selectionModel().selectedRows()
        return sel[0].row() if sel else -1

    def add(self):
        LOGGER.info("Opening quick profile creator")
        default_name = f"Seat-{len(self.profiles) + 1}"
        name, ok = QtWidgets.QInputDialog.getText(self, "New profile", "Profile name:", QtWidgets.QLineEdit.Normal, default_name)
        if not ok:
            LOGGER.info("Profile creation cancelled")
            return
        name = name.strip()
        if not name:
            QtWidgets.QMessageBox.warning(self, "Name required", "Enter a profile name.")
            return

        profile = auto_profile_from_name(name, self.profiles)
        if profile is None:
            LOGGER.error("Unable to auto-detect Apollo/Sunshine installation")
            QtWidgets.QMessageBox.warning(
                self,
                "Executable not found",
                "Could not locate the Apollo/Sunshine executable or base config.\nUse Edit to configure manually."
            )
            dlg = EditDialog(self)
            dlg.name.setText(name)
            if dlg.exec() != QtWidgets.QDialog.Accepted:
                return
            profile = dlg.to_profile()
            ensure_profile_unique_files(profile)
        else:
            profile.name = name
            profile.run_as_mode = "current"
            profile.other_user = ""
            ensure_profile_unique_files(profile)

        LOGGER.info("Attempting to add profile '%s'", profile.name)
        if not Path(profile.exec_path).exists():
            LOGGER.error("Executable missing for profile '%s': %s", profile.name, profile.exec_path)
            QtWidgets.QMessageBox.warning(self, "Invalid executable", f"Executable not found: {profile.exec_path}")
            return
        if not Path(profile.base_config).exists():
            LOGGER.error("Base config missing for profile '%s': %s", profile.name, profile.base_config)
            QtWidgets.QMessageBox.warning(self, "Invalid base config", f"Base config not found: {profile.base_config}")
            return

        repair_profile_defaults(profile)
        try:
            prepare_profile_runtime(profile)
        except Exception as exc:
            LOGGER.exception("Runtime preparation failed for profile '%s'", profile.name)
            QtWidgets.QMessageBox.critical(self, "Runtime error", str(exc))
            return

        self.profiles.append(profile)
        self.model.layoutChanged.emit()
        self.save()
        self.status.showMessage(f"Added profile '{profile.name}'", 4000)
        LOGGER.info("Profile '%s' added", profile.name)


    def edit(self):
        row = self.selected_row()
        if row < 0:
            return
        original = self.profiles[row]
        LOGGER.info("Editing profile '%s'", original.name)
        dlg = EditDialog(self, original)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            updated = dlg.to_profile()
            self.profiles[row] = updated
            self.model.layoutChanged.emit()
            self.save()
            self.status.showMessage(f"Updated profile '{updated.name}'", 4000)
            LOGGER.info("Profile '%s' updated", updated.name)

    def delete(self):
        row = self.selected_row()
        if row < 0:
            return
        profile = self.profiles[row]
        LOGGER.info("Request to delete profile '%s'", profile.name)
        runtime_dir = profile.runtime_dir()
        response = QtWidgets.QMessageBox.question(
            self,
            "Delete profile",
            f"Delete profile '{profile.name}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        if response != QtWidgets.QMessageBox.Yes:
            return

        delete_runtime = False
        if runtime_dir.exists():
            delete_runtime = (QtWidgets.QMessageBox.question(
                self,
                "Remove runtime folder",
                f"Also delete {runtime_dir}?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No
            ) == QtWidgets.QMessageBox.Yes)

        self.profiles.pop(row)
        self.model.layoutChanged.emit()
        self.save()

        if delete_runtime:
            try:
                shutil.rmtree(runtime_dir, ignore_errors=False)
                LOGGER.info("Removed runtime directory %s", runtime_dir)
            except Exception as exc:
                LOGGER.warning("Failed to remove runtime directory %s: %s", runtime_dir, exc)

        self.status.showMessage(f"Deleted profile '{profile.name}'", 4000)
        LOGGER.info("Profile '%s' deleted", profile.name)

    def _render_config(self, profile: InstanceProfile) -> Path:
        return render_profile_config(profile)

    def _build_cmd(self, profile: InstanceProfile, cfg_path: Path) -> Tuple[List[str], Optional[List[str]]]:
        return build_launch_commands(profile, cfg_path)

    def launch(self):
        row = self.selected_row()
        if row < 0:
            return
        profile = self.profiles[row]
        LOGGER.info("Launching profile '%s' on port %s", profile.name, profile.web_port)
        exec_path = Path(profile.exec_path)
        if not exec_path.exists():
            LOGGER.error("Executable missing for profile '%s': %s", profile.name, exec_path)
            QtWidgets.QMessageBox.warning(self, "Executable missing", f"Executable not found: {exec_path}")
            return
        base_config = Path(profile.base_config)
        if not base_config.exists():
            LOGGER.error("Base config missing for profile '%s': %s", profile.name, base_config)
            QtWidgets.QMessageBox.warning(self, "Base config missing", f"Base config not found: {base_config}")
            return
        working_dir = exec_path.parent

        import socket
        busy = False
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", profile.web_port))
            except OSError:
                busy = True
        if busy:
            suggested = find_free_port(profile.web_port + 1, 50)
            LOGGER.warning("Port %s busy for profile '%s'; suggesting %s", profile.web_port, profile.name, suggested)
            if QtWidgets.QMessageBox.question(self, "Port busy", f"Port {profile.web_port} is in use. Use {suggested} instead?") == QtWidgets.QMessageBox.Yes:
                profile.web_port = suggested
                self.model.layoutChanged.emit()
                self.save()
                LOGGER.info("Profile '%s' switched to port %s", profile.name, profile.web_port)
            else:
                return

        cfg_path = self._render_config(profile)
        direct_cmd, runas_cmd = self._build_cmd(profile, cfg_path)
        silent_mode = bool(getattr(self, "silent_launch_action", None) and self.silent_launch_action.isChecked())
        direct_creation = 0
        runas_creation = 0
        popen_kwargs = {"cwd": str(working_dir)}
        if silent_mode and runas_cmd is None:
            popen_kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.name == "nt":
                popen_kwargs["stdin"] = subprocess.DEVNULL
        if os.name == "nt":
            if runas_cmd is None:
                if silent_mode:
                    direct_creation |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
                else:
                    direct_creation |= getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            else:
                if not silent_mode:
                    runas_creation |= getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
                elif silent_mode:
                    LOGGER.info("Silent launch requested but runas command requires console prompt.")
        try:
            if os.name == "nt" and runas_cmd is not None:
                proc = subprocess.Popen(runas_cmd, creationflags=runas_creation or 0)
                LOGGER.info("Spawned runas helper PID %s for profile '%s'", proc.pid, profile.name)
                profile.last_pid = proc.pid or 0
            else:
                proc = subprocess.Popen(direct_cmd, creationflags=direct_creation, **popen_kwargs)
                LOGGER.info("Spawned process PID %s for profile '%s'", proc.pid, profile.name)
                profile.last_pid = proc.pid or 0
            self.model.layoutChanged.emit()
            self.save()
            self.status.showMessage(f"Launched '{profile.name}' (PID ~ {profile.last_pid or 'unknown'})", 5000)
        except Exception as exc:
            LOGGER.exception("Launch failed for profile '%s'", profile.name)
            QtWidgets.QMessageBox.critical(self, "Launch failed", str(exc))

    def stop(self):
        row = self.selected_row()
        if row < 0:
            return
        profile = self.profiles[row]
        LOGGER.info("Stopping profile '%s'", profile.name)
        if profile.last_pid:
            try:
                psutil.Process(profile.last_pid).terminate()
            except Exception as exc:
                LOGGER.warning("Failed to terminate PID %s for profile '%s': %s", profile.last_pid, profile.name, exc)
            profile.last_pid = 0
            self.model.layoutChanged.emit()
            self.save()
            self.status.showMessage("Stop signal sent.", 3000)
        else:
            LOGGER.info("No recorded PID for profile '%s'", profile.name)
            QtWidgets.QMessageBox.information(self, "Stop", "No PID recorded. Close from Web UI or task manager if still running.")

    def open_dir(self):
        row = self.selected_row()
        if row < 0:
            return
        runtime_dir = self.profiles[row].runtime_dir()
        runtime_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info("Opening runtime directory %s", runtime_dir)
        try:
            if os.name == "nt":
                os.startfile(str(runtime_dir))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(runtime_dir)])
            else:
                subprocess.Popen(["xdg-open", str(runtime_dir)])
        except Exception as exc:
            LOGGER.warning("Failed to open directory %s: %s", runtime_dir, exc)
            QtWidgets.QMessageBox.warning(self, "Open directory", str(exc))

    def open_web(self):
        row = self.selected_row()
        if row < 0:
            return
        profile = self.profiles[row]
        url = f"https://localhost:{profile.web_port}"
        LOGGER.info("Opening Web UI for profile '%s' -> %s", profile.name, url)
        import webbrowser
        webbrowser.open(url)

    def check_port(self):
        row = self.selected_row()
        if row < 0:
            return
        profile = self.profiles[row]
        suggested = find_free_port(max(1024, profile.web_port))
        LOGGER.info("Port check for profile '%s': current %s, suggested %s", profile.name, profile.web_port, suggested)
        QtWidgets.QMessageBox.information(self, "Port check", f"Current: {profile.web_port}\nSuggested free port: {suggested}")

    def open_log(self):
        log_path = Path(ACTIVE_LOG_PATH)
        LOGGER.info("Opening session log %s", log_path)
        if not log_path.exists():
            QtWidgets.QMessageBox.information(self, "Log file", f"Log file not created yet: {log_path}")
            return
        try:
            if os.name == "nt":
                os.startfile(str(log_path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(log_path)])
            else:
                subprocess.Popen(["xdg-open", str(log_path)])
        except Exception as exc:
            LOGGER.warning("Failed to open log file %s: %s", log_path, exc)
            QtWidgets.QMessageBox.warning(self, "Open log", str(exc))

    def save(self):
        LOGGER.debug("Saving profiles")
        save_profiles(self.profiles)

    def refresh_pids(self):
        updated = False
        for profile in self.profiles:
            if profile.last_pid and not psutil.pid_exists(profile.last_pid):
                LOGGER.info("Clearing stale PID %s for profile '%s'", profile.last_pid, profile.name)
                profile.last_pid = 0
                updated = True
        if updated:
            self.model.layoutChanged.emit()

# ------------------------------ File pickers ---------------------------------

def h(*widgets: QtWidgets.QWidget) -> QtWidgets.QWidget:
    w = QtWidgets.QWidget(); l = QtWidgets.QHBoxLayout(w); l.setContentsMargins(0,0,0,0)
    for x in widgets: l.addWidget(x)
    return w

def pick_open(line: QtWidgets.QLineEdit, filt: str="All files (*)"):
    fn, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Select file", str(Path.home()), filt)
    if fn: line.setText(fn)

def pick_save(line: QtWidgets.QLineEdit, filt: str="All files (*)"):
    fn, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Select or create file", str(Path.home()), filt)
    if fn: line.setText(fn)

# ------------------------------ Entrypoint -----------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--self-test", action="store_true", help="Run a non-GUI smoke test")
    parser.add_argument("--exec-path", help="Override Sunshine/Apollo executable for self-test")
    parser.add_argument("--config-path", help="Override base config for self-test")
    args, qt_args = parser.parse_known_args(argv_list)

    if args.self_test:
        return run_self_test(args.exec_path, args.config_path)

    qt_argv = [sys.argv[0]] + qt_args
    LOGGER.info("Starting GUI with Qt args: %s", qt_args)
    app = QtWidgets.QApplication(qt_argv)
    app.setApplicationName(APP_NAME)
    window = Main()
    window.show()
    exit_code = app.exec()
    LOGGER.info("GUI terminated with exit code %s", exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
