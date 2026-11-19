"""Open the user's Tor Browser with the normal user's rights (never as Administrator/root)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .osinfo import LINUX, MACOS, WINDOWS, current_os


def find_launcher(tor_browser_dir: str, os_name: str | None = None) -> Path:
    base = Path(tor_browser_dir)
    os_name = os_name or current_os()
    if os_name == WINDOWS:
        candidates = [base / "Tor Browser.lnk", base / "Start Tor Browser.lnk", base / "Browser" / "firefox.exe"]
    elif os_name == LINUX:
        candidates = [base / "Browser" / "start-tor-browser"]
    else:
        candidates = [base] if base.suffix == ".app" else []
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("Tor Browser was not found in that folder. Choose the Tor Browser folder "
                            "(or use 'Install Tor Browser').")


def open_url(url: str) -> None:
    """Open an https link in the user's default browser, as the normal user (not elevated)."""
    if not url.startswith("https://"):
        raise ValueError("only https links")
    os_name = current_os()
    if os_name == WINDOWS:
        explorer = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "explorer.exe")
        subprocess.Popen([explorer, url], close_fds=True)
        return
    cmd = ["xdg-open", url] if os_name == LINUX else ["open", url]
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user and user != "root":
        cmd = ["sudo", "-u", user, "--preserve-env=DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR"] + cmd
    subprocess.Popen(cmd, close_fds=True, start_new_session=True)


def launch(tor_browser_dir: str) -> None:
    if not tor_browser_dir:
        raise ValueError("Set the Tor Browser folder in Settings first (or use 'Install Tor Browser').")
    os_name = current_os()
    target = find_launcher(tor_browser_dir, os_name)
    if os_name == WINDOWS:
        explorer = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "explorer.exe")
        subprocess.Popen([explorer, str(target)], close_fds=True)
        return
    cmd = [str(target), "--detach"] if os_name == LINUX else ["open", "-a", str(target)]
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user and user != "root":
        keep = "DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR"
        cmd = ["sudo", "-u", user, f"--preserve-env={keep}"] + cmd
    subprocess.Popen(cmd, close_fds=True, start_new_session=True)
