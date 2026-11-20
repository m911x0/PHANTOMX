"""`phantomx version` / `phantomx update`.

Runs as the NORMAL user (never elevated): pipx installs into the user's profile, and an
elevated pipx would install a second copy for root/Administrator instead.
Nothing here runs automatically: checking GitHub reveals that you use PhantomX, so it only
happens when you ask (and goes through Tor if protection is on).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

from . import __version__
from .branding import REPO_URL

ARCHIVE_URL = REPO_URL + "/archive/refs/heads/main.zip"
RAW_PYPROJECT = "https://raw.githubusercontent.com/m911x0/PHANTOMX/main/pyproject.toml"


class UpdateError(RuntimeError):
    pass


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def latest_version() -> str:
    from .fetch import get_bytes
    m = re.search(r'(?m)^version\s*=\s*"([0-9][0-9.]*)"', get_bytes(RAW_PYPROJECT, limit=64 << 10).decode("utf-8"))
    if not m:
        raise UpdateError("could not read the latest version from GitHub")
    return m.group(1)


def is_newer(latest: str, current: str = __version__) -> bool:
    return parse_version(latest) > parse_version(current)


def installed_with_pipx() -> bool:
    return "pipx" in sys.prefix.replace("\\", "/").lower()


def pipx_command() -> list[str]:
    exe = shutil.which("pipx")
    if exe:
        return [exe]
    if os.name == "nt" and shutil.which("py"):
        return ["py", "-m", "pipx"]
    return [sys.executable if not installed_with_pipx() else "python3", "-m", "pipx"]


def update_command() -> list[str]:
    if installed_with_pipx():
        return pipx_command() + ["install", "--force", ARCHIVE_URL]
    return [sys.executable, "-m", "pip", "install", "--upgrade", ARCHIVE_URL]


def run_update(log=print) -> int:
    if os.name != "nt" and os.geteuid() == 0:
        raise UpdateError("run `phantomx update` WITHOUT sudo: it updates your own installation.")
    cmd = update_command()
    log("Updating with: " + subprocess.list2cmdline(cmd))
    if os.name == "nt":
        # Windows locks the running program's files, so the update runs in its own window
        # right after this process exits.
        script = f"echo Updating PhantomX... & timeout /t 3 /nobreak >nul & {subprocess.list2cmdline(cmd)} & " \
                 "echo. & echo Done. Run: phantomx version & pause"
        subprocess.Popen(["cmd", "/c", script], creationflags=subprocess.CREATE_NEW_CONSOLE, close_fds=True)
        log("The update continues in a new window. Close PhantomX windows if any are open.")
        return 0
    return subprocess.run(cmd).returncode
