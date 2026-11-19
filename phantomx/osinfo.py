"""Which OS / CPU we are on, in the vocabulary each upstream project uses."""
from __future__ import annotations

import platform
import sys

WINDOWS, LINUX, MACOS = "windows", "linux", "macos"


class UnsupportedPlatform(RuntimeError):
    pass


def current_os() -> str:
    if sys.platform == "win32":
        return WINDOWS
    if sys.platform.startswith("linux"):
        return LINUX
    if sys.platform == "darwin":
        return MACOS
    raise UnsupportedPlatform(f"unsupported OS: {sys.platform}")


def arch() -> str:
    """'x86_64' or 'aarch64'."""
    m = platform.machine().lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "aarch64"
    raise UnsupportedPlatform(f"unsupported CPU architecture: {m}")


def exe_name(base: str, os_name: str | None = None) -> str:
    return base + ".exe" if (os_name or current_os()) == WINDOWS else base


# Upstream naming
def tor_bundle_platform(os_name: str, cpu: str) -> str:
    """tor-expert-bundle-<this>-<ver>.tar.gz"""
    return f"{os_name}-{cpu}"


def singbox_platform(os_name: str, cpu: str) -> str:
    """sing-box-<ver>-<this>.(zip|tar.gz)"""
    o = {WINDOWS: "windows", LINUX: "linux", MACOS: "darwin"}[os_name]
    a = {"x86_64": "amd64", "aarch64": "arm64"}[cpu]
    return f"{o}-{a}"


def tor_browser_key(os_name: str, cpu: str) -> str:
    """Key in Tor Browser's downloads.json."""
    if os_name == WINDOWS:
        return "win64"
    if os_name == MACOS:
        return "macos"
    return f"linux-{cpu}"
