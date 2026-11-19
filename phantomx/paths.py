"""On-disk layout. Everything lives in an admin/root-only folder:
  Windows  C:\\ProgramData\\PhantomX
  Linux    /var/lib/phantomx
  macOS    /private/var/db/phantomx
Binaries are copied here after verification so that a normal-user process cannot swap
them between verification and execution. Paths contain no spaces (torrc requirement).
"""
from __future__ import annotations

import os
from pathlib import Path

from .osinfo import LINUX, MACOS, WINDOWS, current_os, exe_name

APP_NAME = "PhantomX"


def default_root(os_name: str | None = None) -> Path:
    os_name = os_name or current_os()
    if os_name == WINDOWS:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / APP_NAME
    if os_name == MACOS:
        return Path("/private/var/db/phantomx")
    return Path("/var/lib/phantomx")


class Layout:
    def __init__(self, root: Path | None = None, os_name: str | None = None):
        self.os = os_name or current_os()
        self.root = Path(root) if root else default_root(self.os)
        self.bin = self.root / "bin"
        self.tor_bundle = self.bin / "tor-bundle"
        self.singbox_dir = self.bin / "sing-box"
        self.run = self.root / "run"
        self.tor_data = self.root / "tor-data"
        self.downloads = self.root / "downloads"
        self.config = self.root / "config.json"
        self.state = self.root / "state.json"
        self.manifest = self.root / "manifest.json"
        self.pf_token = self.root / "pf.token"

    def _exe(self, base: str) -> str:
        return exe_name(base, self.os)

    @property
    def tor_dir(self) -> Path:
        return self.tor_bundle / "tor"

    @property
    def tor_exe(self) -> Path:
        return self.tor_dir / self._exe("tor")

    @property
    def pt_dir(self) -> Path:
        return self.tor_dir / "pluggable_transports"

    @property
    def lyrebird_exe(self) -> Path:
        return self.pt_dir / self._exe("lyrebird")

    @property
    def snowflake_exe(self) -> Path:
        return self.pt_dir / self._exe("snowflake-client")

    @property
    def conjure_exe(self) -> Path:
        return self.pt_dir / self._exe("conjure-client")

    @property
    def geoip(self) -> Path:
        return self.tor_bundle / "data" / "geoip"

    @property
    def geoip6(self) -> Path:
        return self.tor_bundle / "data" / "geoip6"

    @property
    def singbox_exe(self) -> Path:
        return self.singbox_dir / self._exe("sing-box")

    @property
    def torrc(self) -> Path:
        return self.run / "torrc"

    @property
    def torrc_defaults(self) -> Path:
        return self.run / "torrc-defaults"

    @property
    def tor_log(self) -> Path:
        return self.run / "tor.log"

    @property
    def singbox_config(self) -> Path:
        return self.run / "sing-box.json"

    @property
    def singbox_log(self) -> Path:
        return self.run / "sing-box.log"

    @property
    def singbox_console(self) -> Path:
        return self.run / "sing-box.console.log"

    @property
    def tor_console(self) -> Path:
        return self.run / "tor.console.log"

    @property
    def cookie(self) -> Path:
        return self.tor_data / "control_auth_cookie"


def tor_browser_tor_dir(tb_dir: str | Path, os_name: str | None = None) -> Path:
    """Where Tor Browser keeps its own tor + pluggable transports."""
    base = Path(tb_dir)
    if (os_name or current_os()) == MACOS:
        return base / "Contents" / "MacOS" / "Tor"
    return base / "Browser" / "TorBrowser" / "Tor"


__all__ = ["Layout", "default_root", "tor_browser_tor_dir", "APP_NAME", "WINDOWS", "LINUX", "MACOS"]
