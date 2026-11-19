"""Pick the right OS backend."""
from __future__ import annotations

from .config import Settings
from .osinfo import LINUX, MACOS, WINDOWS, current_os
from .paths import Layout


def make_ops(os_name: str | None = None):
    os_name = os_name or current_os()
    if os_name == WINDOWS:
        from .winutil import SystemOps
        return SystemOps()
    from .posix import PosixOps
    return PosixOps(os_name)


def make_firewall(layout: Layout, ops, settings: Settings | None = None):
    settings = settings or Settings()
    if layout.os == WINDOWS:
        from .firewall import Firewall
        return Firewall(ops.runner)
    if layout.os == LINUX:
        from .posix import LinuxFirewall
        return LinuxFirewall(settings.tun_name)
    if layout.os == MACOS:
        from .posix import MacFirewall
        return MacFirewall(layout.pf_token, ops, settings.tun_address)
    raise RuntimeError(layout.os)


def is_admin() -> bool:
    return make_ops().is_admin()


def relaunch_elevated(args: list[str]) -> bool:
    """Windows: UAC prompt, new process (returns True if launched). POSIX: exec sudo (no return)."""
    if current_os() == WINDOWS:
        from .winutil import relaunch_elevated as win_relaunch
        return win_relaunch(args)
    from .posix import relaunch_with_sudo
    relaunch_with_sudo(args)
    return True
