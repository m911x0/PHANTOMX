"""Name, author, links, logo and legal notice: one place for all of it."""
from __future__ import annotations

import os
import sys

from . import __version__

APP = "PHANTOMX"
AUTHOR = "M911x0"
AUTHOR_URL = "https://github.com/m911x0"
REPO_URL = "https://github.com/m911x0/PHANTOMX"
ISSUES_URL = REPO_URL + "/issues"
COPYRIGHT = f"Copyright (c) 2026 {AUTHOR}. Released under the MIT License."

LOGO = r"""
 ____    _   _      _      _   _   _____    ___    __  __  __  __
|  _ \  | | | |    / \    | \ | | |_   _|  / _ \  |  \/  | \ \/ /
| |_) | | |_| |   / _ \   |  \| |   | |   | | | | | |\/| |  \  /
|  __/  |  _  |  / ___ \  | |\  |   | |   | |_| | | |  | |  /  \
|_|     |_| |_| /_/   \_\ |_| \_|   |_|    \___/  |_|  |_| /_/\_\
""".strip("\n")

TAGLINE = f"Whole-device Tor routing  |  fail-closed  |  v{__version__}  |  by {AUTHOR}"

DISCLAIMER = (
    f"{APP} is a privacy tool provided for lawful purposes only: protecting your privacy, "
    "journalism, research, security testing you are authorized to perform, and circumventing "
    "censorship where that is legal.\n\n"
    "You are solely responsible for how you use it and for complying with the laws of your "
    "country. Do NOT use it to commit or facilitate any crime, harassment, fraud, unauthorized "
    "access, or any other harmful or illegal activity.\n\n"
    f"The author ({AUTHOR}) does not endorse, and expressly disclaims any responsibility or "
    "liability for, any misuse of this software or any damage resulting from its use. The "
    "software is provided \"AS IS\", without warranty of any kind. No tool guarantees anonymity."
)

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def _enable_ansi() -> bool:
    out = sys.stdout
    if out is None or not hasattr(out, "isatty") or not out.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        return False


def print_logo() -> None:
    footer = f"{COPYRIGHT}  {AUTHOR_URL}\nLawful use only. The author disclaims all liability for misuse."
    if _enable_ansi():
        print(f"{BOLD}{LOGO}{RESET}\n  {TAGLINE}\n{DIM}  {footer.replace(chr(10), chr(10) + '  ')}{RESET}\n")
    else:
        print(f"{LOGO}\n  {TAGLINE}\n  {footer.replace(chr(10), chr(10) + '  ')}\n")
