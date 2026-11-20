"""Command line. `phantomx` alone opens the control panel; everything elevates itself
(UAC on Windows, sudo on macOS/Linux) and installs its components on first use."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import traceback
from pathlib import Path

from .branding import print_logo
from .config import normalize_app_path, save_settings
from .engine import Engine
from .leakcheck import FAIL, INCONCLUSIVE, PASS, WARN, verdict
from .osinfo import WINDOWS, current_os
from .paths import Layout
from .system import is_admin, make_ops, relaunch_elevated

CRASH_LOG = Path(tempfile.gettempdir()) / "phantomx-gui-error.log"
_SYM = {PASS: "OK  ", WARN: "NOTE", INCONCLUSIVE: "????", FAIL: "FAIL"}
_VERDICT = {PASS: "RESULT: PROTECTED", WARN: "RESULT: PROTECTED, with your accepted exceptions",
            INCONCLUSIVE: "RESULT: NOT VERIFIED - a mandatory check could not run; do not rely on this session",
            FAIL: "RESULT: FAILED - do not browse"}


def _print_checks(results) -> int:
    for r in results:
        print(f"[{_SYM[r.status]}] {r.title}" + (f" - {r.detail}" if r.detail else ""))
    v = verdict(results)
    print(_VERDICT[v])
    return {PASS: 0, WARN: 0, INCONCLUSIVE: 4, FAIL: 3}[v]


def _fix_streams() -> None:
    # Under pythonw.exe (used for the elevated GUI) there is no console: stdout/stderr are None.
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if stream is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
        elif hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _progress_printer():
    last = {}

    def progress(name: str, done: int, total: int) -> None:
        pct = int(done * 100 / total) if total else 0
        if last.get(name) != pct and (pct % 10 == 0 or pct == 100):
            last[name] = pct
            print(f"  downloading {name}: {pct}%")
    return progress


def main(argv: list[str] | None = None) -> int:
    _fix_streams()
    try:
        return _main(argv)
    except SystemExit:
        raise
    except BaseException:
        # Last resort so a windowless (pythonw) crash is never silent.
        CRASH_LOG.write_text(traceback.format_exc(), encoding="utf-8")
        raise


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phantomx",
                                description="Whole-device Tor with a fail-closed lock (Windows, macOS, Linux).")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("setup", help="download + verify + install tor and sing-box (automatic)")
    s.add_argument("--tor-archive", type=Path, help="manual mode: a Tor Expert Bundle you downloaded")
    s.add_argument("--singbox-archive", type=Path, help="manual mode: a sing-box archive you downloaded")
    sub.add_parser("install-browser", help="download + verify + install Tor Browser")
    sub.add_parser("start", help="lock the device and route everything through Tor")
    sub.add_parser("stop", help="stop and restore normal networking")
    sub.add_parser("restore", help="same as stop: emergency unlock")
    sub.add_parser("status")
    sub.add_parser("check", help="run the leak tests")
    sub.add_parser("logs", help="show the last lines of the tor and sing-box logs (for troubleshooting)")
    sub.add_parser("newnym", help="new Tor circuits for new connections")
    b = sub.add_parser("bridges", help="set bridge lines from a text file, or turn bridges off")
    g = b.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", type=Path)
    g.add_argument("--off", action="store_true")
    m = sub.add_parser("mode", help="privacy mode: balanced (faster, default) or strict (slower)")
    m.add_argument("value", choices=["balanced", "strict"])
    bp = sub.add_parser("bypass", help="split tunnel: apps that go DIRECT with your real IP")
    bp_sub = bp.add_subparsers(dest="action", required=True)
    bp_sub.add_parser("list")
    bp_sub.add_parser("add").add_argument("path")
    bp_sub.add_parser("remove").add_argument("path")
    sub.add_parser("gui", help="open the control panel (default)")
    return p


def _main(argv: list[str] | None) -> int:
    args = _build_parser().parse_args(argv)
    cmd = args.cmd or "gui"
    raw_args = list(argv) if argv is not None else sys.argv[1:]

    print_logo()

    if not is_admin():
        if cmd == "gui" or current_os() != WINDOWS:
            print("Administrator/root rights are required; requesting them...")
            if relaunch_elevated(raw_args or ["gui"]):  # POSIX: exec sudo, does not return
                return 0
            print("ERROR: could not obtain Administrator rights.", file=sys.stderr)
            return 2
        print("ERROR: run this command from an Administrator PowerShell "
              "(or just run `phantomx` to open the control panel).", file=sys.stderr)
        return 2

    if cmd == "gui":
        print("Opening the control panel...")
        from .gui import run_gui
        run_gui()
        return 0

    engine = Engine(log=print)
    try:
        from . import installer
        if cmd == "setup":
            if args.tor_archive or args.singbox_archive:
                if not (args.tor_archive and args.singbox_archive):
                    print("ERROR: manual mode needs both --tor-archive and --singbox-archive", file=sys.stderr)
                    return 2
                installer.install(Layout(), make_ops(), args.tor_archive, args.singbox_archive,
                                  confirm=lambda msg: input(msg + " [y/N] ").strip().lower() == "y")
            else:
                installer.install_auto(engine.layout, engine.ops, print, _progress_printer())
            return 0
        if cmd == "install-browser":
            installer.install_tor_browser(engine.layout, engine.ops, print, _progress_printer())
            return 0
        if cmd == "start":
            if not installer.is_installed(engine.layout):
                print("First run: installing verified tor + sing-box...")
                installer.install_auto(engine.layout, engine.ops, print, _progress_printer())
            last = [-1]

            def progress(pct: int) -> None:
                if pct != last[0]:
                    last[0] = pct
                    print(f"tor: {pct}%")
            return _print_checks(engine.start(progress))
        if cmd in ("stop", "restore"):
            engine.stop()
            return 0
        if cmd == "status":
            st = engine.status()
            print(f"phase={st.phase or 'off'} firewall_locked={st.firewall_locked} "
                  f"sing-box={st.singbox_alive} tor={st.tor_alive} bootstrap={st.bootstrap}% "
                  f"last_leak_test={st.verified or 'none'}")
            if st.phase == "unsafe":
                print("UNSAFE: the firewall lock is NOT in place; your connection may be exposed. Run `phantomx stop`.")
            elif st.phase == "running" and st.verified not in ("pass", "warn"):
                print("NOT VERIFIED: run `phantomx check` before trusting this session.")
            for n in st.notes:
                print(n)
            return 0
        if cmd == "check":
            return _print_checks(engine.run_checks())
        if cmd == "logs":
            from .winutil import tail_files
            L = engine.layout
            for title, files in (("tor", [L.tor_log, L.tor_console]),
                                 ("sing-box", [L.singbox_log, L.singbox_console])):
                print(f"===== {title} =====")
                print(tail_files(files, 25))
            return 0
        if cmd == "newnym":
            engine.new_identity()
            return 0
        if cmd == "mode":
            settings = engine.settings()
            settings.privacy_mode = args.value
            save_settings(engine.layout.config, settings)
            print(f"Privacy mode: {args.value}. Applies on the next start.")
            return 0
        if cmd == "bypass":
            settings = engine.settings()
            if args.action == "list":
                print("\n".join(settings.bypass_apps) or "(none)")
                return 0
            if args.action == "add":
                path = normalize_app_path(args.path)
                if path not in settings.bypass_apps:
                    settings.bypass_apps.append(path)
                print(f"WARNING: {path} will use your REAL IP (not hidden).")
            else:
                target = os.path.normcase(os.path.realpath(args.path))
                settings.bypass_apps = [a for a in settings.bypass_apps if os.path.normcase(a) != target]
            save_settings(engine.layout.config, settings)
            print("Saved; applies on the next start.")
            return 0
        if cmd == "bridges":
            settings = engine.settings()
            if args.off:
                settings.use_bridges = False
            else:
                settings.bridges = [l.strip() for l in args.file.read_text(encoding="utf-8").splitlines() if l.strip()]
                settings.use_bridges = True
                from .torconf import bridge_lines
                bridge_lines(settings)
            save_settings(engine.layout.config, settings)
            print("Saved; applies on the next start.")
            return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
