"""Installing PhantomX's engine (tor + sing-box) and, optionally, Tor Browser.

`install_auto` downloads and verifies everything itself (see fetch.py).
`install` is the manual path for archives the user downloaded and verified themselves.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Callable

from . import fetch
from .config import Settings, load_settings, save_settings, write_json_atomic
from .integrity import IntegrityError, build_manifest, safe_extract_tar, safe_extract_zip, sha256_file
from .osinfo import LINUX, MACOS, WINDOWS, arch, exe_name
from .paths import Layout

Log = Callable[[str], None]


# ---------------------------------------------------------------- engine
def _install_archives(layout: Layout, ops, tor_archive: Path, singbox_archive: Path, log: Log) -> None:
    staging = layout.root / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        tor_dest = staging / "bin" / "tor-bundle"
        safe_extract_tar(tor_archive, tor_dest)
        tor_exe = tor_dest / "tor" / exe_name("tor", layout.os)
        if not tor_exe.is_file():
            raise IntegrityError(f"tor/{tor_exe.name} not found: is this the Tor Expert Bundle for this OS?")

        sb_tmp = staging / "sb-extract"
        if str(singbox_archive).endswith(".zip"):
            safe_extract_zip(singbox_archive, sb_tmp)
        else:
            safe_extract_tar(singbox_archive, sb_tmp)
        found = list(sb_tmp.rglob(exe_name("sing-box", layout.os)))
        if len(found) != 1:
            raise IntegrityError("expected exactly one sing-box binary in the sing-box archive")
        shutil.copytree(found[0].parent, staging / "bin" / "sing-box")

        if layout.os != WINDOWS:
            for p in (staging / "bin").rglob("*"):
                if p.is_file():
                    os.chown(p, 0, 0)
        else:
            status, subject = ops.authenticode(tor_exe)
            log(f"tor.exe Authenticode: {status} {subject}".strip())

        shutil.rmtree(layout.bin, ignore_errors=True)
        shutil.move(str(staging / "bin"), str(layout.bin))
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    write_json_atomic(layout.manifest, build_manifest(layout.bin))
    if not layout.config.exists():
        save_settings(layout.config, Settings())
    log(f"Installed to {layout.root}")


def install(layout: Layout, ops, tor_archive: Path, singbox_archive: Path,
            confirm: Callable[[str], bool], log: Log = print) -> None:
    """Manual path: archives the user downloaded; the user confirms the hashes."""
    tor_archive, singbox_archive = Path(tor_archive), Path(singbox_archive)
    for a in (tor_archive, singbox_archive):
        if not a.is_file():
            raise IntegrityError(f"file not found: {a}")
    ops.secure_root(layout.root)
    message = (
        "Compare these fingerprints with the officially published values before continuing:\n"
        f"  Tor Expert Bundle : {tor_archive.name}\n    SHA-256 {sha256_file(tor_archive)}\n"
        "    (torproject.org: sha256sums-signed-build.txt + its GPG signature)\n"
        f"  sing-box          : {singbox_archive.name}\n    SHA-256 {sha256_file(singbox_archive)}\n"
        "    (github.com/SagerNet/sing-box/releases)\n"
        "Do the fingerprints match and is the signature verified?"
    )
    if not confirm(message):
        raise IntegrityError("setup cancelled: archives not confirmed")
    _install_archives(layout, ops, tor_archive, singbox_archive, log)


def install_auto(layout: Layout, ops, log: Log = print, progress: fetch.Progress | None = None) -> None:
    """Download, verify (signed Tor hash list / GitHub digest) and install tor + sing-box."""
    ops.secure_root(layout.root)
    cpu = arch()
    log("Checking the latest Tor release and verifying its signed hash list...")
    version, bundle, _ = fetch.tor_artifacts(layout.os, cpu)
    log(f"Tor {version}: signature OK (Tor Browser Developers key {fetch.TOR_KEY_PRIMARY[-16:]}).")
    tag, sb = fetch.singbox_artifact(layout.os, cpu)
    log(f"sing-box {tag}: using GitHub's published SHA-256.")
    tor_file = fetch.download(bundle, layout.downloads, progress)
    log(f"Verified {bundle.name}")
    sb_file = fetch.download(sb, layout.downloads, progress)
    log(f"Verified {sb.name}")
    _install_archives(layout, ops, tor_file, sb_file, log)
    shutil.rmtree(layout.downloads, ignore_errors=True)


def is_installed(layout: Layout) -> bool:
    return layout.manifest.exists() and layout.tor_exe.exists() and layout.singbox_exe.exists()


# ---------------------------------------------------------------- Tor Browser
def real_user() -> tuple[str | None, Path]:
    """(username, home) of the human user, even when running under sudo."""
    if os.name == "nt":
        return None, Path.home()
    import pwd
    name = os.environ.get("SUDO_USER")
    if name and name != "root":
        pw = pwd.getpwnam(name)
        return name, Path(pw.pw_dir)
    return None, Path.home()


def _chown_to_user(path: Path, user: str | None) -> None:
    if not user:
        return
    import pwd
    pw = pwd.getpwnam(user)
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            os.lchown(os.path.join(root, n), pw.pw_uid, pw.pw_gid)
    os.lchown(path, pw.pw_uid, pw.pw_gid)


def windows_desktop() -> Path:
    """The real Desktop folder, which may be redirected (e.g. to OneDrive\\Desktop)."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf) == 0 and buf.value:  # CSIDL_DESKTOPDIRECTORY
            return Path(buf.value)
    except (AttributeError, OSError):
        pass
    return Path.home() / "Desktop"


def default_tor_browser_dir(os_name: str) -> Path:
    _, home = real_user()
    if os_name == MACOS:
        return Path("/Applications/Tor Browser.app")
    if os_name == LINUX:
        return home / "tor-browser"
    # The Windows installer puts it on the Desktop in silent mode, whatever /D says.
    return windows_desktop() / "Tor Browser"


def tor_browser_candidates(os_name: str) -> list[Path]:
    _, home = real_user()
    if os_name == WINDOWS:
        return [windows_desktop() / "Tor Browser", home / "Tor Browser", home / "Desktop" / "Tor Browser"]
    if os_name == MACOS:
        return [Path("/Applications/Tor Browser.app"), home / "Applications" / "Tor Browser.app"]
    return [home / "tor-browser", home / "tor-browser_en-US"]


def find_tor_browser(os_name: str) -> Path | None:
    """An existing Tor Browser install in the usual places, or None."""
    from .browser import find_launcher
    for c in tor_browser_candidates(os_name):
        try:
            find_launcher(str(c), os_name)
            return c
        except FileNotFoundError:
            continue
    return None


def install_tor_browser(layout: Layout, ops, log: Log = print, progress: fetch.Progress | None = None) -> Path:
    """Download + verify (signed Tor hash list) + install Tor Browser for the real user.
    Saves the location in settings. Returns the Tor Browser folder."""
    target = find_tor_browser(layout.os) or default_tor_browser_dir(layout.os)
    if find_tor_browser(layout.os):
        log(f"Tor Browser already present at {target}; using it.")
    else:
        ops.secure_root(layout.root)
        log("Verifying Tor's signed hash list...")
        _, _, tb = fetch.tor_artifacts(layout.os, arch())
        file = fetch.download(tb, layout.downloads, progress)
        log(f"Verified {tb.name}; installing...")
        try:
            if layout.os == WINDOWS:
                # NSIS installer: /S silent, /D target (must be last, unquoted)
                proc = subprocess.run([str(file), "/S", f"/D={target}"], timeout=600)
                found = find_tor_browser(layout.os)
                if proc.returncode != 0 or not found:
                    raise IntegrityError(f"Tor Browser installer failed (exit {proc.returncode})")
                target = found
            elif layout.os == LINUX:
                _install_tb_linux(file, target, layout)
            else:
                _install_tb_macos(file, target)
        finally:
            shutil.rmtree(layout.downloads, ignore_errors=True)
        log(f"Tor Browser installed at {target}")
    settings = load_settings(layout.config)
    settings.tor_browser_dir = str(target)
    save_settings(layout.config, settings)
    return target


def _install_tb_linux(archive: Path, target: Path, layout: Layout) -> None:
    user, _ = real_user()
    staging = Path(tempfile.mkdtemp(dir=layout.root))  # root-only: no symlink games during extraction
    try:
        with tarfile.open(archive, "r:xz") as t:
            t.extractall(staging, filter="data")
        src = staging / "tor-browser"
        if not src.is_dir():
            raise IntegrityError("unexpected Tor Browser archive layout")
        _chown_to_user(src, user)
        if target.exists() or target.is_symlink():
            raise IntegrityError(f"{target} appeared during install; aborting")
        shutil.move(str(src), str(target))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _install_tb_macos(dmg: Path, target: Path) -> None:
    user, _ = real_user()
    mnt = Path(tempfile.mkdtemp())
    subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", str(mnt), str(dmg)],
                   check=True, capture_output=True)
    try:
        apps = list(mnt.glob("*.app"))
        if len(apps) != 1:
            raise IntegrityError("unexpected Tor Browser disk image layout")
        subprocess.run(["ditto", str(apps[0]), str(target)], check=True)
        _chown_to_user(target, user)
    finally:
        subprocess.run(["hdiutil", "detach", str(mnt), "-quiet"], capture_output=True)
        shutil.rmtree(mnt, ignore_errors=True)
