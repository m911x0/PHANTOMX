"""Linux and macOS backends.

Fail-closed lock without per-program firewall rules:
sing-box is started with a dedicated group id (PHANTOMX_GID). The firewall then allows
outbound traffic only from (a) loopback, (b) the tunnel interface, (c) DHCP, and (d) sockets
owned by that gid, i.e. sing-box itself, which carries tor's relay connections. Every other
outbound packet is dropped.

  Linux: nftables table `inet phantomx` with an output chain, policy drop. In nftables a
         packet must be accepted by every base chain on a hook, so no other table can
         override our drop.
  macOS: pf rules in anchor `com.apple/phantomx` (evaluated by the stock /etc/pf.conf via
         `anchor "com.apple/*"`). pf is enabled with a reference token, released on restore.

Unlike Windows, these rules are not persistent: after a reboot the lock (and the tunnel)
are gone and the machine is back to normal networking.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .osinfo import LINUX, MACOS, current_os

PHANTOMX_GID = 64927
NFT_TABLE = "phantomx"
PF_ANCHOR = "com.apple/phantomx"


class PosixError(RuntimeError):
    pass


def _run(args: list[str], input: str | None = None, check: bool = True, timeout: float = 30) -> str:
    proc = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise PosixError(f"{' '.join(args)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout + proc.stderr


# ---------------------------------------------------------------- ops
class PosixOps:
    runner = None

    def __init__(self, os_name: str | None = None):
        self.os = os_name or current_os()

    def is_admin(self) -> bool:
        return os.geteuid() == 0

    def secure_root(self, path) -> None:
        p = Path(path)
        if p.exists():
            st = p.stat()
            if st.st_uid != 0:
                raise PosixError(f"{p} exists but is not owned by root. Delete it manually, then try again.")
        else:
            p.mkdir(parents=True, mode=0o700)
        os.chmod(p, 0o700)

    def _exe_of(self, pid: int) -> str | None:
        if self.os == LINUX:
            try:
                return os.readlink(f"/proc/{pid}/exe")
            except OSError:
                return None
        out = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True).stdout.strip()
        return out or None

    def alive(self, pid: int, path) -> bool:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        exe = self._exe_of(int(pid))
        return bool(exe) and os.path.realpath(exe) == os.path.realpath(str(path))

    def kill(self, pid: int, path) -> bool:
        if not self.alive(pid, path):
            return False
        os.kill(int(pid), signal.SIGTERM)
        for _ in range(30):
            time.sleep(0.1)
            if not self.alive(pid, path):
                return True
        os.kill(int(pid), signal.SIGKILL)
        return True

    def flush_dns(self) -> None:
        cmds = ([["resolvectl", "flush-caches"]] if self.os == LINUX
                else [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]])
        for c in cmds:
            if shutil.which(c[0]):
                subprocess.run(c, capture_output=True)

    def tun_interface(self, name: str, address: str) -> str | None:
        """Linux: the configured name. macOS: the utunN that carries our tunnel address."""
        if self.os == LINUX:
            return name if Path(f"/sys/class/net/{name}").exists() else None
        ip = address.split("/")[0]
        current = None
        for line in _run(["ifconfig"], check=False).splitlines():
            m = re.match(r"^(\S+):", line)
            if m:
                current = m.group(1)
            elif current and current.startswith("utun") and f"inet {ip} " in line + " ":
                return current
        return None

    def adapter_up(self, name: str, address: str = "") -> bool:
        iface = self.tun_interface(name, address)
        if not iface:
            return False
        if self.os == LINUX:
            state = Path(f"/sys/class/net/{iface}/operstate").read_text().strip()
            return state in ("up", "unknown")
        return True

    def physical(self, tun_name: str) -> tuple[str | None, str | None]:
        """(ipv4, interface) of the real network adapter."""
        if self.os == LINUX:
            for line in _run(["ip", "-4", "route", "show", "default"], check=False).splitlines():
                m = re.search(r"\bdev (\S+)", line)
                if m and m.group(1) != tun_name:
                    dev = m.group(1)
                    addr = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _run(["ip", "-4", "-o", "addr", "show", "dev", dev], check=False))
                    return (addr.group(1) if addr else None), dev
            return None, None
        current, info = None, {}
        for line in _run(["ifconfig"], check=False).splitlines():
            m = re.match(r"^(\S+):", line)
            if m:
                current = m.group(1)
                info[current] = {}
            elif current:
                a = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", line)
                if a and not a.group(1).startswith(("127.", "169.254.")):
                    info[current]["ip"] = a.group(1)
                if "status: active" in line:
                    info[current]["active"] = True
        for name, d in info.items():
            if name.startswith("en") and d.get("ip") and d.get("active"):
                return d["ip"], name
        return None, None

    def physical_ipv4(self, tun_name: str) -> str | None:
        return self.physical(tun_name)[0]

    def authenticode(self, path) -> tuple[str, str]:
        return "n/a", ""

    def tor_project_signed(self, path) -> bool:
        return False  # posix builds are verified by hash against the GPG-verified bundle instead


# ---------------------------------------------------------------- Linux firewall
def check_gid_free(gid: int = PHANTOMX_GID) -> None:
    """The firewall trusts this gid; refuse if a real group already uses it (PX09)."""
    try:
        import grp
        existing = grp.getgrgid(gid)
    except (ImportError, KeyError):
        return
    raise PosixError(f"group id {gid} is already used by group '{existing.gr_name}'. "
                     "PhantomX trusts that gid in its firewall rules, so it refuses to run.")


def nft_ruleset(tun_name: str, gid: int = PHANTOMX_GID) -> str:
    """One atomic nft transaction (PX01): `nft -f` applies the whole file or nothing.
    The leading `table` + `delete table` replace any previous version without a gap.
    FORWARD is covered too (PX04): containers/VMs may only go out through the tunnel."""
    return f"""table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    meta skgid {gid} accept
    oifname "{tun_name}" accept
    udp sport 68 udp dport 67 accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    oifname "{tun_name}" accept
    iifname "{tun_name}" accept
  }}
}}
"""


def nft_enforcing(listing: str, tun_name: str, gid: int = PHANTOMX_GID) -> bool:
    """Independent check of what the kernel actually holds (`nft list table`)."""
    return (listing.count("policy drop") >= 2 and "hook output" in listing and "hook forward" in listing
            and f"skgid {gid}" in listing and f'"{tun_name}"' in listing)


class LinuxFirewall:
    def __init__(self, tun_name: str = "PhantomX"):
        self.tun_name = tun_name

    def snapshot(self) -> dict:
        return {"profiles": [], "rules": []}

    def _listing(self) -> str | None:
        proc = subprocess.run(["nft", "list", "table", "inet", NFT_TABLE], capture_output=True, text=True)
        return proc.stdout if proc.returncode == 0 else None

    def lockdown(self, disable_rules, allow_programs) -> None:
        if not shutil.which("nft"):
            raise PosixError("nftables (`nft`) is required. Install it (e.g. `sudo apt install nftables`).")
        check_gid_free()
        _run(["nft", "-f", "-"], input=nft_ruleset(self.tun_name))
        listing = self._listing()
        if not listing or not nft_enforcing(listing, self.tun_name):
            raise PosixError("nftables lock could not be verified in the kernel ruleset")

    def allow_tunnel(self, alias: str, address: str = "") -> None:
        pass  # the tunnel interface name is already allowed in the ruleset

    def restore(self, snapshot) -> None:
        _run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)  # absent table is fine

    def status(self) -> dict:
        enabled = bool(shutil.which("nft"))
        listing = self._listing() if enabled else None
        return {"enabled": enabled, "locked": bool(listing) and nft_enforcing(listing, self.tun_name),
                "ours": 1 if listing else 0, "unmanaged": [], "active": []}


# ---------------------------------------------------------------- macOS firewall
def pf_rules(tun_iface: str | None, gid: int = PHANTOMX_GID) -> str:
    lines = [
        "pass out quick on lo0 all",
        f"pass out quick group {gid}",
        "pass out quick proto udp from any port 68 to any port 67",
    ]
    if tun_iface:
        lines.append(f"pass out quick on {tun_iface} all")
    lines.append("block drop out quick all")
    return "\n".join(lines) + "\n"


class MacFirewall:
    def __init__(self, token_path: Path, ops: PosixOps | None = None, tun_address: str = ""):
        self.token_path = Path(token_path)
        self.ops = ops or PosixOps(MACOS)
        self.tun_address = tun_address

    def snapshot(self) -> dict:
        return {"profiles": [], "rules": []}

    def _load(self, iface: str | None) -> None:
        _run(["pfctl", "-a", PF_ANCHOR, "-f", "-"], input=pf_rules(iface))

    def lockdown(self, disable_rules, allow_programs) -> None:
        check_gid_free()
        self._load(None)
        if not self.token_path.exists():
            out = _run(["pfctl", "-E"], check=False)
            m = re.search(r"Token\s*:\s*(\d+)", out)
            if not m:
                raise PosixError(f"could not enable pf: {out.strip()}")
            self.token_path.write_text(m.group(1))
        if not self.status()["locked"]:
            raise PosixError("pf lock could not be verified (pf disabled, or the anchor is not evaluated "
                             "by the main ruleset in /etc/pf.conf)")

    def allow_tunnel(self, alias: str, address: str = "") -> None:
        iface = self.ops.tun_interface(alias, address or self.tun_address)
        if not iface:
            raise PosixError("tunnel interface (utun) not found")
        self._load(iface)

    def restore(self, snapshot) -> None:
        _run(["pfctl", "-a", PF_ANCHOR, "-F", "all"], check=False)
        if self.token_path.exists():
            _run(["pfctl", "-X", self.token_path.read_text().strip()], check=False)
            self.token_path.unlink(missing_ok=True)

    def status(self) -> dict:
        """PX05: report what pf really enforces.
        enabled = pf can be used here (pfctl present; lockdown turns pf on itself).
        locked  = pf is running AND our anchor holds the block rule AND the main ruleset
                  actually evaluates `com.apple/*` anchors."""
        return pf_status(_run(["pfctl", "-s", "info"], check=False),
                         _run(["pfctl", "-s", "rules"], check=False),
                         _run(["pfctl", "-a", PF_ANCHOR, "-s", "rules"], check=False),
                         bool(shutil.which("pfctl")))


def pf_status(info: str, main_rules: str, anchor_rules: str, available: bool = True) -> dict:
    running = "Status: Enabled" in info
    anchored = bool(re.search(r'anchor "com\.apple/\*"', main_rules))
    has_block = "block drop out quick all" in anchor_rules
    return {"enabled": available, "running": running,
            "locked": running and anchored and has_block,
            "ours": 1 if anchor_rules.strip() else 0, "unmanaged": [], "active": []}


# ---------------------------------------------------------------- elevation
def relaunch_with_sudo(args: list[str]) -> None:
    """Replace this process with `sudo python -m phantomx <args>` (asks for the password)."""
    keep = "DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,LANG"
    os.execvp("sudo", ["sudo", f"--preserve-env={keep}", sys.executable, "-m", "phantomx", *args])
