"""Leak tests run after start (and on demand).

The bypass tests deliberately try to leave WITHOUT the tunnel. They must FAIL to connect.
Note: if a bypass test unexpectedly succeeds, that one test packet did leave directly —
which is exactly the leak it reports.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import struct
import time
import urllib.request
import uuid
from dataclasses import dataclass

from .config import Settings
from .firewall import firewall_locked
from .osinfo import LINUX, MACOS, current_os

CHECK_URL = "https://check.torproject.org/api/ip"
PASS, WARN, FAIL = "pass", "warn", "fail"


@dataclass(frozen=True)
class CheckResult:
    key: str
    title: str
    status: str
    detail: str = ""


class SystemProbe:
    def __init__(self, ops, firewall, settings: Settings):
        self.ops, self.firewall, self.settings = ops, firewall, settings
        self._iface: str | None = None

    def firewall_status(self) -> dict:
        return self.firewall.status()

    def physical_ipv4(self) -> str | None:
        ip, self._iface = self.ops.physical(self.settings.tun_name)
        return ip

    def resolve_ipv4(self, name: str) -> list[str]:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})

    def tor_check(self) -> dict:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # system route only
        with opener.open(CHECK_URL, timeout=30) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            return json.loads(resp.read(4096).decode("utf-8"))

    def _pin_to_physical(self, s: socket.socket, bind_ip: str) -> None:
        """Force the socket out of the physical NIC, bypassing the tunnel's routes.
        Windows' strong-host model does that when the source IP is bound; Linux and macOS
        use a weak-host model, so the socket is pinned to the interface itself."""
        os_name = current_os()
        if os_name == LINUX and self._iface:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), self._iface.encode() + b"\x00")
        elif os_name == MACOS and self._iface:
            s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(self._iface))  # IP_BOUND_IF
        s.bind((bind_ip, 0))

    def tcp_connect(self, bind_ip: str | None, host: str, port: int, family=socket.AF_INET) -> bool:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            if bind_ip:
                self._pin_to_physical(s, bind_ip)
            s.connect((host, port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def udp_dns_probe(self, bind_ip: str, server: str) -> bool:
        query = struct.pack(">HHHHHH", 0x4f53, 0x0100, 1, 0, 0, 0)
        query += b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
        query += struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            self._pin_to_physical(s, bind_ip)
            s.sendto(query, (server, 53))
            s.recvfrom(512)
            return True
        except OSError:
            return False
        finally:
            s.close()


TOR_CHECK_ATTEMPTS = 4
TOR_CHECK_RETRY_DELAY = 5


def run_checks(probe, settings: Settings, sleep=time.sleep) -> list[CheckResult]:
    results: list[CheckResult] = []

    try:
        fw = probe.firewall_status()
        locked = firewall_locked(fw)
        results.append(CheckResult("firewall", "Firewall lock (no direct outbound)",
                                   PASS if locked else FAIL,
                                   "" if locked else "default outbound policy is not Block"))
        extra = fw["unmanaged"]
        results.append(CheckResult(
            "rules", "Unmanaged outbound allow rules",
            WARN if extra else PASS,
            (f"{len(extra)} rule(s) from Group Policy or another store could allow direct traffic if the tunnel stops: "
             + ", ".join(extra[:5])) if extra else ""))
    except Exception as exc:  # noqa: BLE001 - report, never crash the check run
        results.append(CheckResult("firewall", "Firewall lock (no direct outbound)", FAIL, str(exc)))

    apps = settings.bypass_apps
    results.append(CheckResult(
        "split", "Apps bypassing Tor (split tunnel)", WARN if apps else PASS,
        ("these use your REAL IP by your choice: " + ", ".join(a.replace("/", "\\").rsplit("\\", 1)[-1] for a in apps))
        if apps else "none"))

    fake = ipaddress.ip_network(settings.fakeip_range)
    try:
        ips = probe.resolve_ipv4(f"{uuid.uuid4().hex[:16]}.example.com")
        ok = bool(ips) and all(ipaddress.ip_address(ip) in fake for ip in ips)
        results.append(CheckResult("dns", "DNS stays inside the tunnel", PASS if ok else FAIL,
                                   "" if ok else f"resolved to real addresses: {', '.join(ips)}"))
    except OSError as exc:
        results.append(CheckResult("dns", "DNS stays inside the tunnel", WARN, f"lookup failed: {exc}"))

    try:
        # Right after "Bootstrapped 100%" tor may not have an exit circuit for this port yet,
        # so the first stream can be closed (seen as SSL EOF). Retry before reporting.
        for attempt in range(TOR_CHECK_ATTEMPTS):
            try:
                body = probe.tor_check()
                break
            except Exception:  # noqa: BLE001
                if attempt == TOR_CHECK_ATTEMPTS - 1:
                    raise
                sleep(TOR_CHECK_RETRY_DELAY)
        ip = body.get("IP") if isinstance(body, dict) else None
        ok = isinstance(body, dict) and body.get("IsTor") is True and isinstance(ip, str)
        if ok:
            ipaddress.ip_address(ip)
        results.append(CheckResult("tor", "Traffic exits through Tor", PASS if ok else FAIL,
                                   f"exit IP: {ip}" if ok else "check.torproject.org did not confirm Tor"))
    except Exception as exc:  # noqa: BLE001
        results.append(CheckResult("tor", "Traffic exits through Tor", FAIL, str(exc)))

    phys = probe.physical_ipv4()
    if not phys:
        results.append(CheckResult("bypass", "Direct exit attempt from the physical NIC", WARN,
                                   "no physical network interface found to test"))
    else:
        leaked = probe.tcp_connect(phys, "1.1.1.1", 443)
        results.append(CheckResult("bypass", "Direct TCP exit attempt (physical NIC)",
                                   FAIL if leaked else PASS,
                                   "direct connection succeeded: LEAK!" if leaked else "blocked"))
        leaked_udp = probe.udp_dns_probe(phys, "1.1.1.1")
        results.append(CheckResult("udp", "Direct UDP exit attempt",
                                   FAIL if leaked_udp else PASS,
                                   "a direct UDP reply arrived: LEAK!" if leaked_udp else "blocked"))

    leaked6 = probe.tcp_connect(None, "2606:4700:4700::1111", 443, socket.AF_INET6)
    results.append(CheckResult("ipv6", "IPv6 exit attempt", FAIL if leaked6 else PASS,
                               "IPv6 connection succeeded: possible LEAK!" if leaked6 else "blocked"))
    return results


def verdict(results: list[CheckResult]) -> str:
    statuses = {r.status for r in results}
    return FAIL if FAIL in statuses else WARN if WARN in statuses else PASS
