"""Leak tests run after start (and on demand).

The bypass tests deliberately try to leave WITHOUT the tunnel. They must FAIL to connect.
Note: if a bypass test unexpectedly succeeds, that one test packet did leave directly —
which is exactly the leak it reports.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import socket
import struct
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .config import Settings
from .firewall import firewall_locked
from .osinfo import LINUX, MACOS, WINDOWS, current_os

IP_UNICAST_IF = 31

CHECK_URL = "https://check.torproject.org/api/ip"
PASS, WARN, INCONCLUSIVE, FAIL = "pass", "warn", "inconclusive", "fail"


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
        with opener.open(CHECK_URL, timeout=TOR_CHECK_TIMEOUT) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            return json.loads(resp.read(4096).decode("utf-8"))

    def _pin_to_physical(self, s: socket.socket, bind_ip: str) -> None:
        """Force the socket out of the physical NIC, bypassing the tunnel's routes, so the test
        is a REAL bypass attempt (PX02): the socket is explicitly pinned to the interface on
        every OS, and also bound to its source address."""
        os_name = current_os()
        if os_name == WINDOWS and self._iface is not None:
            # IP_UNICAST_IF (31): interface index, network byte order, for IPv4 sockets.
            s.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(int(self._iface)))
        elif os_name == LINUX and self._iface:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), self._iface.encode() + b"\x00")
        elif os_name == MACOS and self._iface:
            s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(self._iface))  # IP_BOUND_IF
        s.bind((bind_ip, 0))

    def tcp_connect(self, bind_ip: str | None, host: str, port: int, family=socket.AF_INET) -> Outcome:
        """A real bypass attempt. Setup failures are TEST_ERROR, never 'blocked' (F02)."""
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if family == socket.AF_INET6 and _err(exc) in _NO_FAMILY:
                return Outcome(BLOCKED, "IPv6 is not available on this system")
            return Outcome(TEST_ERROR, f"could not create socket: {exc}")
        s.settimeout(4)
        try:
            try:
                if bind_ip:
                    self._pin_to_physical(s, bind_ip)
            except OSError as exc:
                return Outcome(TEST_ERROR, f"could not pin the test to the physical adapter: {exc}")
            try:
                s.connect((host, port))
                return Outcome(LEAKED, "direct connection succeeded")
            except OSError as exc:
                return classify_send_error(exc)
        finally:
            s.close()

    def udp_dns_probe(self, bind_ip: str, server: str) -> Outcome:
        query = struct.pack(">HHHHHH", 0x4f53, 0x0100, 1, 0, 0, 0)
        query += b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
        query += struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            try:
                self._pin_to_physical(s, bind_ip)
            except OSError as exc:
                return Outcome(TEST_ERROR, f"could not pin the test to the physical adapter: {exc}")
            try:
                s.sendto(query, (server, 53))
            except OSError as exc:
                return classify_send_error(exc)
            try:
                s.recvfrom(512)
                return Outcome(LEAKED, "a direct UDP reply arrived")
            except OSError as exc:
                return classify_send_error(exc)
        finally:
            s.close()


# ---- probe outcomes (F02): three states, because "the test broke" is not "the firewall blocked"
BLOCKED, LEAKED, TEST_ERROR = "blocked", "leaked", "test_error"


@dataclass(frozen=True)
class Outcome:
    state: str
    detail: str = ""


def _err(exc: OSError) -> int | None:
    return getattr(exc, "winerror", None) or exc.errno


_BLOCKED_ERRS = {e for e in (errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH,
                             errno.ENETDOWN, errno.ETIMEDOUT)} | {10013, 10050, 10051, 10060, 10065}
_REPLY_ERRS = {errno.ECONNREFUSED, errno.ECONNRESET} | {10054, 10061}  # an answer came back: packets left
_NO_FAMILY = {errno.EAFNOSUPPORT} | {10047}


def classify_send_error(exc: OSError) -> Outcome:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return Outcome(BLOCKED, "no answer (dropped)")
    code = _err(exc)
    if code in _REPLY_ERRS:
        return Outcome(LEAKED, f"a remote host answered ({exc})")
    if code in _BLOCKED_ERRS:
        return Outcome(BLOCKED, f"refused locally ({exc.strerror or code})")
    return Outcome(TEST_ERROR, f"unexpected error: {exc}")


def as_outcome(value) -> Outcome:
    """Accept legacy booleans (True = leaked) from simple probes, e.g. in tests."""
    if isinstance(value, Outcome):
        return value
    return Outcome(LEAKED, "connection succeeded") if value else Outcome(BLOCKED, "blocked")


TOR_CHECK_ATTEMPTS = 4
TOR_CHECK_RETRY_DELAY = 3
TOR_CHECK_TIMEOUT = 15


def _check_firewall(probe) -> list[CheckResult]:
    try:
        fw = probe.firewall_status()
    except Exception as exc:  # noqa: BLE001 - report, never crash the check run
        return [CheckResult("firewall", "Firewall lock (no direct outbound)", FAIL, str(exc))]
    locked = firewall_locked(fw)
    out = [CheckResult("firewall", "Firewall lock (no direct outbound)", PASS if locked else FAIL,
                       "" if locked else "the firewall does not report the lock as enforced")]
    gpo = list(fw.get("unmanaged_gpo") or [])
    extra = [n for n in fw.get("unmanaged") or [] if n not in gpo]
    if gpo:
        # PX03: a policy-managed allow rule can override the local lock, so protection
        # cannot be claimed on such a machine.
        out.append(CheckResult(
            "rules", "Outbound allow rules enforced by Group Policy", FAIL,
            f"{len(gpo)} policy rule(s) PhantomX cannot disable may allow direct traffic: " + ", ".join(gpo[:5])))
    else:
        out.append(CheckResult(
            "rules", "Unmanaged outbound allow rules", WARN if extra else PASS,
            (f"{len(extra)} system/service rule(s) PhantomX cannot disable; they only matter if the tunnel "
             "stops: " + ", ".join(extra[:5])) if extra else ""))
    return out


def _check_split(settings) -> list[CheckResult]:
    apps = settings.bypass_apps
    return [CheckResult(
        "split", "Apps bypassing Tor (split tunnel)", WARN if apps else PASS,
        ("these use your REAL IP by your choice: " + ", ".join(a.replace("/", "\\").rsplit("\\", 1)[-1] for a in apps))
        if apps else "none")]


def _check_dns(probe, settings) -> list[CheckResult]:
    fake = ipaddress.ip_network(settings.fakeip_range)
    try:
        ips = probe.resolve_ipv4(f"{uuid.uuid4().hex[:16]}.example.com")
    except OSError as exc:
        return [CheckResult("dns", "DNS stays inside the tunnel", INCONCLUSIVE, f"lookup failed: {exc}")]
    ok = bool(ips) and all(ipaddress.ip_address(ip) in fake for ip in ips)
    return [CheckResult("dns", "DNS stays inside the tunnel", PASS if ok else FAIL,
                        "" if ok else f"resolved to real addresses: {', '.join(ips)}")]


def _check_tor(probe, sleep) -> list[CheckResult]:
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
        return [CheckResult("tor", "Traffic exits through Tor", PASS if ok else FAIL,
                            f"exit IP: {ip}" if ok else "check.torproject.org did not confirm Tor")]
    except Exception as exc:  # noqa: BLE001 - check site unreachable: not proof of a leak, not proof of Tor
        return [CheckResult("tor", "Traffic exits through Tor", INCONCLUSIVE, str(exc))]


def _check_bypass(probe) -> list[CheckResult]:
    try:
        phys = probe.physical_ipv4()
    except Exception as exc:  # noqa: BLE001
        phys, phys_err = None, str(exc)
    else:
        phys_err = "no physical network interface found to test"
    if not phys:
        return [CheckResult("bypass", "Direct exit attempt from the physical NIC", INCONCLUSIVE, phys_err)]
    return [_probe_result("bypass", "Direct TCP exit attempt (physical NIC)",
                          as_outcome(probe.tcp_connect(phys, "1.1.1.1", 443))),
            _probe_result("udp", "Direct UDP exit attempt", as_outcome(probe.udp_dns_probe(phys, "1.1.1.1")))]


def _check_ipv6(probe) -> list[CheckResult]:
    return [_probe_result("ipv6", "IPv6 exit attempt",
                          as_outcome(probe.tcp_connect(None, "2606:4700:4700::1111", 443, socket.AF_INET6)))]


def run_checks(probe, settings: Settings, sleep=time.sleep, on_result=None) -> list[CheckResult]:
    """All checks, the slow network ones IN PARALLEL: total time is the slowest single check
    (worst case ~1 min for an unreachable check site), not their sum. `on_result(result)` is
    called as each one finishes so the UI can show live progress. Results keep a fixed order."""
    tasks = [
        lambda: _check_firewall(probe),
        lambda: _check_split(settings),
        lambda: _check_dns(probe, settings),
        lambda: _check_tor(probe, sleep),
        lambda: _check_bypass(probe),
        lambda: _check_ipv6(probe),
    ]

    def run(task):
        try:
            res = task()
        except Exception as exc:  # noqa: BLE001 - a crashing check is inconclusive, never a pass
            res = [CheckResult("internal", "Leak test", INCONCLUSIVE, f"check crashed: {exc}")]
        if on_result:
            for r in res:
                try:
                    on_result(r)
                except Exception:  # noqa: BLE001
                    pass
        return res

    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(run, t) for t in tasks]
        return [r for f in futures for r in f.result()]


def _probe_result(key: str, title: str, o: Outcome) -> CheckResult:
    status = {BLOCKED: PASS, LEAKED: FAIL, TEST_ERROR: INCONCLUSIVE}[o.state]
    prefix = {BLOCKED: "blocked", LEAKED: "LEAK", TEST_ERROR: "test could not run"}[o.state]
    return CheckResult(key, title, status, f"{prefix}: {o.detail}" if o.detail and o.detail != prefix else prefix)


def verdict(results: list[CheckResult]) -> str:
    """FAIL > INCONCLUSIVE > WARN > PASS. WARN is reserved for exceptions the user accepted
    (split tunnel, service rules); anything that could not be verified is INCONCLUSIVE (F05)."""
    statuses = {r.status for r in results}
    for s in (FAIL, INCONCLUSIVE, WARN):
        if s in statuses:
            return s
    return PASS
