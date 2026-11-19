"""sing-box TUN configuration: every TCP connection on the device goes to tor's SOCKS port.

Design (target: sing-box 1.12.x config format; `sing-box check` validates it before start):
- TUN with auto_route + strict_route captures all IPv4 traffic.
- DNS is answered locally with FakeIP, so no DNS query ever leaves the machine. The real
  hostname is handed to tor inside SOCKS (remote resolution), which also makes .onion work.
- UDP is rejected (Tor carries TCP only). QUIC/WebRTC fall back or fail closed.
- Only tor.exe itself (and its pluggable transports) may go direct, matched by full path.
"""
from __future__ import annotations

import json
import subprocess
from typing import Callable

from .config import Settings
from .osinfo import MACOS, WINDOWS
from .paths import Layout
from .posix import PHANTOMX_GID
from .winutil import _FLAGS, spawn_detached, tail_files


class SingBoxError(RuntimeError):
    pass


def build_config(settings: Settings, layout: Layout, direct_paths: list[str],
                 pt_domains: list[str]) -> dict:
    # No `detour`: an empty detour already dials directly (sing-box rejects detour=direct at runtime).
    # sing-box forbids FakeIP as the default server, so the default is tor's own DNSPort
    # (loopback: resolution still happens inside Tor). A/AAAA queries from apps get FakeIP.
    dns_servers: list[dict] = [
        {"type": "udp", "tag": "tor-dns", "server": "127.0.0.1", "server_port": settings.dns_port},
        {"type": "fakeip", "tag": "fakeip", "inet4_range": settings.fakeip_range},
    ]
    dns_rules: list[dict] = []
    if pt_domains:
        # Pluggable transports (snowflake/webtunnel) must resolve their own rendezvous hosts.
        dns_servers.append({"type": "udp", "tag": "pt-dns", "server": settings.bootstrap_dns})
        dns_rules.append({"domain": list(pt_domains), "server": "pt-dns"})
    dns_rules.append({"query_type": ["A", "AAAA"], "server": "fakeip"})

    rules: list[dict] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    if direct_paths:
        rules.append({"process_path": list(direct_paths), "outbound": "direct"})
    rules += [
        {"network": "udp", "action": "reject"},
        {"ip_cidr": [settings.fakeip_range], "outbound": "tor"},
        {"ip_is_private": True, "action": "reject"},
    ]

    tun = {"type": "tun", "tag": "tun-in", "address": [settings.tun_address], "mtu": 1500,
           "auto_route": True, "strict_route": True, "stack": "gvisor"}
    if layout.os != MACOS:  # macOS only allows utunN names; sing-box picks a free one
        tun["interface_name"] = settings.tun_name

    return {
        # "fatal": connection errors at error/warn level include destination hostnames, i.e.
        # browsing history on disk. Only crashes are logged.
        "log": {"level": "fatal", "timestamp": True, "output": str(layout.singbox_log)},
        "dns": {"servers": dns_servers, "rules": dns_rules, "final": "tor-dns", "strategy": "ipv4_only"},
        "inbounds": [tun],
        "outbounds": [
            {"type": "socks", "tag": "tor", "server": "127.0.0.1",
             "server_port": settings.socks_port, "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": rules, "final": "tor", "auto_detect_interface": True,
                  "default_domain_resolver": "tor-dns"},
    }


class SingBoxService:
    def __init__(self, layout: Layout, spawn: Callable = spawn_detached, run: Callable = subprocess.run):
        self.layout = layout
        self.spawn = spawn
        self._run = run

    def prepare(self, config: dict) -> None:
        self.layout.run.mkdir(parents=True, exist_ok=True)
        self.layout.singbox_config.write_text(json.dumps(config, indent=2), encoding="utf-8")
        self.layout.singbox_log.write_text("", encoding="utf-8")

    def check(self) -> None:
        proc = self._run(
            [str(self.layout.singbox_exe), "check", "-c", str(self.layout.singbox_config)],
            capture_output=True, timeout=30, creationflags=_FLAGS,
        )
        if proc.returncode != 0:
            out = (proc.stderr or b"").decode("utf-8", "replace") + (proc.stdout or b"").decode("utf-8", "replace")
            raise SingBoxError("sing-box rejected the generated config:\n" + out.strip())

    def start(self) -> int:
        return self.spawn(
            [self.layout.singbox_exe, "run", "-c", self.layout.singbox_config, "-D", self.layout.run],
            cwd=self.layout.singbox_dir, output=self.layout.singbox_console,
            **({} if self.layout.os == WINDOWS else {"gid": PHANTOMX_GID}),
        )

    def log_tail(self, n: int = 8) -> str:
        return tail_files([self.layout.singbox_log, self.layout.singbox_console], n)
