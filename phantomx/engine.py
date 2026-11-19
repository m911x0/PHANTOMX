"""Orchestration. The single rule: lock first, and never unlock except on an explicit Stop.

Start order:
  1. preflight (admin, folder ownership, pinned hashes, firewall enabled)
  2. save firewall snapshot to the journal  (before ANY change)
  3. lock the firewall                      (from here on nothing can leave directly)
  4. start sing-box, wait for the TUN adapter, allow traffic into the tunnel
  5. start tor, wait for 100% bootstrap
  6. run leak tests
Any failure after step 3 stops the helper processes but KEEPS the lock: the user is
offline, not exposed. Stop restores the exact original firewall state.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import controlport
from .config import Settings, SettingsError, load_settings, normalize_app_path
from .firewall import firewall_enabled, firewall_locked
from .integrity import load_manifest, sha256_file, verify_manifest
from .leakcheck import CheckResult, SystemProbe, run_checks
from .paths import Layout, tor_browser_tor_dir
from .singbox import SingBoxService, build_config
from .state import StateStore
from .torconf import TorService, bridge_domains, bridge_lines, build_torrc
from .system import make_firewall, make_ops

TB_PT_NAMES = ("lyrebird", "snowflake-client", "conjure-client")
STILL_LOCKED = ("\n\nThe internet is still LOCKED (nothing is leaking). "
                "Run 'stop' (or press 'Stop & restore internet') to get your normal connection back.")


class StartError(RuntimeError):
    pass


@dataclass
class Status:
    phase: str | None              # None (off) | "locking" | "locked" | "running"
    singbox_alive: bool = False
    tor_alive: bool = False
    bootstrap: int = 0
    firewall_locked: bool = False
    notes: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, layout: Layout | None = None, *, ops=None,
                 firewall=None, tor: TorService | None = None,
                 singbox: SingBoxService | None = None, state: StateStore | None = None,
                 probe_factory: Callable | None = None, log: Callable[[str], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.layout = layout or Layout()
        self.ops = ops or make_ops(self.layout.os)
        if firewall is None:
            try:
                settings = load_settings(self.layout.config)
            except Exception:  # noqa: BLE001 - unreadable before setup; defaults are fine here
                settings = Settings()
            firewall = make_firewall(self.layout, self.ops, settings)
        self.fw = firewall
        self.tor = tor or TorService(self.layout)
        self.sb = singbox or SingBoxService(self.layout)
        self.state = state or StateStore(self.layout.state)
        self.probe_factory = probe_factory or (lambda s: SystemProbe(self.ops, self.fw, s))
        self.log = log or (lambda msg: None)
        self.sleep = sleep

    # ---------- helpers ----------
    def settings(self) -> Settings:
        return load_settings(self.layout.config)

    def preflight(self) -> None:
        if not self.ops.is_admin():
            raise StartError("PhantomX must run as Administrator.")
        self.ops.secure_root(self.layout.root)
        manifest = load_manifest(self.layout.manifest)
        if not manifest:
            raise StartError("Not installed yet. Run: phantomx setup")
        problems = verify_manifest(self.layout.bin, manifest)
        if problems:
            raise StartError("Integrity check failed (files may have been modified):\n" + "\n".join(problems[:10]))
        if not firewall_enabled(self.fw.status()):
            raise StartError("Windows Defender Firewall is disabled on at least one profile (or another security "
                             "product manages it). Leak protection cannot be guaranteed without it.")

    def _trusted_tb_binary(self, exe: Path) -> bool:
        """Tor Browser's tor/PT binary may go direct only if it is byte-identical to the copy we
        verified at setup (GPG-signed hash list), or carries a valid Tor Project signature."""
        counterpart = {
            self.layout.tor_exe.name.lower(): self.layout.tor_exe,
            self.layout.lyrebird_exe.name.lower(): self.layout.lyrebird_exe,
            self.layout.conjure_exe.name.lower(): self.layout.conjure_exe,
        }.get(exe.name.lower())
        if counterpart is not None and counterpart.is_file() and sha256_file(exe) == sha256_file(counterpart):
            return True
        try:
            return self.ops.tor_project_signed(exe)
        except Exception:  # noqa: BLE001
            return False

    def _direct_paths(self, settings: Settings) -> list[str]:
        paths = [str(self.layout.tor_exe)]
        if settings.use_bridges:
            paths += [str(p) for p in (self.layout.lyrebird_exe, self.layout.snowflake_exe) if p.exists()]
        if settings.privacy_mode == "balanced" and settings.tor_browser_dir:
            tor_dir = tor_browser_tor_dir(settings.tor_browser_dir, self.layout.os)
            names = [self.layout.tor_exe.name] + [self.layout._exe(n) for n in TB_PT_NAMES]
            for exe in [tor_dir / names[0]] + [tor_dir / "PluggableTransports" / n for n in names[1:]]:
                if not exe.exists():
                    continue
                if self._trusted_tb_binary(exe):
                    paths.append(os.path.realpath(exe))
                else:
                    self.log(f"Tor Browser's {exe.name} does not match the verified tor build; "
                             "it will run Tor-over-Tor (slower, still safe). Update Tor Browser or PhantomX's tor.")
        bypass = []
        for app in settings.bypass_apps:
            try:
                bypass.append(normalize_app_path(app))
            except SettingsError as exc:
                self.log(f"Skipping bypass app: {exc}")
        if bypass:
            self.log(f"WARNING: {len(bypass)} app(s) bypass Tor and use your REAL IP: "
                     + ", ".join(Path(b).name for b in bypass))
        return paths + bypass

    def _stop_processes(self, state: dict) -> None:
        pids = state.get("pids") or {}
        for key, path in (("singbox", self.layout.singbox_exe), ("tor", self.layout.tor_exe)):
            pid = pids.get(key)
            if pid:
                try:
                    self.ops.kill(pid, path)
                except Exception as exc:  # noqa: BLE001
                    self.log(f"Could not stop {key}: {exc}")

    def _wait_adapter(self, settings: Settings, sb_pid: int, timeout: float = 30) -> None:
        waited = 0.0
        while waited < timeout:
            if self.ops.adapter_up(settings.tun_name, settings.tun_address):
                return
            if not self.ops.alive(sb_pid, self.layout.singbox_exe):
                self.sleep(0.5)  # let the console log flush
                raise StartError("sing-box exited before the tunnel interface came up:\n" + self.sb.log_tail())
            self.sleep(1)
            waited += 1
        raise StartError("The tunnel interface did not come up in time:\n" + self.sb.log_tail())

    # ---------- public API ----------
    def start(self, on_progress: Callable[[int], None] = lambda p: None) -> list[CheckResult]:
        settings = self.settings()
        # Build both configs first: a bad bridge line fails here, before anything changes.
        torrc = build_torrc(settings, self.layout)
        pt_domains = bridge_domains(bridge_lines(settings)) if settings.use_bridges else []
        self.preflight()
        sb_config = build_config(settings, self.layout, self._direct_paths(settings), pt_domains)

        state = self.state.load()
        if not state or not state.get("snapshot"):
            state = {"version": 1, "phase": "locking", "snapshot": self.fw.snapshot(), "pids": {}}
            self.state.save(state)
            self.log("Saved the original firewall settings.")
        else:
            self.log("Found a previous locked session; reusing its original firewall snapshot.")
            self._stop_processes(state)
            state["pids"] = {}

        try:
            self.fw.lockdown(state["snapshot"]["rules"], [str(self.layout.singbox_exe)])
        except Exception as exc:
            state["phase"] = "locked"
            self.state.save(state)
            raise StartError(f"Firewall lock incomplete: {exc}{STILL_LOCKED}") from exc
        state["phase"] = "locked"
        self.state.save(state)
        self.log("Lock enabled: nothing can leave this device except through the tunnel.")

        try:
            self.sb.prepare(sb_config)
            self.sb.check()
            sb_pid = self.sb.start()
            state["pids"]["singbox"] = sb_pid
            self.state.save(state)
            self._wait_adapter(settings, sb_pid)
            self.fw.allow_tunnel(settings.tun_name, settings.tun_address)
            self.ops.flush_dns()
            self.log("Tunnel is up. Connecting to the Tor network...")

            self.tor.prepare(torrc)
            tor_pid = self.tor.start()
            state["pids"]["tor"] = tor_pid
            self.state.save(state)
            self.tor.wait_bootstrap(settings.bootstrap_timeout,
                                    lambda: self.ops.alive(tor_pid, self.layout.tor_exe), on_progress)
            state["phase"] = "running"
            self.state.save(state)
            self.log("Connected to the Tor network.")
        except Exception as exc:
            self._stop_processes(state)
            state["pids"] = {}
            state["phase"] = "locked"
            self.state.save(state)
            raise StartError(f"{exc}{STILL_LOCKED}") from exc

        return self.run_checks(settings)

    def stop(self) -> None:
        state = self.state.load() or {}
        self._stop_processes(state)
        self.fw.restore(state.get("snapshot"))
        try:
            self.ops.flush_dns()
        except Exception:  # noqa: BLE001
            pass
        self.state.clear()
        self.log("Protection stopped; original firewall settings restored.")

    def run_checks(self, settings: Settings | None = None) -> list[CheckResult]:
        settings = settings or self.settings()
        return run_checks(self.probe_factory(settings), settings)

    def new_identity(self) -> None:
        controlport.new_identity(self.layout.cookie, self.settings().control_port)
        self.log("New identity requested: new connections will use fresh Tor circuits.")

    def status(self) -> Status:
        state = self.state.load() or {}
        st = Status(phase=state.get("phase"))
        pids = state.get("pids") or {}
        if pids.get("singbox"):
            st.singbox_alive = self.ops.alive(pids["singbox"], self.layout.singbox_exe)
        if pids.get("tor"):
            st.tor_alive = self.ops.alive(pids["tor"], self.layout.tor_exe)
            st.bootstrap = self.tor.read_progress()[0] if st.tor_alive else 0
        try:
            st.firewall_locked = firewall_locked(self.fw.status())
        except Exception as exc:  # noqa: BLE001
            st.notes.append(str(exc))
        if st.phase == "running" and not (st.singbox_alive and st.tor_alive):
            st.phase = "locked"
            st.notes.append("A tunnel component stopped; the device is locked with no internet.")
        return st
