import tempfile
import unittest
from pathlib import Path

from phantomx.config import Settings, save_settings
from phantomx.engine import Engine, StartError
from phantomx.firewall import DEFAULT_PROFILES, Firewall
from phantomx.integrity import build_manifest
from phantomx.config import write_json_atomic
from phantomx.paths import Layout
from phantomx.state import StateStore
from phantomx.torconf import TorError

SNAP = {"profiles": [{"name": "Public", "outbound": "NotConfigured"}], "rules": ["RuleA", "RuleB"]}
ACTIVE_OPEN = [{"name": n, "enabled": "True", "outbound": "Allow"} for n in ("Domain", "Private", "Public")]


class FakeFirewall:
    def __init__(self, events):
        self.events = events
        self.locked = False

    def snapshot(self):
        self.events.append("snapshot")
        return dict(SNAP)

    def lockdown(self, disable_rules, allow_programs):
        self.events.append(("lockdown", tuple(disable_rules), tuple(allow_programs)))
        self.locked = True

    def allow_tunnel(self, alias, address=""):
        self.events.append(("allow_tunnel", alias))

    def restore(self, snapshot):
        self.events.append(("restore", snapshot))
        self.locked = False

    def status(self):
        out = "Block" if self.locked else "Allow"
        return {"active": [dict(p, outbound=out) for p in ACTIVE_OPEN], "unmanaged": [], "ours": 0}


class FakeOps:
    def __init__(self, events):
        self.events = events
        self.alive_pids = set()

    def is_admin(self):
        return True

    def secure_root(self, path):
        pass

    def alive(self, pid, path):
        return pid in self.alive_pids

    def kill(self, pid, path):
        self.events.append(("kill", pid))
        self.alive_pids.discard(pid)
        return True

    def adapter_up(self, name, address=""):
        return True

    def flush_dns(self):
        self.events.append("flush")

    def tor_project_signed(self, path):
        return True


class FakeSingBox:
    def __init__(self, events, ops):
        self.events, self.ops = events, ops

    def prepare(self, config):
        self.events.append("sb_prepare")

    def check(self):
        self.events.append("sb_check")

    def start(self):
        self.events.append("sb_start")
        self.ops.alive_pids.add(111)
        return 111

    def log_tail(self):
        return ""


class FakeTor:
    def __init__(self, events, ops, fail=False):
        self.events, self.ops, self.fail = events, ops, fail

    def prepare(self, torrc):
        self.events.append("tor_prepare")

    def start(self):
        self.events.append("tor_start")
        self.ops.alive_pids.add(222)
        return 222

    def wait_bootstrap(self, timeout, is_alive, on_progress):
        if self.fail:
            raise TorError("stuck at 10%")
        on_progress(100)
        self.events.append("tor_ready")

    def read_progress(self):
        return 100, None


class FakeProbeFactory:
    def __call__(self, settings):
        from tests.test_leakcheck import GoodProbe
        return GoodProbe()


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="os_")
        self.layout = Layout(Path(self.tmp.name) / "PhantomX")
        self.layout.tor_dir.mkdir(parents=True)
        self.layout.tor_exe.write_bytes(b"tor")
        self.layout.singbox_dir.mkdir(parents=True)
        self.layout.singbox_exe.write_bytes(b"sb")
        write_json_atomic(self.layout.manifest, build_manifest(self.layout.bin))
        save_settings(self.layout.config, Settings())
        self.events = []

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, tor_fail=False):
        ops = FakeOps(self.events)
        fw = FakeFirewall(self.events)
        eng = Engine(self.layout, ops=ops, firewall=fw, tor=FakeTor(self.events, ops, tor_fail),
                     singbox=FakeSingBox(self.events, ops), state=StateStore(self.layout.state),
                     probe_factory=FakeProbeFactory(), sleep=lambda s: None)
        return eng, ops, fw

    def test_start_order_lock_before_anything(self):
        eng, ops, fw = self.make()
        results = eng.start()
        names = [e if isinstance(e, str) else e[0] for e in self.events]
        self.assertEqual(names, ["snapshot", "lockdown", "sb_prepare", "sb_check", "sb_start",
                                 "allow_tunnel", "flush", "tor_prepare", "tor_start", "tor_ready"])
        lock = self.events[1]
        self.assertEqual(lock[1], ("RuleA", "RuleB"))
        self.assertEqual(lock[2], (str(self.layout.singbox_exe),))
        self.assertEqual(StateStore(self.layout.state).load()["phase"], "running")
        self.assertTrue(all(r.status == "pass" for r in results))

    def test_failure_keeps_lock_and_kills_helpers(self):
        eng, ops, fw = self.make(tor_fail=True)
        with self.assertRaises(StartError) as cm:
            eng.start()
        self.assertIn("still LOCKED", str(cm.exception))
        self.assertTrue(fw.locked, "firewall must stay locked after a failed start")
        self.assertNotIn("restore", [e[0] for e in self.events if isinstance(e, tuple)])
        self.assertIn(("kill", 111), self.events)
        self.assertIn(("kill", 222), self.events)
        st = StateStore(self.layout.state).load()
        self.assertEqual((st["phase"], st["pids"]), ("locked", {}))
        self.assertEqual(st["snapshot"], SNAP)

    def test_restart_reuses_original_snapshot(self):
        eng, ops, fw = self.make(tor_fail=True)
        with self.assertRaises(StartError):
            eng.start()
        self.events.clear()
        eng.tor.fail = False
        eng.start()
        self.assertNotIn("snapshot", self.events, "must not snapshot the locked state as 'original'")

    def test_stop_restores_saved_snapshot(self):
        eng, ops, fw = self.make()
        eng.start()
        eng.stop()
        self.assertIn(("restore", SNAP), self.events)
        self.assertIsNone(StateStore(self.layout.state).load())
        self.assertFalse(fw.locked)

    def test_emergency_restore_without_state(self):
        eng, ops, fw = self.make()
        eng.stop()
        self.assertIn(("restore", None), self.events)

    def test_tampered_binary_blocks_start_before_any_change(self):
        self.layout.tor_exe.write_bytes(b"evil")
        eng, ops, fw = self.make()
        with self.assertRaises(StartError):
            eng.start()
        self.assertEqual(self.events, [])

    def test_bad_bridges_fail_before_any_change(self):
        save_settings(self.layout.config, Settings(use_bridges=True, bridges=["obfs4 1.2.3.4:443 FP"]))
        eng, ops, fw = self.make()  # lyrebird.exe not installed
        with self.assertRaises(Exception):
            eng.start()
        self.assertEqual(self.events, [])

    def test_status_detects_dead_tunnel(self):
        eng, ops, fw = self.make()
        eng.start()
        ops.alive_pids.clear()
        st = eng.status()
        self.assertEqual(st.phase, "locked")
        self.assertTrue(st.firewall_locked)


class FirewallScriptData(unittest.TestCase):
    def test_restore_without_snapshot_uses_defaults(self):
        calls = []

        class R:
            def run(self, script, data=None, timeout=0):
                calls.append(data)
                return {"ok": True}
        Firewall(R()).restore(None)
        self.assertEqual(calls[0]["profiles"], DEFAULT_PROFILES)


class LockdownVerification(unittest.TestCase):
    def test_rules_left_enabled_is_an_error(self):
        from phantomx.firewall import FirewallError

        class R:
            def run(self, script, data=None, timeout=0):
                return {"ok": False, "targeted": 203, "still_enabled": ["WFDPRINT-SPOOL-Out-Active"],
                        "errors": ["WFDPRINT-SPOOL-Out-Active: Access is denied"]}
        with self.assertRaises(FirewallError) as cm:
            Firewall(R()).lockdown(["WFDPRINT-SPOOL-Out-Active"], ["sb.exe"])
        self.assertIn("Access is denied", str(cm.exception))

    def test_clean_lockdown_passes(self):
        class R:
            def run(self, script, data=None, timeout=0):
                return {"ok": True, "targeted": 203, "still_enabled": [], "errors": []}
        Firewall(R()).lockdown(["a"], ["sb.exe"])


if __name__ == "__main__":
    unittest.main()
