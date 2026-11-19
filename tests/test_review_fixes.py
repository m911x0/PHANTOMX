"""Regression tests for the findings of the 2026-11-20 security review (PX01-PX10)."""
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from phantomx import posix
from phantomx.config import Settings, save_settings, write_json_atomic
from phantomx.engine import Engine, StartError
from phantomx.firewall import Firewall
from phantomx.integrity import build_manifest
from phantomx.leakcheck import FAIL, PASS, WARN, SystemProbe, run_checks
from phantomx.paths import Layout
from phantomx.posix import LinuxFirewall, nft_enforcing, nft_ruleset, pf_status
from phantomx.state import StateStore
from tests.test_engine import FakeFirewall, FakeOps, FakeProbeFactory, FakeSingBox, FakeTor
from tests.test_leakcheck import GoodProbe

GOOD_LISTING = nft_ruleset("PhantomX").split("delete table inet phantomx\n", 1)[1]


class PX01AtomicLinuxLock(unittest.TestCase):
    def test_ruleset_is_one_atomic_replace(self):
        r = nft_ruleset("PhantomX")
        self.assertTrue(r.startswith("table inet phantomx\ndelete table inet phantomx\ntable inet phantomx {"))

    def test_enforcing_requires_both_chains(self):
        self.assertTrue(nft_enforcing(GOOD_LISTING, "PhantomX"))
        self.assertFalse(nft_enforcing(GOOD_LISTING.replace("hook forward", "hook x"), "PhantomX"))
        self.assertFalse(nft_enforcing("", "PhantomX"))

    def _lock(self, listing):
        fw = LinuxFirewall("PhantomX")
        with mock.patch.object(posix.shutil, "which", return_value="/usr/sbin/nft"), \
                mock.patch.object(posix, "check_gid_free"), \
                mock.patch.object(posix, "_run", return_value="") as run, \
                mock.patch.object(LinuxFirewall, "_listing", return_value=listing):
            fw.lockdown([], [])
        return run

    def test_single_nft_call_no_separate_delete(self):
        run = self._lock(GOOD_LISTING)
        self.assertEqual([c.args[0] for c in run.call_args_list], [["nft", "-f", "-"]])

    def test_unverified_lock_raises(self):
        with self.assertRaises(posix.PosixError):
            self._lock(None)


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

    def make(self, fw=None):
        ops = FakeOps(self.events)
        fw = fw or FakeFirewall(self.events)
        return Engine(self.layout, ops=ops, firewall=fw, tor=FakeTor(self.events, ops),
                      singbox=FakeSingBox(self.events, ops), state=StateStore(self.layout.state),
                      probe_factory=FakeProbeFactory(), sleep=lambda s: None), fw


class PX01HonestMessages(EngineCase):
    def test_failed_lock_is_not_called_locked(self):
        class Broken(FakeFirewall):
            def lockdown(self, *a):
                raise RuntimeError("nft -f failed")  # and nothing got locked
        eng, _ = self.make(Broken(self.events))
        with self.assertRaises(StartError) as cm:
            eng.start()
        self.assertIn("could NOT be confirmed", str(cm.exception))
        self.assertNotIn("still LOCKED", str(cm.exception))

    def test_lock_reported_ok_but_not_enforced_is_rejected(self):
        class Liar(FakeFirewall):
            def lockdown(self, *a):
                self.events.append("lockdown")  # claims success, enforces nothing
        eng, _ = self.make(Liar(self.events))
        with self.assertRaises(StartError):
            eng.start()
        self.assertNotIn("sb_start", self.events)


class PX07ProtectedNeedsVerification(EngineCase):
    def test_status_carries_last_leak_test(self):
        eng, _ = self.make()
        eng.start()
        self.assertEqual(eng.status().verified, PASS)

    def test_running_without_test_is_unverified(self):
        eng, _ = self.make()
        eng.start()
        state = StateStore(self.layout.state).load()
        state["last_check"] = None
        StateStore(self.layout.state).save(state)
        st = eng.status()
        self.assertEqual((st.phase, st.verified), ("running", None))


class PX08Recovery(EngineCase):
    def test_restore_not_verified_keeps_state(self):
        class Sticky(FakeFirewall):
            def status(self):
                return dict(super().status(), ours=2)
        eng, _ = self.make(Sticky(self.events))
        eng.start()
        with self.assertRaises(StartError):
            eng.stop()
        self.assertIsNotNone(StateStore(self.layout.state).load())

    def test_corrupt_state_still_recovers(self):
        eng, fw = self.make()
        self.layout.state.parent.mkdir(parents=True, exist_ok=True)
        self.layout.state.write_text("{not json", encoding="utf-8")
        eng.stop()
        self.assertIn(("restore", None), self.events)
        self.assertTrue(list(self.layout.root.glob("state.json.corrupt-*")))

    def test_no_journal_but_locked_refuses_new_snapshot(self):
        eng, fw = self.make()
        fw.locked = True  # a lock exists but its journal is gone
        with self.assertRaises(StartError):
            eng.start()
        self.assertNotIn("snapshot", self.events)


class PX03GroupPolicy(unittest.TestCase):
    def test_gpo_rule_fails_and_service_rule_warns(self):
        locked = {"active": [{"name": "Public", "enabled": "True", "outbound": "Block"}]}
        p = GoodProbe()
        p.firewall_status = lambda: dict(locked, unmanaged=["Corp allow", "ICS"], unmanaged_gpo=["Corp allow"])
        r = {x.key: x for x in run_checks(p, Settings(), sleep=lambda s: None)}
        self.assertEqual(r["rules"].status, FAIL)
        self.assertIn("Corp allow", r["rules"].detail)
        p.firewall_status = lambda: dict(locked, unmanaged=["ICS"], unmanaged_gpo=[])
        self.assertEqual({x.key: x.status for x in run_checks(p, Settings())}["rules"], WARN)

    def test_status_parses_rule_sources(self):
        class R:
            def run(self, script, data=None, timeout=0):
                return {"active": [], "ours": 0, "unmanaged": [
                    {"name": "Corp allow", "source": "GroupPolicy"}, {"name": "ICS", "source": "Dynamic"}]}
        st = Firewall(R()).status()
        self.assertEqual((st["unmanaged"], st["unmanaged_gpo"]), (["Corp allow", "ICS"], ["Corp allow"]))


class PX05MacStatus(unittest.TestCase):
    MAIN = 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
    ANCHOR = "pass out quick on lo0 all\nblock drop out quick all\n"

    def test_locked_only_when_pf_runs_and_anchor_is_evaluated(self):
        self.assertTrue(pf_status("Status: Enabled", self.MAIN, self.ANCHOR)["locked"])
        self.assertFalse(pf_status("Status: Disabled", self.MAIN, self.ANCHOR)["locked"])
        self.assertFalse(pf_status("Status: Enabled", "", self.ANCHOR)["locked"])
        self.assertFalse(pf_status("Status: Enabled", self.MAIN, "")["locked"])

    def test_running_is_reported_truthfully(self):
        self.assertFalse(pf_status("Status: Disabled", self.MAIN, self.ANCHOR)["running"])


class PX02WindowsPinning(unittest.TestCase):
    def test_probe_socket_pinned_to_interface(self):
        calls = []

        class S:
            def setsockopt(self, *a):
                calls.append(a)

            def bind(self, addr):
                calls.append(("bind", addr))
        probe = SystemProbe(ops=None, firewall=None, settings=Settings())
        probe._iface = 18
        with mock.patch("phantomx.leakcheck.current_os", return_value="windows"):
            probe._pin_to_physical(S(), "192.168.1.5")
        self.assertEqual(calls[0], (socket.IPPROTO_IP, 31, socket.htonl(18)))
        self.assertEqual(calls[1], ("bind", ("192.168.1.5", 0)))


class PX09GidCollision(unittest.TestCase):
    def test_existing_group_is_refused(self):
        fake = types.SimpleNamespace(getgrgid=lambda gid: types.SimpleNamespace(gr_name="docker"))
        with mock.patch.dict(sys.modules, {"grp": fake}):
            with self.assertRaises(posix.PosixError):
                posix.check_gid_free()

    def test_free_gid_passes(self):
        def missing(gid):
            raise KeyError(gid)
        with mock.patch.dict(sys.modules, {"grp": types.SimpleNamespace(getgrgid=missing)}):
            posix.check_gid_free()


if __name__ == "__main__":
    unittest.main()
