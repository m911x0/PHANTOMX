"""Regression tests for the second (re-)audit of v0.4.1: FINDING-01..05 and the macOS report."""
import errno
import socket
import sys
import unittest
from unittest import mock

from phantomx.config import Settings
from phantomx.engine import StartError
from phantomx.firewall import Firewall, FirewallError
from phantomx.leakcheck import (BLOCKED, FAIL, INCONCLUSIVE, LEAKED, PASS, TEST_ERROR, WARN, Outcome,
                                SystemProbe, classify_send_error, run_checks, verdict)
from phantomx.posix import nft_enforcing
from phantomx.state import StateStore
from phantomx.winutil import child_state, describe_exit, spawn_detached
from tests.test_engine import FakeFirewall
from tests.test_leakcheck import GoodProbe
from tests.test_review_fixes import EngineCase, nft_json


class F01NoFalseLocked(EngineCase):
    def test_failed_lock_is_recorded_as_unsafe_not_locked(self):
        class Broken(FakeFirewall):
            def lockdown(self, *a):
                raise RuntimeError("apply failed")
        eng, _ = self.make(Broken(self.events))
        with self.assertRaises(StartError):
            eng.start()
        self.assertEqual(StateStore(self.layout.state).load()["phase"], "unsafe")
        self.assertEqual(eng.status().phase, "unsafe")

    def test_lock_lost_while_running_becomes_unsafe(self):
        eng, fw = self.make()
        eng.start()
        fw.locked = False  # someone/something removed the lock
        st = eng.status()
        self.assertEqual(st.phase, "unsafe")
        self.assertIsNone(st.verified)

    def test_old_leak_test_expires(self):
        eng, _ = self.make()
        eng.start()
        state = StateStore(self.layout.state).load()
        state["last_check"]["at"] -= 31 * 60
        StateStore(self.layout.state).save(state)
        self.assertIsNone(eng.status().verified)


class F02TriStateProbe(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_send_error(socket.timeout()).state, BLOCKED)
        self.assertEqual(classify_send_error(OSError(errno.EPERM, "Operation not permitted")).state, BLOCKED)
        self.assertEqual(classify_send_error(OSError(errno.ECONNREFUSED, "refused")).state, LEAKED)
        self.assertEqual(classify_send_error(OSError(errno.EINVAL, "invalid")).state, TEST_ERROR)
        win = OSError(None, "An attempt was made to access a socket in a way forbidden")
        win.winerror = 10013
        self.assertEqual(classify_send_error(win).state, BLOCKED)

    def test_setup_failure_is_test_error_not_pass(self):
        probe = SystemProbe(ops=None, firewall=None, settings=Settings())
        with mock.patch.object(SystemProbe, "_pin_to_physical", side_effect=OSError(errno.EADDRNOTAVAIL, "bad bind")):
            o = probe.tcp_connect("192.0.2.1", "1.1.1.1", 443)
        self.assertEqual(o.state, TEST_ERROR)

    def test_test_error_makes_run_inconclusive(self):
        p = GoodProbe()
        p.tcp_connect = lambda b, h, port, family=None: Outcome(TEST_ERROR, "boom")
        r = run_checks(p, Settings(), sleep=lambda s: None)
        self.assertEqual({x.key: x.status for x in r}["bypass"], INCONCLUSIVE)
        self.assertEqual(verdict(r), INCONCLUSIVE)


class F03RestoreVerification(unittest.TestCase):
    SNAP = {"profiles": [{"name": "Public", "outbound": "NotConfigured"}], "rules": ["A", "B"]}

    def restore_with(self, reply):
        class R:
            def run(self, script, data=None, timeout=0):
                return reply
        Firewall(R()).restore(self.SNAP)

    def test_rule_left_disabled_fails(self):
        with self.assertRaises(FirewallError):
            self.restore_with({"profiles_bad": [], "not_enabled": ["B"], "missing": 0, "ours": 0, "errors": []})

    def test_profile_not_restored_fails(self):
        with self.assertRaises(FirewallError):
            self.restore_with({"profiles_bad": ["Public=Block"], "not_enabled": [], "missing": 0, "ours": 0})

    def test_deleted_rule_is_not_a_failure(self):
        self.restore_with({"profiles_bad": [], "not_enabled": [], "missing": 1, "ours": 0, "errors": []})

    def test_engine_keeps_state_when_restore_unverified(self):
        case = EngineCase()
        case.setUp()
        try:
            class Bad(FakeFirewall):
                def restore(self, snapshot):
                    raise FirewallError("rule B still disabled")
            eng, _ = case.make(Bad(case.events))
            eng.start()
            with self.assertRaises(StartError):
                eng.stop()
            self.assertIsNotNone(StateStore(case.layout.state).load())
        finally:
            case.tearDown()


class F04StructuralNft(unittest.TestCase):
    def test_reviewer_counterexample_is_rejected(self):
        # OUTPUT/FORWARD accept, with two unrelated drop-policy chains: text counting said True.
        decoys = [{"chain": {"name": "x", "type": "filter", "hook": "input", "policy": "drop"}},
                  {"chain": {"name": "y", "type": "filter", "hook": "prerouting", "policy": "drop"}}]
        self.assertFalse(nft_enforcing(nft_json(out="accept", fwd="accept", extra=decoys), "PhantomX"))

    def test_unconditional_accept_is_rejected(self):
        extra = [{"rule": {"chain": "output", "expr": [{"accept": None}]}}]
        self.assertFalse(nft_enforcing(nft_json(extra=extra), "PhantomX"))

    def test_unknown_allowance_or_jump_is_rejected(self):
        port = [{"rule": {"chain": "output", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
            {"accept": None}]}}]
        jump = [{"rule": {"chain": "output", "expr": [{"jump": {"target": "elsewhere"}}]}}]
        self.assertFalse(nft_enforcing(nft_json(extra=port), "PhantomX"))
        self.assertFalse(nft_enforcing(nft_json(extra=jump), "PhantomX"))

    def test_our_ruleset_passes(self):
        self.assertTrue(nft_enforcing(nft_json(), "PhantomX"))


class F05AcceptedVsInconclusive(unittest.TestCase):
    def test_split_tunnel_is_an_accepted_exception(self):
        r = run_checks(GoodProbe(), Settings(bypass_apps=[r"C:\g\game.exe"]), sleep=lambda s: None)
        self.assertEqual(verdict(r), WARN)

    def test_dns_lookup_failure_is_inconclusive(self):
        p = GoodProbe()

        def fail(name):
            raise OSError("no resolver")
        p.resolve_ipv4 = fail
        self.assertEqual(verdict(run_checks(p, Settings(), sleep=lambda s: None)), INCONCLUSIVE)

    def test_precedence(self):
        from phantomx.leakcheck import CheckResult as C
        self.assertEqual(verdict([C("a", "", WARN), C("b", "", INCONCLUSIVE)]), INCONCLUSIVE)
        self.assertEqual(verdict([C("a", "", INCONCLUSIVE), C("b", "", FAIL)]), FAIL)
        self.assertEqual(verdict([C("a", "", PASS)]), PASS)


class MacTorDiagnostics(unittest.TestCase):
    def test_exit_code_of_our_child_is_known(self):
        pid = spawn_detached([sys.executable, "-c", "import sys; sys.exit(3)"], cwd=".")
        for _ in range(100):
            tracked, alive, code = child_state(pid)
            if not alive:
                break
            import time
            time.sleep(0.05)
        self.assertTrue(tracked)
        self.assertEqual(code, 3)
        self.assertEqual(describe_exit(code), "exit code 3")

    def test_signal_kill_is_explained(self):
        self.assertIn("signal 9", describe_exit(-9))


if __name__ == "__main__":
    unittest.main()
