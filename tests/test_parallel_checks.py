import threading
import time
import unittest

from phantomx.config import Settings
from phantomx.leakcheck import INCONCLUSIVE, run_checks, verdict
from tests.test_leakcheck import GoodProbe


class SlowProbe(GoodProbe):
    """Each network probe takes 0.4 s; sequentially that would be >= 2 s."""

    def _slow(self, value):
        time.sleep(0.4)
        return value

    def resolve_ipv4(self, name):
        return self._slow(["198.18.0.7"])

    def tor_check(self):
        return self._slow({"IsTor": True, "IP": "185.220.101.1"})

    def tcp_connect(self, *a, **k):
        return self._slow(False)

    def udp_dns_probe(self, *a):
        return self._slow(False)


class TestParallelChecks(unittest.TestCase):
    def test_runs_in_parallel_and_keeps_order(self):
        t0 = time.monotonic()
        results = run_checks(SlowProbe(), Settings(), sleep=lambda s: None)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 1.5, f"took {elapsed:.2f}s: checks are not parallel")
        self.assertEqual([r.key for r in results],
                         ["firewall", "rules", "split", "dns", "tor", "bypass", "udp", "ipv6"])

    def test_every_result_is_reported_live(self):
        seen, lock = [], threading.Lock()

        def on_result(r):
            with lock:
                seen.append(r.key)
        results = run_checks(GoodProbe(), Settings(), sleep=lambda s: None, on_result=on_result)
        self.assertEqual(sorted(seen), sorted(r.key for r in results))

    def test_crashing_check_is_inconclusive_not_pass(self):
        p = GoodProbe()

        def boom():
            raise RuntimeError("unexpected")
        p.physical_ipv4 = boom
        r = run_checks(p, Settings(), sleep=lambda s: None)
        self.assertEqual(verdict(r), INCONCLUSIVE)

    def test_bad_progress_callback_does_not_break_the_run(self):
        def broken(_):
            raise ValueError("ui gone")
        self.assertEqual(len(run_checks(GoodProbe(), Settings(), sleep=lambda s: None, on_result=broken)), 8)


if __name__ == "__main__":
    unittest.main()
