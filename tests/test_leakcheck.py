import unittest

from phantomx.config import Settings
from phantomx.leakcheck import FAIL, INCONCLUSIVE, PASS, WARN, run_checks, verdict

LOCKED = {"active": [{"name": n, "enabled": "True", "outbound": "Block"} for n in ("Domain", "Private", "Public")],
          "unmanaged": [], "ours": 4}


class GoodProbe:
    def firewall_status(self):
        return LOCKED

    def physical_ipv4(self):
        return "192.168.1.20"

    def resolve_ipv4(self, name):
        return ["198.18.0.7"]

    def tor_check(self):
        return {"IsTor": True, "IP": "185.220.101.1"}

    def tcp_connect(self, bind_ip, host, port, family=None):
        return False

    def udp_dns_probe(self, bind_ip, server):
        return False


def by_key(results):
    return {r.key: r.status for r in results}


class TestLeakChecks(unittest.TestCase):
    def test_all_good(self):
        r = run_checks(GoodProbe(), Settings())
        self.assertEqual(set(by_key(r).values()), {PASS})
        self.assertEqual(verdict(r), PASS)

    def test_dns_leak(self):
        p = GoodProbe()
        p.resolve_ipv4 = lambda n: ["93.184.216.34"]
        self.assertEqual(by_key(run_checks(p, Settings()))["dns"], FAIL)

    def test_direct_tcp_leak(self):
        p = GoodProbe()
        p.tcp_connect = lambda b, h, port, family=None: b is not None
        k = by_key(run_checks(p, Settings()))
        self.assertEqual((k["bypass"], k["ipv6"]), (FAIL, PASS))

    def test_udp_and_ipv6_leak(self):
        p = GoodProbe()
        p.udp_dns_probe = lambda b, s: True
        p.tcp_connect = lambda b, h, port, family=None: ":" in h
        k = by_key(run_checks(p, Settings()))
        self.assertEqual((k["udp"], k["ipv6"]), (FAIL, FAIL))

    def test_not_tor(self):
        p = GoodProbe()
        p.tor_check = lambda: {"IsTor": False, "IP": "203.0.113.5"}
        self.assertEqual(by_key(run_checks(p, Settings()))["tor"], FAIL)

    def test_tor_unreachable(self):
        p = GoodProbe()

        calls = []

        def boom():
            calls.append(1)
            raise OSError("timed out")
        p.tor_check = boom
        self.assertEqual(by_key(run_checks(p, Settings(), sleep=lambda s: None))["tor"], INCONCLUSIVE)
        self.assertEqual(len(calls), 4)

    def test_tor_check_recovers_after_transient_eof(self):
        p = GoodProbe()
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise OSError("SSL: UNEXPECTED_EOF_WHILE_READING")
            return {"IsTor": True, "IP": "185.220.101.1"}
        p.tor_check = flaky
        self.assertEqual(by_key(run_checks(p, Settings(), sleep=lambda s: None))["tor"], PASS)

    def test_unlocked_firewall_and_unmanaged_rules(self):
        p = GoodProbe()
        p.firewall_status = lambda: {"active": [{"name": "Public", "enabled": "True", "outbound": "Allow"}],
                                     "unmanaged": ["GPO rule"], "ours": 0}
        k = by_key(run_checks(p, Settings()))
        self.assertEqual((k["firewall"], k["rules"]), (FAIL, WARN))

    def test_no_physical_interface_is_inconclusive(self):
        p = GoodProbe()
        p.physical_ipv4 = lambda: None
        r = run_checks(p, Settings())
        self.assertEqual(by_key(r)["bypass"], INCONCLUSIVE)
        self.assertEqual(verdict(r), INCONCLUSIVE)
        self.assertNotIn("udp", by_key(r))


if __name__ == "__main__":
    unittest.main()
