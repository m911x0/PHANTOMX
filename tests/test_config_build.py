import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from phantomx.config import Settings, SettingsError, load_settings, save_settings, validate_settings
from phantomx.paths import Layout
from phantomx.singbox import build_config
from phantomx.torconf import (TorConfigError, bridge_domains, bridge_lines, build_torrc,
                                 normalize_bridge, parse_progress, tor_path)

OBFS4 = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"
SNOWFLAKE = ("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
             "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
             "url=https://snowflake-broker.torproject.net/ fronts=foursquare.com,github.githubassets.com "
             "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 utls-imitate=hellorandomizedalpn")
WEBTUNNEL = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/abc ver=0.0.1"


class LayoutCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="os_")
        self.layout = Layout(Path(self.tmp.name) / "PhantomX")

    def tearDown(self):
        self.tmp.cleanup()


class TestSettings(LayoutCase):
    def test_roundtrip_and_unknown_keys_ignored(self):
        s = Settings(socks_port=9055)
        save_settings(self.layout.config, s)
        self.layout.config.write_text(self.layout.config.read_text().replace("{", '{"junk": 1,', 1))
        self.assertEqual(load_settings(self.layout.config).socks_port, 9055)

    def test_rejects_bad_values(self):
        for bad in (Settings(socks_port=80), Settings(control_port=9050), Settings(tun_name="a b"),
                    Settings(tun_address="198.18.0.1/30"), Settings(use_bridges=True, bridges=[]),
                    Settings(bootstrap_dns="not-ip")):
            with self.assertRaises(SettingsError):
                validate_settings(bad)


class TestTorrc(LayoutCase):
    def test_core_lines(self):
        torrc = build_torrc(Settings(), self.layout)
        self.assertIn("SocksPort 127.0.0.1:9050\n", torrc)  # balanced (default)
        self.assertIn("ControlPort 127.0.0.1:9051", torrc)
        self.assertIn("DNSPort 127.0.0.1:9053", torrc)
        self.assertIn("CookieAuthentication 1", torrc)
        self.assertIn("ClientUseIPv6 0", torrc)
        self.assertNotIn("UseBridges", torrc)
        if os.name == "nt":
            self.assertNotIn("/", torrc.split("DataDirectory ")[1].split()[0])  # native Windows path

    def test_path_with_space_rejected(self):
        with self.assertRaises(TorConfigError):
            build_torrc(Settings(), Layout(Path(self.tmp.name) / "has space"))

    def test_bridges_need_transport_binary(self):
        s = Settings(use_bridges=True, bridges=[OBFS4])
        with self.assertRaises(TorConfigError):
            build_torrc(s, self.layout)
        self.layout.pt_dir.mkdir(parents=True)
        self.layout.lyrebird_exe.write_bytes(b"x")
        torrc = build_torrc(s, self.layout)
        self.assertIn("UseBridges 1", torrc)
        self.assertIn("ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec", torrc)
        self.assertIn("Bridge " + OBFS4, torrc)

    def test_snowflake_uses_lyrebird_in_new_bundles(self):
        self.layout.pt_dir.mkdir(parents=True)
        self.layout.lyrebird_exe.write_bytes(b"x")
        torrc = build_torrc(Settings(use_bridges=True, bridges=[SNOWFLAKE]), self.layout)
        self.assertIn("ClientTransportPlugin snowflake exec " + tor_path(self.layout.lyrebird_exe), torrc)

    def test_geoip_from_bundle_data_dir(self):
        self.layout.geoip.parent.mkdir(parents=True)
        self.layout.geoip.write_text("x")
        self.assertIn("GeoIPFile " + tor_path(self.layout.geoip), build_torrc(Settings(), self.layout))

    def test_bridge_line_validation(self):
        self.assertEqual(normalize_bridge("Bridge " + OBFS4), OBFS4)
        self.assertEqual(normalize_bridge("192.0.2.1:9001 ABCDEF"), "192.0.2.1:9001 ABCDEF")
        for bad in ("obfs4 1.2.3.4:1\nControlPort 0.0.0.0:9051", 'obfs4 "x"', "evil 1.2.3.4:1", "obfs4 a # c", ""):
            with self.assertRaises(TorConfigError):
                normalize_bridge(bad)

    def test_bridge_domains(self):
        lines = bridge_lines(Settings(use_bridges=True, bridges=[OBFS4, SNOWFLAKE, WEBTUNNEL]))
        self.assertEqual(bridge_domains(lines), sorted([
            "snowflake-broker.torproject.net", "foursquare.com", "github.githubassets.com",
            "stun.l.google.com", "stun.antisip.com", "example.org"]))
        self.assertEqual(bridge_domains([OBFS4]), [])

    def test_parse_progress(self):
        log = ("Nov 19 [notice] Bootstrapped 5% (conn): Connecting\n"
               "Nov 19 [notice] Bootstrapped 45% (requesting_descriptors): x\n")
        self.assertEqual(parse_progress(log), (45, None))
        self.assertEqual(parse_progress(log + "Nov 19 [err] boom\n")[1], "Nov 19 [err] boom")


class TestSingBoxConfig(LayoutCase):
    def test_structure(self):
        s = Settings()
        c = build_config(s, self.layout, [r"C:\ProgramData\PhantomX\bin\tor-bundle\tor\tor.exe"], [])
        tun = c["inbounds"][0]
        self.assertTrue(tun["auto_route"] and tun["strict_route"])
        self.assertEqual(c["route"]["final"], "tor")
        dns = c["dns"]
        self.assertEqual(dns["final"], "tor-dns")
        self.assertEqual([s["tag"] for s in dns["servers"]], ["tor-dns", "fakeip"], "no cleartext DNS without bridges")
        self.assertEqual((dns["servers"][0]["server"], dns["servers"][0]["server_port"]), ("127.0.0.1", 9053))
        self.assertEqual(dns["rules"], [{"query_type": ["A", "AAAA"], "server": "fakeip"}])
        self.assertEqual(c["route"]["default_domain_resolver"], "tor-dns")
        rules = c["route"]["rules"]
        order = [next(iter(k for k in r if k != "outbound")) for r in rules]
        self.assertEqual(order, ["action", "protocol", "process_path", "network", "ip_cidr", "ip_is_private"])
        self.assertEqual(rules[2]["outbound"], "direct")
        self.assertEqual(rules[3], {"network": "udp", "action": "reject"})
        tor = next(o for o in c["outbounds"] if o["tag"] == "tor")
        self.assertEqual((tor["server"], tor["server_port"]), ("127.0.0.1", 9050))

    def test_pt_dns_only_for_bridge_domains(self):
        c = build_config(Settings(), self.layout, [], ["foursquare.com"])
        self.assertEqual(c["dns"]["rules"], [{"domain": ["foursquare.com"], "server": "pt-dns"},
                                             {"query_type": ["A", "AAAA"], "server": "fakeip"}])
        self.assertNotIn("process_path", str(c["route"]["rules"]))

    @unittest.skipUnless(os.environ.get("PHANTOMX_SINGBOX"), "set PHANTOMX_SINGBOX to a sing-box.exe")
    def test_real_singbox_accepts_config(self):
        exe = os.environ["PHANTOMX_SINGBOX"]
        for domains in ([], ["foursquare.com"]):
            cfg = Path(self.tmp.name) / "sb.json"
            cfg.write_text(json.dumps(build_config(Settings(), self.layout, [str(self.layout.tor_exe)], domains)))
            proc = subprocess.run([exe, "check", "-c", str(cfg)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("WARN", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
