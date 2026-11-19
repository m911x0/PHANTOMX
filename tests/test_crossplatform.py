"""Cross-platform pieces that can be verified from any OS: naming, layouts, generated
firewall rules and sing-box configs, OpenPGP verification against Tor's real signature."""
import tempfile
import unittest
from pathlib import Path

from phantomx import fetch
from phantomx.config import Settings
from phantomx.openpgp import PGPError, load_keys, verify_detached
from phantomx.osinfo import singbox_platform, tor_browser_key, tor_bundle_platform
from phantomx.paths import Layout, default_root, tor_browser_tor_dir
from phantomx.posix import PHANTOMX_GID, nft_ruleset, pf_rules
from phantomx.singbox import build_config
from phantomx.torconf import build_torrc

DATA = Path(__file__).parent / "data"


class TestOpenPGP(unittest.TestCase):
    def setUp(self):
        self.keys = fetch.pinned_tor_keys()
        self.data = (DATA / "sha256sums-signed-build.txt").read_bytes()
        self.sig = (DATA / "sha256sums-signed-build.txt.asc").read_text()

    def test_pinned_key_is_tor_browser_developers(self):
        self.assertEqual(self.keys[0].fingerprint, fetch.TOR_KEY_PRIMARY)

    def test_real_tor_signature_verifies(self):
        self.assertEqual(verify_detached(self.data, self.sig, self.keys).fingerprint,
                         "022DA248432D2A0E0F54E65E316C1FACD62D07D9")

    def test_one_changed_byte_is_rejected(self):
        with self.assertRaises(PGPError):
            verify_detached(self.data.replace(b"9eed3c3f", b"9eed3c3e"), self.sig, self.keys)

    def test_wrong_key_is_rejected(self):
        primary_only = [k for k in self.keys if k.fingerprint == fetch.TOR_KEY_PRIMARY]
        with self.assertRaises(PGPError):
            verify_detached(self.data, self.sig, primary_only)

    def test_sums_parsing(self):
        sums = fetch.parse_sums(self.data.decode())
        self.assertEqual(sums["tor-expert-bundle-windows-x86_64-16.0.1.tar.gz"][:8], "9eed3c3f")


class TestNaming(unittest.TestCase):
    def test_upstream_names(self):
        self.assertEqual(tor_bundle_platform("macos", "aarch64"), "macos-aarch64")
        self.assertEqual(singbox_platform("macos", "aarch64"), "darwin-arm64")
        self.assertEqual(singbox_platform("linux", "x86_64"), "linux-amd64")
        self.assertEqual(tor_browser_key("linux", "aarch64"), "linux-aarch64")
        self.assertEqual(tor_browser_key("windows", "x86_64"), "win64")

    def test_layouts(self):
        self.assertEqual(Layout(Path("/r"), "linux").tor_exe.as_posix(), "/r/bin/tor-bundle/tor/tor")
        self.assertEqual(Layout(Path("/r"), "macos").singbox_exe.name, "sing-box")
        self.assertEqual(Layout(Path("/r"), "windows").lyrebird_exe.name, "lyrebird.exe")
        self.assertEqual(default_root("linux").as_posix(), "/var/lib/phantomx")
        self.assertNotIn(" ", default_root("macos").as_posix())
        self.assertEqual(tor_browser_tor_dir("/Applications/Tor Browser.app", "macos").as_posix(),
                         "/Applications/Tor Browser.app/Contents/MacOS/Tor")


class TestFirewallRules(unittest.TestCase):
    def test_nftables(self):
        r = nft_ruleset("PhantomX")
        self.assertIn("policy drop;", r)
        self.assertIn(f"meta skgid {PHANTOMX_GID} accept", r)
        self.assertIn('oifname "PhantomX" accept', r)
        self.assertIn('oifname "lo" accept', r)
        self.assertNotIn("ip6", r)  # inet family + policy drop covers IPv6 too

    def test_pf(self):
        locked = pf_rules(None)
        self.assertTrue(locked.rstrip().endswith("block drop out quick all"))
        self.assertNotIn("utun", locked)
        self.assertIn(f"pass out quick group {PHANTOMX_GID}", locked)
        self.assertIn("pass out quick on utun5 all", pf_rules("utun5"))


class TestPerOsConfigs(unittest.TestCase):
    def test_singbox_tun_name(self):
        for os_name, has_name in (("windows", True), ("linux", True), ("macos", False)):
            layout = Layout(Path("/r"), os_name)
            tun = build_config(Settings(), layout, [str(layout.tor_exe)], [])["inbounds"][0]
            self.assertEqual("interface_name" in tun, has_name, os_name)

    def test_torrc_for_posix_layout(self):
        with tempfile.TemporaryDirectory(prefix="os_") as t:
            layout = Layout(Path(t) / "root", "linux")
            self.assertIn("tor-data", build_torrc(Settings(), layout))


if __name__ == "__main__":
    unittest.main()
