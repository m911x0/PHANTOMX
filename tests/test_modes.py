import os
import tempfile
import unittest
from pathlib import Path

from phantomx.config import Settings, SettingsError, normalize_app_path, validate_settings
from phantomx.engine import Engine
from phantomx.leakcheck import PASS, WARN, run_checks
from phantomx.paths import Layout, tor_browser_tor_dir
from phantomx.torconf import build_torrc
from tests.test_engine import FakeOps
from tests.test_leakcheck import GoodProbe


class ModesCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="os_")
        base = Path(self.tmp.name)
        self.layout = Layout(base / "PhantomX")
        self.layout.tor_dir.mkdir(parents=True)
        self.layout.tor_exe.write_bytes(b"verified-tor")
        self.tb = base / "TB"
        self.tb_tor = tor_browser_tor_dir(self.tb) / self.layout.tor_exe.name
        self.tb_tor.parent.mkdir(parents=True)
        self.app = base / "game.exe"
        self.app.write_bytes(b"x")
        os.chmod(self.app, 0o755)  # POSIX requires an executable program
        self.logs = []

    def tearDown(self):
        self.tmp.cleanup()

    def engine(self, signed=False):
        ops = FakeOps([])
        ops.tor_project_signed = lambda p: signed
        return Engine(self.layout, ops=ops, firewall=object(), tor=object(), singbox=object(),
                      state=object(), log=self.logs.append)

    def test_torrc_isolation_by_mode(self):
        self.assertIn("SocksPort 127.0.0.1:9050\n", build_torrc(Settings(), self.layout))
        self.assertIn("SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateDestPort",
                      build_torrc(Settings(privacy_mode="strict"), self.layout))

    def test_invalid_mode(self):
        with self.assertRaises(SettingsError):
            validate_settings(Settings(privacy_mode="turbo"))

    def test_tb_tor_identical_to_verified_goes_direct(self):
        self.tb_tor.write_bytes(b"verified-tor")
        paths = self.engine()._direct_paths(Settings(tor_browser_dir=str(self.tb)))
        self.assertEqual(len(paths), 2)
        self.assertEqual(Path(paths[1]).name, self.layout.tor_exe.name)
        self.assertEqual(Path(paths[1]).parent.name, "Tor")

    def test_tb_tor_different_and_unsigned_stays_in_tunnel(self):
        self.tb_tor.write_bytes(b"something-else")
        paths = self.engine()._direct_paths(Settings(tor_browser_dir=str(self.tb)))
        self.assertEqual(paths, [str(self.layout.tor_exe)])
        self.assertTrue(any("Tor-over-Tor" in l for l in self.logs))

    def test_tb_tor_signed_goes_direct(self):
        self.tb_tor.write_bytes(b"newer-signed-build")
        self.assertEqual(len(self.engine(signed=True)._direct_paths(Settings(tor_browser_dir=str(self.tb)))), 2)

    def test_strict_never_bypasses_tb(self):
        self.tb_tor.write_bytes(b"verified-tor")
        s = Settings(tor_browser_dir=str(self.tb), privacy_mode="strict")
        self.assertEqual(self.engine()._direct_paths(s), [str(self.layout.tor_exe)])

    def test_bypass_apps_added_and_missing_skipped(self):
        s = Settings(bypass_apps=[str(self.app), str(self.app.with_name("gone.exe"))])
        paths = self.engine()._direct_paths(s)
        self.assertEqual(len(paths), 2)
        self.assertTrue(any("REAL IP" in l for l in self.logs))
        self.assertTrue(any("Skipping" in l for l in self.logs))

    def test_normalize_app_path(self):
        self.assertTrue(normalize_app_path(f'"{self.app}"').lower().endswith("game.exe"))
        for bad in ("game.exe", str(self.app.with_suffix(".txt")), ""):
            with self.assertRaises(SettingsError):
                normalize_app_path(bad)

    def test_leakcheck_reports_split_tunnel(self):
        k = {r.key: r for r in run_checks(GoodProbe(), Settings(bypass_apps=[r"C:\Games\game.exe"]))}
        self.assertEqual(k["split"].status, WARN)
        self.assertIn("game.exe", k["split"].detail)
        self.assertEqual({r.key: r.status for r in run_checks(GoodProbe(), Settings())}["split"], PASS)


if __name__ == "__main__":
    unittest.main()
