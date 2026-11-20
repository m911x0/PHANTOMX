"""Real macOS test (no mocks): download the verified Tor Expert Bundle, prepare it the way the
installer does, and actually execute `tor --version`. Runs in CI on macOS only:

    PHANTOMX_MAC_REAL=1 python -m unittest tests.test_macos_tor_real -v
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ENABLED = sys.platform == "darwin" and os.environ.get("PHANTOMX_MAC_REAL") == "1"


@unittest.skipUnless(ENABLED, "macOS only, set PHANTOMX_MAC_REAL=1")
class RealMacTor(unittest.TestCase):
    def test_bundle_tor_runs_after_preparation(self):
        from phantomx import fetch
        from phantomx.installer import is_macho, macos_signature_ok, prepare_macos_binaries
        from phantomx.integrity import safe_extract_tar
        from phantomx.osinfo import arch

        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            _, bundle, _ = fetch.tor_artifacts("macos", arch())          # GPG-verified hash list
            archive = fetch.download(bundle, tmp / "dl")                 # hash-checked download
            root = tmp / "bin" / "tor-bundle"
            safe_extract_tar(archive, root)
            tor = root / "tor" / "tor"
            env = dict(os.environ, DYLD_LIBRARY_PATH=str(tor.parent))

            before = {p.name: macos_signature_ok(p) for p in root.rglob("*") if p.is_file() and is_macho(p)}
            print("\nsignature valid BEFORE preparation:", before)
            raw = subprocess.run([str(tor), "--version"], capture_output=True, text=True, env=env, timeout=60)
            print("raw bundle tor exit code:", raw.returncode)

            prepare_macos_binaries(tmp / "bin", log=print)
            after = subprocess.run([str(tor), "--version"], capture_output=True, text=True, env=env, timeout=60)
            print("prepared tor exit code:", after.returncode, "|", after.stdout.strip()[:80])
            self.assertEqual(after.returncode, 0, after.stderr)
            self.assertIn("Tor version", after.stdout)


if __name__ == "__main__":
    unittest.main()
