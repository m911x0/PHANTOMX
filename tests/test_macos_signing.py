"""macOS kills unsigned code with SIGKILL; the installer must ad-hoc sign what lacks a signature."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from phantomx.installer import is_macho, prepare_macos_binaries


class FakeCodesign:
    """Simulates `codesign`/`xattr`: files listed in `signed` verify, others don't until signed."""

    def __init__(self, signed=(), fail_sign=False):
        self.signed = set(signed)
        self.fail_sign = fail_sign
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(args)
        rc = 0
        if args[:2] == ["codesign", "--verify"]:
            rc = 0 if Path(args[-1]).name in self.signed else 1
        elif args[:2] == ["codesign", "--force"]:
            if self.fail_sign:
                rc = 1
            else:
                self.signed.add(Path(args[-1]).name)
        return subprocess.CompletedProcess(args, rc, "", "")


class TestMacSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "bin"
        (root / "tor-bundle" / "tor").mkdir(parents=True)
        (root / "sing-box").mkdir()
        macho = bytes.fromhex("cffaedfe") + b"\0" * 64      # arm64/x86_64 Mach-O magic
        (root / "tor-bundle" / "tor" / "tor").write_bytes(macho)
        (root / "tor-bundle" / "tor" / "libevent-2.1.7.dylib").write_bytes(macho)
        (root / "sing-box" / "sing-box").write_bytes(macho)
        (root / "tor-bundle" / "tor" / "geoip").write_text("not code")
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_unsigned_macho_files_get_signed(self):
        cs = FakeCodesign(signed={"sing-box"})  # Go binaries come ad-hoc signed already
        signed = prepare_macos_binaries(self.root, log=lambda m: None, run=cs)
        self.assertEqual(sorted(signed), ["libevent-2.1.7.dylib", "tor"])
        self.assertFalse(any("geoip" in str(c) for c in cs.calls))
        self.assertEqual(cs.calls[0][:4], ["xattr", "-r", "-d", "com.apple.quarantine"])

    def test_signing_failure_is_an_error(self):
        from phantomx.integrity import IntegrityError
        with self.assertRaises(IntegrityError):
            prepare_macos_binaries(self.root, log=lambda m: None, run=FakeCodesign(fail_sign=True))

    def test_macho_detection(self):
        self.assertTrue(is_macho(self.root / "tor-bundle" / "tor" / "tor"))
        self.assertFalse(is_macho(self.root / "tor-bundle" / "tor" / "geoip"))


if __name__ == "__main__":
    unittest.main()
