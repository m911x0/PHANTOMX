import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from phantomx.integrity import (IntegrityError, build_manifest, safe_extract_tar, safe_extract_zip,
                                   verify_manifest)


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "bin"
        (self.root / "tor").mkdir(parents=True)
        (self.root / "tor" / "tor.exe").write_bytes(b"tor")
        (self.root / "readme.txt").write_text("x")

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean(self):
        self.assertEqual(verify_manifest(self.root, build_manifest(self.root)), [])

    def test_detects_modified_missing_and_planted(self):
        m = build_manifest(self.root)
        (self.root / "tor" / "tor.exe").write_bytes(b"evil")
        (self.root / "readme.txt").unlink()
        (self.root / "tor" / "version.dll").write_bytes(b"planted")
        (self.root / "notes.log").write_text("not executable, ignored")
        problems = verify_manifest(self.root, m)
        self.assertIn("modified: tor/tor.exe", problems)
        self.assertIn("missing: readme.txt", problems)
        self.assertIn("unexpected executable: tor/version.dll", problems)
        self.assertEqual(len(problems), 3)

    def test_manifest_path_escape(self):
        self.assertTrue(any("invalid" in p for p in verify_manifest(self.root, {"../x": "0"})))

    def test_zip_traversal_rejected(self):
        archive = Path(self.tmp.name) / "evil.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("../../escape.exe", b"x")
        with self.assertRaises(IntegrityError):
            safe_extract_zip(archive, Path(self.tmp.name) / "out")

    def test_tar_traversal_rejected(self):
        archive = Path(self.tmp.name) / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            info = tarfile.TarInfo("../escape.exe")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(Exception):
            safe_extract_tar(archive, Path(self.tmp.name) / "out")
        self.assertFalse((Path(self.tmp.name) / "escape.exe").exists())


if __name__ == "__main__":
    unittest.main()
