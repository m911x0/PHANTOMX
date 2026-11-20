import io
import sys
import unittest
from unittest import mock

from phantomx import cli, updater


class TestVersions(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(updater.is_newer("0.4.10", "0.4.9"))
        self.assertTrue(updater.is_newer("0.5.0", "0.4.2"))
        self.assertFalse(updater.is_newer("0.4.2", "0.4.2"))
        self.assertFalse(updater.is_newer("0.4.1", "0.4.2"))


class TestUpdateCommand(unittest.TestCase):
    def test_pipx_install_uses_force_reinstall_from_github(self):
        with mock.patch.object(updater, "installed_with_pipx", return_value=True), \
                mock.patch.object(updater, "pipx_command", return_value=["pipx"]):
            self.assertEqual(updater.update_command(), ["pipx", "install", "--force", updater.ARCHIVE_URL])

    def test_pip_install_upgrades(self):
        with mock.patch.object(updater, "installed_with_pipx", return_value=False):
            cmd = updater.update_command()
        self.assertEqual(cmd[1:5], ["-m", "pip", "install", "--upgrade"])
        self.assertTrue(cmd[-1].startswith("https://github.com/m911x0/PHANTOMX/"))


class TestCliNoElevation(unittest.TestCase):
    """version/update must run as the normal user: no UAC/sudo prompt."""

    def run_cli(self, argv, latest):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out), \
                mock.patch.object(cli, "is_admin", side_effect=AssertionError("must not check admin")), \
                mock.patch.object(cli, "relaunch_elevated", side_effect=AssertionError("must not elevate")), \
                mock.patch.object(updater, "latest_version", return_value=latest), \
                mock.patch.object(updater, "run_update", return_value=0) as run:
            code = cli.main(argv)
        return code, out.getvalue(), run

    def test_version_reports_update(self):
        code, out, _ = self.run_cli(["version"], "9.9.9")
        self.assertEqual(code, 0)
        self.assertIn("phantomx update", out)

    def test_update_when_current_does_nothing(self):
        from phantomx import __version__
        code, out, run = self.run_cli(["update"], __version__)
        self.assertIn("up to date", out)
        run.assert_not_called()

    def test_update_when_newer_runs(self):
        code, out, run = self.run_cli(["update"], "9.9.9")
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
