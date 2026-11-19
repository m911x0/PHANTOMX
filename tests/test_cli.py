import io
import sys
import unittest
from unittest import mock

from phantomx import cli
from phantomx.branding import print_logo


class TestWindowless(unittest.TestCase):
    """pythonw.exe (used for the elevated GUI) has sys.stdout/stderr = None."""

    def test_logo_with_no_console(self):
        with mock.patch.object(sys, "stdout", None):
            print_logo()  # must not raise

    def test_main_gui_path_with_no_console(self):
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None), \
                mock.patch.object(cli, "is_admin", return_value=True), \
                mock.patch("phantomx.gui.run_gui") as run_gui:
            self.assertEqual(cli.main(["gui"]), 0)
            run_gui.assert_called_once()

    def test_non_admin_gui_relaunches_elevated(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(cli, "is_admin", return_value=False), \
                mock.patch.object(cli, "relaunch_elevated", return_value=True) as relaunch:
            self.assertEqual(cli.main([]), 0)
            relaunch.assert_called_once_with(["gui"])


if __name__ == "__main__":
    unittest.main()
