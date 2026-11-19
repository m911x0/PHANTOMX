"""Read-only PowerShell tests: data round-trip, and every embedded script parses cleanly.
Nothing here changes system state."""
import os
import unittest

from phantomx import firewall, winutil
from phantomx.winutil import PRELUDE, PowerShellError, PowerShellRunner

SCRIPTS = {name: getattr(mod, name) for mod in (firewall, winutil)
           for name in dir(mod) if name.startswith("PS_")}

PARSE = r"""
$errs = @()
foreach ($s in @($D.scripts)) {
  $tokens = $null; $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseInput([string]$s.code, [ref]$tokens, [ref]$e)
  foreach ($x in @($e)) { if ($x) { $errs += ($s.name + ': ' + $x.Message) } }
}
Emit ([pscustomobject]@{ errors = @($errs) })
"""


@unittest.skipUnless(os.name == "nt", "Windows only")
class TestPowerShell(unittest.TestCase):
    def test_roundtrip_unicode_and_quotes(self):
        value = "C:\\Dössier-ünïcødé \u4e2d 'x' \"y\" $(whoami); `n"
        out = PowerShellRunner().run("Emit ([pscustomobject]@{ v = [string]$D.v; n = @($D.list).Count })",
                                     {"v": value, "list": ["a", "b", "c"]})
        self.assertEqual(out, {"v": value, "n": 3})

    def test_errors_raise(self):
        with self.assertRaises(PowerShellError):
            PowerShellRunner().run("throw 'nope'", {})

    def test_all_scripts_parse(self):
        payload = {"scripts": [{"name": n, "code": PRELUDE + "\n" + c} for n, c in SCRIPTS.items()]}
        self.assertGreaterEqual(len(payload["scripts"]), 10)
        out = PowerShellRunner().run(PARSE, payload)
        self.assertEqual(out["errors"], [])


if __name__ == "__main__":
    unittest.main()
