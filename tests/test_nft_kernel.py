"""Real-kernel nftables test (no mocks). Runs only in CI's isolated network namespace:

    sudo unshare --net env PHANTOMX_NFT_KERNEL=1 python -m unittest tests.test_nft_kernel

It applies PhantomX's actual ruleset with `nft`, reads it back with `nft -j`, and checks the
structural verifier against what the kernel really holds, including a tampered table.
"""
import os
import shutil
import subprocess
import unittest

from phantomx.posix import NFT_TABLE, LinuxFirewall, nft_enforcing

ENABLED = (os.environ.get("PHANTOMX_NFT_KERNEL") == "1" and shutil.which("nft") is not None
           and hasattr(os, "geteuid") and os.geteuid() == 0)


def nft(*args, input=None):
    return subprocess.run(["nft", *args], input=input, capture_output=True, text=True, check=True).stdout


@unittest.skipUnless(ENABLED, "needs root, nft and PHANTOMX_NFT_KERNEL=1 (isolated netns in CI)")
class RealKernel(unittest.TestCase):
    def setUp(self):
        self.fw = LinuxFirewall("PhantomX")
        subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)

    tearDown = setUp

    def test_lock_apply_verify_restore(self):
        self.fw.lockdown([], [])  # raises if the kernel does not hold an enforcing table
        st = self.fw.status()
        self.assertTrue(st["locked"])
        self.assertTrue(nft_enforcing(nft("-j", "list", "table", "inet", NFT_TABLE), "PhantomX"))
        self.fw.lockdown([], [])  # re-lock = atomic replace, must still verify
        self.assertTrue(self.fw.status()["locked"])
        self.fw.restore(None)
        self.assertEqual(self.fw.status()["ours"], 0)

    def test_tampered_policy_is_detected(self):
        self.fw.lockdown([], [])
        nft("chain", "inet", NFT_TABLE, "output", "{ policy accept ; }")
        self.assertFalse(self.fw.status()["locked"])

    def test_extra_accept_rule_is_detected(self):
        self.fw.lockdown([], [])
        nft("add", "rule", "inet", NFT_TABLE, "output", "tcp", "dport", "443", "accept")
        self.assertFalse(self.fw.status()["locked"])


if __name__ == "__main__":
    unittest.main()
