# Changelog

## 0.4.4 (2026-11-20): macOS fix
- **macOS: tor was killed at launch ("signal 9").** Apple Silicon kills unsigned code silently, and the Tor Expert Bundle's binaries are not signed for direct use. After verifying the archive (Tor's GPG-signed SHA-256 list), the installer now removes quarantine flags and applies an ad-hoc signature to every Mach-O file without a valid one. The manifest pins the result.
- Start refuses with a clear fix ("press Update components") if the binaries were installed by an older version and macOS would kill them.
- CI: new **real macOS** job that downloads the verified bundle and actually executes `tor --version`.

## 0.4.3 (2026-11-20)
- New `phantomx version` (installed vs. latest on GitHub) and `phantomx update`. Both run as the normal user with no elevation, because pipx lives in the user's profile. On Windows the update runs in its own window after PhantomX exits, since Windows locks running files.
- Control panel: **Check for updates** link (on demand only).
- One-time manual reinstall needed when coming from 0.4.2 or older (see README → Update).

## 0.4.2 (2026-11-20): security correctness (re-audit of 0.4.1)
- **FINDING-01 (critical):** a failed or unverified lock is never recorded or shown as LOCKED. The new **UNSAFE** state ("lock NOT confirmed, you may be exposed") is used whenever the firewall does not confirm enforcement. `status` re-checks the real firewall every time, whatever the journal says.
- **FINDING-02:** leak probes have three outcomes: **BLOCKED / LEAKED / TEST_ERROR**. Socket setup failures are TEST_ERROR and are never counted as a pass. A remote answer (connection refused/reset) is treated as a **leak**, because packets left the machine.
- **FINDING-03, Windows:** restore is verified against the saved snapshot: every profile policy and every previously disabled rule. If anything does not match, the journal is kept and `stop` can be retried. Rules deleted since the snapshot are reported but are not a failure.
- **FINDING-04, Linux:** lock verification is **structural** (`nft -j`). The output and forward base chains must themselves have policy drop, and every accept rule must be one of the expected allowances. Unconditional accepts and jump/goto are rejected. The reviewer's counterexample is a regression test.
- **FINDING-05:** **INCONCLUSIVE** is separated from accepted exceptions. PROTECTED requires every mandatory check to pass. Only user-accepted exceptions (split tunnel, service-owned rules) may produce "PROTECTED, with your accepted exceptions". Otherwise the result is **NOT VERIFIED**.
- **Monitoring:** the GUI watchdog re-checks the firewall lock (not just process liveness). Leak-test results expire after 30 minutes and are re-run automatically.
- **macOS:** processes started by PhantomX are now tracked exactly (no `ps` guessing), and tor's real exit code/signal is reported (e.g. "killed by signal 9 - blocked by code signing"). tor gets `DYLD_LIBRARY_PATH` for its bundled libevent. The executable path comes from `proc_pidpath`.
- **CI:** new **real-kernel** job: the actual nftables ruleset is applied in an isolated network namespace and verified, including tampered-table detection.

## 0.4.1 (2026-11-20): security review fixes
Fixes from an independent static review of 0.4.0 (findings PX01-PX10):

- **PX01 (critical), Linux:** the nftables lock is now applied in **one atomic transaction**. There is no longer a separate delete-then-create window, and the lock is verified against the kernel ruleset (`nft list table`) before it is reported. On any lock failure, messages now state the *verified* state: "still locked" only if the firewall confirms it, and otherwise "lock could NOT be confirmed".
- **Engine:** after applying the lock, the firewall state is checked independently. Start refuses to continue unless the lock is actually enforced.
- **PX02, Windows:** the "direct exit" leak test now pins its socket to the physical adapter (`IP_UNICAST_IF`) in addition to binding its source address. Physical-adapter detection prefers hardware NICs and never picks a virtual tunnel adapter.
- **PX03, Windows:** outbound allow rules enforced by **Group Policy** now **fail** the leak test (they could override the lock). Service-owned dynamic rules (e.g. Internet Connection Sharing) remain a warning.
- **PX04, Linux:** a `forward` chain (policy drop) now covers containers and VMs. Forwarded traffic may only use the tunnel.
- **PX05, macOS:** pf status reports the truth. `locked` requires pf to be running, our anchor to hold the block rule, **and** the main ruleset to evaluate `com.apple/*` anchors. The lock is verified after applying it.
- **PX07:** a running tunnel is no longer shown as PROTECTED. PROTECTED requires a passing leak test in the current session. The GUI shows *VERIFYING* and runs the test automatically. `phantomx status` prints the last result.
- **PX08:** restore is verified (no PhantomX rules may remain) before the session journal is deleted. A damaged `state.json` no longer breaks recovery: it is quarantined and safe defaults are restored. Start refuses to snapshot a firewall that is already locked by a session whose journal is lost.
- **PX09, Linux/macOS:** start is refused if the trusted group id (64927) already belongs to a real group.
- **PX10:** CI now tests Python 3.10, 3.11 and 3.12 on Windows, macOS and Linux. The error message names the minimum patch versions (3.10.12+ / 3.11.4+).
- **Migration:** `phantomx start`/`stop` cleanly stop a leftover pre-rename *OnionShield* session and restore its firewall settings.

**Still open:** PX06 (an elevated process runs Python code from a user-writable install). The planned fix is an unprivileged GUI plus a small privileged service. See SECURITY.md.

## 0.4.0 (2026-11-19)
First public release: whole-device Tor routing, fail-closed firewall lock (Windows/macOS/Linux), real leak tests, verified auto-install, Tor Browser integration, GUI and CLI.
