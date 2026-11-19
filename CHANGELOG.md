# Changelog

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
