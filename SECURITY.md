# Security

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub's private reporting instead (**Security → Report a vulnerability** on https://github.com/m911x0/PHANTOMX), or contact [M911x0](https://github.com/m911x0). A leak report should include your OS, the output of `phantomx check` and `phantomx logs` (remove anything personal), and the steps to reproduce.

# Security design

## Threat model
**In scope:** the network path. Websites, trackers, the ISP, and anyone on the local network must not learn the device's real IP address or the DNS names it looks up, **even when** a component fails, an app ignores proxy settings, or an app uses UDP, WebRTC or IPv6.

**Out of scope:** browser fingerprinting and logins (use Tor Browser), Windows telemetry identifiers, malware running as Administrator, global traffic-correlation adversaries, and the ISP seeing that Tor is in use (use bridges to hide this).

## Layers
1. **Firewall lock (fail-closed)**
   - **Windows** (`firewall.py`): the default outbound action is set to Block on all profiles. Enabled outbound *allow* rules in the local store are temporarily disabled. Only `sing-box.exe`, the TUN interface, and DHCP are allowed out. The original state is journaled to `state.json` *before* any change, and is restored only by an explicit Stop.
   - **Linux** (`posix.py`): nftables table `inet phantomx` with an output chain, policy drop. It accepts only loopback, the tunnel interface, DHCP, and sockets whose group id is `PHANTOMX_GID`; sing-box is started with that gid. In nftables every base chain on a hook must accept a packet, so other tables cannot override the drop.
   - **macOS** (`posix.py`): pf rules in anchor `com.apple/phantomx`, which the stock `/etc/pf.conf` evaluates. The rules pass loopback, `group PHANTOMX_GID`, DHCP and the sing-box utun interface, then `block drop out quick all`. pf is enabled with a reference token, which is released on Stop.
2. **Supply chain** (`fetch.py`, `openpgp.py`): tor and Tor Browser are accepted only if their SHA-256 matches Tor's `sha256sums-signed-build.txt`, and that file's OpenPGP signature verifies against the Tor Browser Developers key **shipped inside this package**. Verification is pure Python (RSA PKCS#1 v1.5), so no gpg or network keyserver is involved. sing-box must match the SHA-256 digest GitHub publishes for the asset, and only the 1.12.x series is accepted. All downloads are HTTPS only, with fixed hosts and path prefixes.
2. **Tunnel**, in `singbox.py`. A TUN interface with `auto_route` + `strict_route` captures all traffic.
   - DNS is hijacked and answered with FakeIP, so names reach tor inside SOCKS (remote resolution).
   - UDP is rejected and private ranges are rejected.
   - Only tor (and its pluggable transports), matched by **full path** inside the admin-only folder, may go direct.
3. **tor**, in `torconf.py`.
   - The SOCKS port listens on loopback only, with `IsolateDestAddr`.
   - ControlPort uses cookie auth, and the cookie lives in the admin-only folder.
   - IPv6 is off and `SafeLogging` is on.
4. **Integrity**, in `integrity.py` and `winutil.secure_root`.
   - Archives are extracted safely (tar `data` filter and zip path checks).
   - Every file is pinned by SHA-256, and unexpected `.exe`/`.dll` files are rejected.
   - The data folder is restricted to Administrators and SYSTEM. A pre-existing folder not owned by them is refused.
5. **Verification**, in `leakcheck.py`. After start, these are actually attempted:
   - a direct TCP connection bound to the physical NIC
   - a direct UDP DNS query
   - an IPv6 connection
   - a real DNS lookup

   All of them must fail. The Tor Project check API must also confirm Tor.

## Engineering rules
- PowerShell scripts are constants. All values are passed as JSON on stdin and are never interpolated.
- The GUI never touches Tk from worker threads; it uses a queue drained on the main thread.
- Tor Browser is opened via `explorer.exe` so it does **not** inherit Administrator rights.
- sing-box logs only at `fatal` level, because its error/warn lines include destination hostnames, which would amount to browsing history on disk. tor uses `SafeLogging 1`, which scrubs addresses. No browsing data is stored.

## Residual risks (known)
- **Group Policy and other policy stores:** allow rules there cannot be disabled locally. They are reported as a warning by the leak test, because they could permit direct traffic while the tunnel is down.
- **Pluggable-transport hostnames:** for snowflake and webtunnel, those hostnames (e.g. the CDN front, STUN servers) are resolved in cleartext via `bootstrap_dns`. This is inherent to how those transports work.
- **Tor Browser's own tor (balanced mode):** it may go direct only if its tor.exe is byte-identical to the GPG-verified tor, or Tor Project-signed. The check happens at start, and the binary lives in a user-writable folder. User-level malware could launch that genuine tor binary with its own config (for example, a bridge it controls) and so reach the network directly. Use **strict** mode to disable this bypass.
- **Balanced circuit sharing:** system apps share circuits for up to ~10 minutes. A single exit relay can therefore see traffic from several apps in that window. Use **strict** mode to give each destination its own circuit.
- **Split tunnel:** listed apps bypass Tor by design and expose the real IP. They are matched by full path, so anything placed at that path inherits the bypass.
- **Python source location:** the source code runs elevated. For production, install it in a location only administrators can write (e.g. Program Files) or ship a signed executable.
- **End-to-end not yet confirmed on real hardware:** the generated config passes `sing-box check` and starts with sing-box 1.12.25 up to TUN creation (tested unprivileged). The full elevated run still needs to be confirmed. Some config errors appear only at runtime, so sing-box/tor console output is captured to `run\*.console.log` and shown on failure.
- **Linux/macOS lock is not persistent:** nftables/pf rules do not survive a reboot. After a reboot the machine is back to normal (unprotected) networking until protection is started again. Windows' lock does persist.
- **Linux/macOS untested on hardware by the author yet:** the generated nftables/pf rules and sing-box configs are unit-tested, and the configs pass `sing-box check`. The elevated runs on real Linux/macOS machines still need confirmation.
- **gid-based allow (Linux/macOS):** any process running with group id `PHANTOMX_GID` (64927) can bypass the lock. Only root can change a process's gid to that value, so this matters only against root malware, which is already out of scope.
- **Pinned signing key rotation:** if Tor rotates its signing subkey, verification fails closed until PhantomX ships the updated key file.
- **NTP is blocked while locked:** on very long sessions the clock may drift, and tor needs a roughly correct clock.
