"""Fail-closed lock using Windows Defender Firewall.

While locked:
- Default outbound action on every profile = Block.
- Existing *enabled outbound allow* rules (local store) are temporarily disabled, because an
  allow rule would otherwise let that program bypass the lock whenever the tunnel is down.
- Only these are allowed out: sing-box.exe (it carries tor's relay traffic), the TUN
  interface, and DHCP (so the network lease does not expire).

If PhantomX crashes or the PC reboots, the lock stays: no traffic leaks, the internet is
simply off until the user presses Stop/Restore. The original state is restored exactly from
the snapshot saved before any change.
"""
from __future__ import annotations

from .winutil import PowerShellRunner

GROUP = "PhantomX"

PS_SNAPSHOT = r"""
$profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.Name; outbound = [string]$_.DefaultOutboundAction } })
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object { $_.Group -ne 'PhantomX' } | ForEach-Object { [string]$_.Name })
Emit ([pscustomobject]@{ profiles = $profiles; rules = $rules })
"""

PS_LOCKDOWN = r"""
Remove-NetFirewallRule -PolicyStore PersistentStore -Group 'PhantomX' -ErrorAction SilentlyContinue
foreach ($p in @($D.allow_programs)) {
  New-NetFirewallRule -PolicyStore PersistentStore -DisplayName ('PhantomX allow ' + [System.IO.Path]::GetFileName([string]$p)) `
    -Group 'PhantomX' -Direction Outbound -Action Allow -Program ([string]$p) -Profile Any | Out-Null
}
New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'PhantomX allow DHCP' -Group 'PhantomX' `
  -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any | Out-Null
$wanted = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($n in @($D.disable_rules)) { [void]$wanted.Add([string]$n) }
$errs = @()
# Disable via the rule objects themselves (bound to the store they came from), then VERIFY.
$targets = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object { $_.Group -ne 'PhantomX' -and $wanted.Contains([string]$_.Name) })
foreach ($r in $targets) {
  try { $r | Set-NetFirewallRule -Enabled False -ErrorAction Stop }
  catch { $errs += ([string]$r.Name + ': ' + $_.Exception.Message) }
}
Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -DefaultOutboundAction Block
$still = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object { $_.Group -ne 'PhantomX' -and $wanted.Contains([string]$_.Name) } | ForEach-Object { [string]$_.Name })
Emit ([pscustomobject]@{ ok = ($still.Count -eq 0); targeted = $targets.Count; still_enabled = $still; errors = @($errs | Select-Object -First 5) })
"""

PS_ALLOW_TUNNEL = r"""
New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'PhantomX allow tunnel' -Group 'PhantomX' `
  -Direction Outbound -Action Allow -InterfaceAlias ([string]$D.alias) -Profile Any | Out-Null
Emit ([pscustomobject]@{ ok = $true })
"""

PS_RESTORE = r"""
$errs = @()
foreach ($p in @($D.profiles)) {
  try { Set-NetFirewallProfile -PolicyStore PersistentStore -Name ([string]$p.name) -DefaultOutboundAction ([string]$p.outbound) -ErrorAction Stop }
  catch { $errs += ('profile ' + [string]$p.name + ': ' + $_.Exception.Message) }
}
$wanted = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($n in @($D.rules)) { [void]$wanted.Add([string]$n) }
$found = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { $wanted.Contains([string]$_.Name) })
foreach ($r in $found) {
  if ([string]$r.Enabled -ne 'True') {
    try { $r | Set-NetFirewallRule -Enabled True -ErrorAction Stop }
    catch { $errs += ([string]$r.Name + ': ' + $_.Exception.Message) }
  }
}
Remove-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$D.group) -ErrorAction SilentlyContinue

# ---- verify against the snapshot (F03) ----
$profiles_bad = @()
$now = @{}
Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object { $now[[string]$_.Name] = [string]$_.DefaultOutboundAction }
foreach ($p in @($D.profiles)) {
  if ($now[[string]$p.name] -ne [string]$p.outbound) { $profiles_bad += ([string]$p.name + '=' + $now[[string]$p.name]) }
}
$present = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { $wanted.Contains([string]$_.Name) })
$not_enabled = @($present | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { [string]$_.Name })
$missing = $wanted.Count - $present.Count
$ours = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$D.group) -ErrorAction SilentlyContinue).Count
Emit ([pscustomobject]@{ profiles_bad = $profiles_bad; not_enabled = $not_enabled; missing = $missing;
                         ours = $ours; errors = @($errs | Select-Object -First 5) })
"""

PS_STATUS = r"""
$active = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; outbound = [string]$_.DefaultOutboundAction } })
$unmanaged = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
  Where-Object { $_.Group -ne 'PhantomX' } | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.DisplayName; source = [string]$_.PolicyStoreSourceType } })
$ours = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group ([string]$D.group) -ErrorAction SilentlyContinue).Count
Emit ([pscustomobject]@{ active = $active; unmanaged = $unmanaged; ours = $ours })
"""

class FirewallError(RuntimeError):
    pass


DEFAULT_PROFILES =[{"name": n, "outbound": "NotConfigured"} for n in ("Domain", "Private", "Public")]


class Firewall:
    def __init__(self, runner: PowerShellRunner | None = None, group: str = GROUP):
        self.runner = runner or PowerShellRunner()
        self.group = group  # rule group to restore/count ("OnionShield" for pre-rename sessions)

    def snapshot(self) -> dict:
        r = self.runner.run(PS_SNAPSHOT, {})
        return {"profiles": list(r.get("profiles") or []), "rules": list(r.get("rules") or [])}

    def lockdown(self, disable_rules: list[str], allow_programs: list[str]) -> None:
        r = self.runner.run(PS_LOCKDOWN, {"disable_rules": list(disable_rules),
                                          "allow_programs": [str(p) for p in allow_programs]}) or {}
        still = list(r.get("still_enabled") or [])
        if still:
            # The default-Block policy is already on, so we are locked; but these allow rules
            # would let their programs out directly if the tunnel stopped. Refuse to continue.
            errs = "; ".join(r.get("errors") or []) or "no error reported"
            raise FirewallError(f"could not disable {len(still)} of {r.get('targeted')} outbound allow rules "
                                f"(e.g. {', '.join(still[:3])}). Details: {errs}")

    def allow_tunnel(self, alias: str, address: str = "") -> None:
        self.runner.run(PS_ALLOW_TUNNEL, {"alias": alias})

    def restore(self, snapshot: dict | None) -> None:
        if not snapshot or not snapshot.get("profiles"):
            # Emergency path (snapshot lost): return to Windows defaults and drop our rules.
            snapshot = {"profiles": DEFAULT_PROFILES, "rules": (snapshot or {}).get("rules", [])}
        r = self.runner.run(PS_RESTORE, {"profiles": snapshot["profiles"], "rules": snapshot.get("rules", []),
                                         "group": self.group}) or {}
        problems = []
        if r.get("profiles_bad"):
            problems.append("profile outbound policy not restored: " + ", ".join(r["profiles_bad"]))
        if r.get("not_enabled"):
            problems.append(f"{len(r['not_enabled'])} rule(s) still disabled, e.g. " + ", ".join(r["not_enabled"][:3]))
        if int(r.get("ours") or 0):
            problems.append(f"{r['ours']} {self.group} rule(s) still present")
        if problems:
            errs = "; ".join(r.get("errors") or [])
            raise FirewallError("restore could not be verified against the saved snapshot: " + "; ".join(problems)
                                + (f". Details: {errs}" if errs else ""))
        # Rules deleted since the snapshot (r["missing"]) cannot be re-enabled; that is not a failure.

    def status(self) -> dict:
        """`unmanaged`: names of allow rules we cannot disable; `unmanaged_gpo`: the subset that
        comes from Group Policy (PX03: those can override the lock and FAIL the leak test)."""
        r = self.runner.run(PS_STATUS, {"group": self.group})
        raw = list(r.get("unmanaged") or [])
        names = [u["name"] if isinstance(u, dict) else str(u) for u in raw]
        gpo = [u["name"] for u in raw if isinstance(u, dict) and u.get("source") == "GroupPolicy"]
        return {"active": list(r.get("active") or []), "unmanaged": names, "unmanaged_gpo": gpo,
                "ours": int(r.get("ours") or 0)}


def firewall_enabled(status: dict) -> bool:
    if "enabled" in status:  # Linux / macOS backends report it directly
        return bool(status["enabled"])
    return bool(status["active"]) and all(p.get("enabled") == "True" for p in status["active"])


def firewall_locked(status: dict) -> bool:
    if "locked" in status:
        return bool(status["locked"])
    return bool(status["active"]) and all(p.get("outbound") == "Block" for p in status["active"])
