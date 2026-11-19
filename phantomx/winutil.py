"""Windows helpers.

PowerShell scripts are fixed strings. Every variable value (paths, rule names, pids)
is passed as JSON on stdin and read into `$D`, so no value is ever spliced into
script text — that removes quoting/injection bugs entirely.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
_FLAGS = CREATE_NO_WINDOW if os.name == "nt" else 0

PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$__reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), (New-Object System.Text.UTF8Encoding($false)))
$__raw = $__reader.ReadToEnd()
$D = $null
if ($__raw.Trim().Length -gt 0) { $D = $__raw | ConvertFrom-Json }
function Emit($obj) {
  $json = ConvertTo-Json -InputObject $obj -Depth 6 -Compress
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
  $out = [Console]::OpenStandardOutput()
  $out.Write($bytes, 0, $bytes.Length)
  $out.Flush()
}
"""


class PowerShellError(RuntimeError):
    pass


def powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


class PowerShellRunner:
    def run(self, script: str, data: Any = None, timeout: float = 120) -> Any:
        full = PRELUDE + "\n" + script
        encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
        payload = json.dumps(data, ensure_ascii=True).encode("ascii") if data is not None else b""
        proc = subprocess.run(
            [powershell_exe(), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            input=payload, capture_output=True, timeout=timeout, creationflags=_FLAGS,
        )
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise PowerShellError(err or f"PowerShell exit code {proc.returncode}")
        out = proc.stdout.decode("utf-8", "replace").strip()
        return json.loads(out) if out else None


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_elevated(args: list[str]) -> bool:
    """Start `python -m phantomx <args>` elevated (UAC prompt). True if launched.
    Uses pythonw.exe when available so no extra console window appears."""
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    if pythonw.exists():
        exe = pythonw
    params = subprocess.list2cmdline(["-m", "phantomx", *args])
    cwd = str(Path(__file__).resolve().parent.parent)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", str(exe), params, cwd, 1)
    return rc > 32


def spawn_detached(args: list[str], cwd: str | Path, output: str | Path | None = None,
                   gid: int | None = None, env: dict | None = None) -> int:
    """Start a background process with no window that outlives this one. Returns its pid.

    stdout+stderr go to `output` so startup errors (printed before a program's own logger
    is ready) are never lost. On POSIX, `gid` runs it under that group id (the firewall
    allows exactly that gid out), and it gets its own session.
    """
    sink = open(output, "wb") if output else subprocess.DEVNULL
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = _FLAGS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
        if gid is not None:
            kwargs["group"] = gid
            kwargs["extra_groups"] = []
    try:
        proc = subprocess.Popen(
            [str(a) for a in args], cwd=str(cwd), env=env,
            stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT if output else subprocess.DEVNULL,
            close_fds=True, **kwargs,
        )
    finally:
        if output:
            sink.close()
    return proc.pid


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def tail_files(paths, n: int = 8) -> str:
    """Last n non-empty lines across the given log files, ANSI colours stripped."""
    lines: list[str] = []
    for p in paths:
        try:
            text = Path(p).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        lines += [_ANSI.sub("", l) for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-n:]) or "(no output captured)"


PS_PROC = r"""
$p = Get-Process -Id ([int]$D.pid) -ErrorAction SilentlyContinue
$match = $false
if ($p -and $p.Path) {
  $match = ([System.IO.Path]::GetFullPath($p.Path) -ieq [System.IO.Path]::GetFullPath([string]$D.path))
}
$killed = $false
if ($match -and $D.kill) { Stop-Process -Id $p.Id -Force; $killed = $true }
Emit ([pscustomobject]@{ alive = $match; killed = $killed })
"""

PS_ADAPTER_UP = r"""
$a = Get-NetAdapter -Name ([string]$D.name) -ErrorAction SilentlyContinue
Emit ([pscustomobject]@{ up = [bool]($a -and $a.Status -eq 'Up') })
"""

PS_FLUSH_DNS = r"""
Clear-DnsClientCache
Emit ([pscustomobject]@{ ok = $true })
"""

PS_PHYSICAL_IP = r"""
$c = Get-NetIPConfiguration | Where-Object {
  $_.IPv4DefaultGateway -and $_.InterfaceAlias -ne [string]$D.tun -and $_.NetAdapter.Status -eq 'Up'
} | Select-Object -First 1
$ip = $null
if ($c) { $ip = [string](($c.IPv4Address | Select-Object -First 1).IPAddress) }
Emit ([pscustomobject]@{ ip = $ip })
"""

PS_AUTHENTICODE = r"""
$s = Get-AuthenticodeSignature -LiteralPath ([string]$D.path)
$subject = ''
if ($s.SignerCertificate) { $subject = [string]$s.SignerCertificate.Subject }
Emit ([pscustomobject]@{ status = [string]$s.Status; subject = $subject })
"""

# Refuse a pre-existing folder not owned by Administrators/SYSTEM (a normal user could
# have planted config or binaries in it), then restrict the ACL to Administrators+SYSTEM.
PS_SECURE_ROOT = r"""
$p = [string]$D.path
if (Test-Path -LiteralPath $p) {
  $owner = (Get-Acl -LiteralPath $p).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne 'S-1-5-32-544' -and $owner -ne 'S-1-5-18') { throw "UNTRUSTED_OWNER $owner" }
} else {
  New-Item -ItemType Directory -Path $p | Out-Null
}
& icacls.exe $p /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed with $LASTEXITCODE" }
Emit ([pscustomobject]@{ ok = $true })
"""


class SystemOps:
    """Small OS operations the engine needs; replaced by a fake in tests."""

    def __init__(self, runner: PowerShellRunner | None = None):
        self.runner = runner or PowerShellRunner()

    def is_admin(self) -> bool:
        return is_admin()

    def alive(self, pid: int, path: Path | str) -> bool:
        return bool(self.runner.run(PS_PROC, {"pid": int(pid), "path": str(path), "kill": False})["alive"])

    def kill(self, pid: int, path: Path | str) -> bool:
        return bool(self.runner.run(PS_PROC, {"pid": int(pid), "path": str(path), "kill": True})["killed"])

    def adapter_up(self, name: str, address: str = "") -> bool:
        return bool(self.runner.run(PS_ADAPTER_UP, {"name": name})["up"])

    def physical(self, tun_name: str) -> tuple[str | None, str | None]:
        return self.physical_ipv4(tun_name), None  # Windows strong-host model: binding the IP is enough

    def flush_dns(self) -> None:
        self.runner.run(PS_FLUSH_DNS, {})

    def physical_ipv4(self, tun_name: str) -> str | None:
        return self.runner.run(PS_PHYSICAL_IP, {"tun": tun_name})["ip"]

    def authenticode(self, path: Path | str) -> tuple[str, str]:
        r = self.runner.run(PS_AUTHENTICODE, {"path": str(path)})
        return r["status"], r["subject"]

    def tor_project_signed(self, path: Path | str) -> bool:
        status, subject = self.authenticode(path)
        return status == "Valid" and "The Tor Project" in subject

    def secure_root(self, path: Path | str) -> None:
        try:
            self.runner.run(PS_SECURE_ROOT, {"path": str(path)})
        except PowerShellError as exc:
            if "UNTRUSTED_OWNER" in str(exc):
                raise PowerShellError(
                    f"The folder {path} already exists and is not owned by Administrators. "
                    "Delete it manually, then try again."
                ) from exc
            raise
