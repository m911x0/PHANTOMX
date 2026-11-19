"""User settings (stored as JSON in the admin-only data folder)."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


class SettingsError(ValueError):
    pass


@dataclass
class Settings:
    socks_port: int = 9050          # tor SOCKS port that sing-box forwards all TCP into
    control_port: int = 9051        # tor ControlPort (loopback, cookie auth) for "new identity"
    dns_port: int = 9053            # tor DNSPort (loopback): sing-box's default resolver, so it too goes via Tor
    tun_name: str = "PhantomX"
    tun_address: str = "172.19.0.1/30"
    fakeip_range: str = "198.18.0.0/15"
    bootstrap_timeout: int = 300
    use_bridges: bool = False
    bridges: list[str] = field(default_factory=list)
    # Only used to resolve hostnames that bridge lines need (snowflake broker, webtunnel host).
    bootstrap_dns: str = "1.1.1.1"
    tor_browser_dir: str = ""
    # "balanced" (default): faster. System apps share Tor circuits (rotated every ~10 min) and a
    #   verified Tor Browser tor.exe bypasses the tunnel, so there is no slow Tor-over-Tor.
    # "strict": a separate circuit per destination; Tor Browser runs Tor-over-Tor. Slower.
    privacy_mode: str = "balanced"
    # Split tunnel (opt-in): full .exe paths that go DIRECT, NOT through Tor. Exposes their real IP.
    bypass_apps: list[str] = field(default_factory=list)
    # The user accepted the lawful-use notice in the GUI (shown once).
    terms_accepted: bool = False


PRIVACY_MODES = ("balanced", "strict")


def normalize_app_path(path: str) -> str:
    """Absolute, real on-disk path of an existing program (sing-box matches the exact path).
    Windows: an .exe. macOS/Linux: an executable file (inside .app bundles: Contents/MacOS/...)."""
    if not isinstance(path, str) or not path.strip():
        raise SettingsError("empty app path")
    p = Path(path.strip().strip('"'))
    if not p.is_absolute():
        raise SettingsError(f"not an absolute path: {path}")
    if os.name == "nt" and p.suffix.lower() != ".exe":
        raise SettingsError(f"not an .exe: {path}")
    if not p.is_file():
        raise SettingsError(f"file not found: {path}")
    if os.name != "nt" and not os.access(p, os.X_OK):
        raise SettingsError(f"not an executable program: {path}")
    return os.path.realpath(p)


def validate_settings(s: Settings) -> None:
    for name in ("socks_port", "control_port", "dns_port"):
        value = getattr(s, name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
            raise SettingsError(f"{name} must be an integer 1024-65535")
    if len({s.socks_port, s.control_port, s.dns_port}) != 3:
        raise SettingsError("socks_port, control_port and dns_port must all differ")
    if not isinstance(s.tun_name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", s.tun_name):
        raise SettingsError("tun_name must be 1-32 letters, digits, '-' or '_'")
    try:
        tun = ipaddress.ip_interface(s.tun_address)
        fake = ipaddress.ip_network(s.fakeip_range)
        ipaddress.ip_address(s.bootstrap_dns)
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc
    if tun.version != 4 or fake.version != 4:
        raise SettingsError("tun_address and fakeip_range must be IPv4")
    if tun.network.overlaps(fake):
        raise SettingsError("tun_address must not overlap fakeip_range")
    if isinstance(s.bootstrap_timeout, bool) or not isinstance(s.bootstrap_timeout, int) or not 30 <= s.bootstrap_timeout <= 1800:
        raise SettingsError("bootstrap_timeout must be 30-1800 seconds")
    if not isinstance(s.bridges, list) or not all(isinstance(b, str) for b in s.bridges):
        raise SettingsError("bridges must be a list of strings")
    if s.use_bridges and not [b for b in s.bridges if b.strip()]:
        raise SettingsError("use_bridges is on but no bridge lines are set")
    if not isinstance(s.tor_browser_dir, str):
        raise SettingsError("tor_browser_dir must be a string")
    if s.privacy_mode not in PRIVACY_MODES:
        raise SettingsError(f"privacy_mode must be one of {PRIVACY_MODES}")
    if not isinstance(s.bypass_apps, list) or not all(isinstance(a, str) and a for a in s.bypass_apps):
        raise SettingsError("bypass_apps must be a list of paths")


def load_settings(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SettingsError("config.json must contain an object")
    known = {f.name for f in fields(Settings)}
    settings = Settings(**{k: v for k, v in raw.items() if k in known})
    validate_settings(settings)
    return settings


def save_settings(path: Path, settings: Settings) -> None:
    validate_settings(settings)
    write_json_atomic(path, asdict(settings))


def write_json_atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
