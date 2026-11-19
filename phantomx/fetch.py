"""Automatic downloads with verification. Nothing downloaded is used unless verified:

  Tor (expert bundle + Tor Browser): SHA-256 must match `sha256sums-signed-build.txt`, whose
      OpenPGP signature must verify against the Tor Browser Developers key pinned in this
      package (phantomx/keys/torbrowser-developers.asc).
  sing-box: SHA-256 must match the digest GitHub publishes for the release asset.
            Only the 1.12.x series is used (the config format PhantomX generates).
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Callable

from .openpgp import PGPError, load_keys, verify_detached
from .osinfo import singbox_platform, tor_browser_key, tor_bundle_platform

TOR_DIST = "https://dist.torproject.org/torbrowser"
TOR_DOWNLOADS_JSON = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"
TOR_KEY_PRIMARY = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
SINGBOX_REPO = "SagerNet/sing-box"
SINGBOX_SERIES = "1.12"
USER_AGENT = "PhantomX-installer"

Progress = Callable[[str, int, int], None]  # (label, done_bytes, total_bytes)


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifact:
    name: str
    url: str
    sha256: str


def _open(url: str, timeout: float = 60):
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def get_bytes(url: str, limit: int = 4 << 20) -> bytes:
    with _open(url) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise FetchError(f"response too large: {url}")
    return data


def get_json(url: str):
    return json.loads(get_bytes(url).decode("utf-8"))


def download(artifact: Artifact, dest_dir: Path, progress: Progress | None = None) -> Path:
    """Stream to disk, hashing as we go; delete and fail on any mismatch."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / artifact.name
    h = hashlib.sha256()
    with _open(artifact.url, timeout=120) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(1 << 16):
            f.write(chunk)
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(artifact.name, done, total)
    if h.hexdigest() != artifact.sha256.lower():
        dest.unlink(missing_ok=True)
        raise FetchError(f"SHA-256 mismatch for {artifact.name}: download corrupted or tampered with")
    return dest


# ---------------------------------------------------------------- Tor
def pinned_tor_keys():
    text = resources.files("phantomx").joinpath("keys/torbrowser-developers.asc").read_text(encoding="utf-8")
    keys = load_keys(text)
    if keys[0].fingerprint != TOR_KEY_PRIMARY:
        raise FetchError("bundled Tor signing key file is not the expected key")
    return keys


def parse_sums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(\S+)", line.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out


def verified_tor_sums(version: str) -> dict[str, str]:
    base = f"{TOR_DIST}/{version}/sha256sums-signed-build.txt"
    data = get_bytes(base)
    sig = get_bytes(base + ".asc").decode("ascii", "replace")
    try:
        verify_detached(data, sig, pinned_tor_keys())
    except PGPError as exc:
        raise FetchError(f"Tor hash list signature is INVALID ({exc}); refusing to continue") from exc
    return parse_sums(data.decode("utf-8"))


def latest_tor_version() -> str:
    version = get_json(TOR_DOWNLOADS_JSON).get("version", "")
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", version):
        raise FetchError(f"unexpected Tor Browser version string: {version!r}")
    return version


def tor_artifacts(os_name: str, cpu: str) -> tuple[str, Artifact, Artifact]:
    """(version, expert bundle, Tor Browser) for this platform, hashes from the signed list."""
    version = latest_tor_version()
    sums = verified_tor_sums(version)
    bundle = f"tor-expert-bundle-{tor_bundle_platform(os_name, cpu)}-{version}.tar.gz"
    tb_url = get_json(TOR_DOWNLOADS_JSON)["downloads"][tor_browser_key(os_name, cpu)]["ALL"]["binary"]
    tb_name = tb_url.rsplit("/", 1)[-1]
    for name in (bundle, tb_name):
        if name not in sums:
            raise FetchError(f"{name} is not in Tor's signed hash list")
    if not tb_url.startswith(f"{TOR_DIST}/{version}/"):
        raise FetchError(f"unexpected Tor Browser download location: {tb_url}")
    return (version,
            Artifact(bundle, f"{TOR_DIST}/{version}/{bundle}", sums[bundle]),
            Artifact(tb_name, tb_url, sums[tb_name]))


# ---------------------------------------------------------------- sing-box
def _version_key(tag: str) -> tuple[int, ...]:
    return tuple(int(x) for x in tag.lstrip("v").split("."))


def singbox_artifact(os_name: str, cpu: str) -> tuple[str, Artifact]:
    refs = get_json(f"https://api.github.com/repos/{SINGBOX_REPO}/git/matching-refs/tags/v{SINGBOX_SERIES}.")
    tags = [r["ref"].rsplit("/", 1)[-1] for r in refs]
    stable = [t for t in tags if re.fullmatch(rf"v{re.escape(SINGBOX_SERIES)}\.\d+", t)]
    if not stable:
        raise FetchError(f"no stable sing-box {SINGBOX_SERIES}.x release found")
    tag = max(stable, key=_version_key)
    release = get_json(f"https://api.github.com/repos/{SINGBOX_REPO}/releases/tags/{tag}")
    if release.get("prerelease") or release.get("draft"):
        raise FetchError(f"sing-box {tag} is not a stable release")
    plat = singbox_platform(os_name, cpu)
    ext = ".zip" if os_name == "windows" else ".tar.gz"
    wanted = f"sing-box-{tag.lstrip('v')}-{plat}{ext}"
    for asset in release.get("assets", []):
        if asset.get("name") == wanted:
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                raise FetchError(f"GitHub published no SHA-256 digest for {wanted}")
            url = asset["browser_download_url"]
            if not url.startswith(f"https://github.com/{SINGBOX_REPO}/releases/download/"):
                raise FetchError(f"unexpected sing-box download location: {url}")
            return tag, Artifact(wanted, url, digest.split(":", 1)[1])
    raise FetchError(f"{wanted} not found in sing-box {tag}")
