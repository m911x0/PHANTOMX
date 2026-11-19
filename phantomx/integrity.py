"""Binary integrity: safe archive extraction and a SHA-256 manifest of everything in bin/."""
from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

EXEC_SUFFIXES = {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".com", ".scr", ".vbs", ".js"}


class IntegrityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path) -> dict[str, str]:
    root = Path(root)
    return {p.relative_to(root).as_posix(): sha256_file(p)
            for p in sorted(root.rglob("*")) if p.is_file()}


def verify_manifest(root: Path, manifest: dict[str, str]) -> list[str]:
    """Return a list of problems; empty means every file matches and nothing executable was added."""
    root = Path(root).resolve()
    problems: list[str] = []
    for rel, digest in manifest.items():
        path = (root / rel).resolve()
        if not path.is_relative_to(root):
            problems.append(f"invalid manifest path: {rel}")
        elif not path.is_file():
            problems.append(f"missing: {rel}")
        elif sha256_file(path) != digest:
            problems.append(f"modified: {rel}")
    known = set(manifest)
    if root.exists():
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in EXEC_SUFFIXES and p.relative_to(root).as_posix() not in known:
                problems.append(f"unexpected executable: {p.relative_to(root).as_posix()}")
    return problems


def load_manifest(path: Path) -> dict[str, str] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise IntegrityError("manifest.json is malformed")
    return data


def safe_extract_tar(archive: Path, dest: Path) -> None:
    if not hasattr(tarfile, "data_filter"):
        raise IntegrityError("this Python lacks safe tar extraction; use Python 3.12+")
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        tar.extractall(dest, filter="data")


def safe_extract_zip(archive: Path, dest: Path) -> None:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            target = (root / info.filename).resolve()
            if target != root and not target.is_relative_to(root):
                raise IntegrityError(f"unsafe path in archive: {info.filename}")
        z.extractall(root)
