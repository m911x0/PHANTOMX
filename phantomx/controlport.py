"""Minimal tor ControlPort client (loopback + cookie auth) for "new identity"."""
from __future__ import annotations

import socket
from pathlib import Path


class ControlError(RuntimeError):
    pass


def _command(f, line: str) -> str:
    f.write(line.encode("ascii") + b"\r\n")
    f.flush()
    reply = f.readline().decode("ascii", "replace").strip()
    if not reply.startswith("250"):
        raise ControlError(reply or "no reply from tor")
    return reply


def new_identity(cookie_path: Path, port: int, timeout: float = 5) -> None:
    """Ask tor to use fresh circuits for new connections (existing ones are not cut)."""
    cookie = Path(cookie_path).read_bytes()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        f = s.makefile("rwb")
        _command(f, "AUTHENTICATE " + cookie.hex())
        _command(f, "SIGNAL NEWNYM")
        _command(f, "QUIT")
