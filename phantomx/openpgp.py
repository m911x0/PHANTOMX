"""Minimal OpenPGP detached-signature verifier (RFC 4880, v4 RSA), pure Python.

Scope is deliberately tiny: verify that a file was signed by a key in a *pinned* key file
shipped with PhantomX (Tor Browser Developers). No keyring, no web of trust, no network.
The key file itself is trusted because it is part of this package.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

HASHES = {2: ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
          8: ("sha256", bytes.fromhex("3031300d060960864801650304020105000420")),
          9: ("sha384", bytes.fromhex("3041300d060960864801650304020205000430")),
          10: ("sha512", bytes.fromhex("3051300d060960864801650304020305000440"))}


class PGPError(ValueError):
    pass


@dataclass(frozen=True)
class RSAKey:
    fingerprint: str  # hex, upper
    n: int
    e: int

    @property
    def key_id(self) -> str:
        return self.fingerprint[-16:]


def dearmor(text: str) -> bytes:
    lines = text.strip().splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("-----BEGIN PGP"))
        end = next(i for i, l in enumerate(lines) if l.startswith("-----END PGP"))
    except StopIteration as exc:
        raise PGPError("not ASCII-armored OpenPGP data") from exc
    body = lines[start + 1:end]
    while body and body[0].strip():  # skip armor headers (e.g. "Comment: ...")
        if ":" not in body[0]:
            break
        body = body[1:]
    data = "".join(l.strip() for l in body if l.strip() and not l.startswith("="))
    return base64.b64decode(data)


def packets(data: bytes):
    i = 0
    while i < len(data):
        tag_byte = data[i]
        if not tag_byte & 0x80:
            raise PGPError("invalid packet header")
        if tag_byte & 0x40:  # new format
            tag = tag_byte & 0x3F
            first = data[i + 1]
            if first < 192:
                length, i = first, i + 2
            elif first < 224:
                length, i = ((first - 192) << 8) + data[i + 2] + 192, i + 3
            elif first == 255:
                length, i = int.from_bytes(data[i + 2:i + 6], "big"), i + 6
            else:
                raise PGPError("partial body lengths are not supported")
        else:  # old format
            tag = (tag_byte >> 2) & 0x0F
            ltype = tag_byte & 0x03
            if ltype == 3:
                raise PGPError("indeterminate length not supported")
            size = 1 << ltype
            length = int.from_bytes(data[i + 1:i + 1 + size], "big")
            i += 1 + size
        yield tag, data[i:i + length]
        i += length


def _mpi(buf: bytes, pos: int) -> tuple[int, int]:
    bits = int.from_bytes(buf[pos:pos + 2], "big")
    n = (bits + 7) // 8
    return int.from_bytes(buf[pos + 2:pos + 2 + n], "big"), pos + 2 + n


def load_keys(armored: str) -> list[RSAKey]:
    keys = []
    for tag, body in packets(dearmor(armored)):
        if tag not in (6, 14) or not body or body[0] != 4:
            continue
        if body[5] not in (1, 2, 3):  # RSA only
            continue
        n, pos = _mpi(body, 6)
        e, _ = _mpi(body, pos)
        fp = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
        keys.append(RSAKey(fp, n, e))
    if not keys:
        raise PGPError("no RSA keys found")
    return keys


def _issuers(subpackets: bytes) -> set[str]:
    out, i = set(), 0
    while i < len(subpackets):
        first = subpackets[i]
        if first < 192:
            length, i = first, i + 1
        elif first < 255:
            length, i = ((first - 192) << 8) + subpackets[i + 1] + 192, i + 2
        else:
            length, i = int.from_bytes(subpackets[i + 1:i + 5], "big"), i + 5
        stype, payload = subpackets[i] & 0x7F, subpackets[i + 1:i + length]
        if stype == 16:
            out.add(payload.hex().upper())
        elif stype == 33 and payload:
            out.add(payload[1:].hex().upper()[-16:])
        i += length
    return out


def verify_detached(data: bytes, armored_sig: str, keys: list[RSAKey]) -> RSAKey:
    """Return the key that made a valid signature over `data`; raise PGPError otherwise."""
    sigs = [body for tag, body in packets(dearmor(armored_sig)) if tag == 2]
    if not sigs:
        raise PGPError("no signature packet")
    errors = []
    for sig in sigs:
        if sig[0] != 4:
            errors.append("unsupported signature version")
            continue
        sig_type, pub_algo, hash_algo = sig[1], sig[2], sig[3]
        if sig_type not in (0x00, 0x01) or pub_algo not in (1, 3) or hash_algo not in HASHES:
            errors.append("unsupported signature type/algorithm")
            continue
        hlen = int.from_bytes(sig[4:6], "big")
        hashed = sig[6:6 + hlen]
        pos = 6 + hlen
        ulen = int.from_bytes(sig[pos:pos + 2], "big")
        unhashed = sig[pos + 2:pos + 2 + ulen]
        pos += 2 + ulen
        left16 = sig[pos:pos + 2]
        s, _ = _mpi(sig, pos + 2)

        payload = data
        if sig_type == 0x01:  # canonical text
            payload = b"\r\n".join(l.rstrip(b"\r") for l in data.split(b"\n"))
        header = sig[0:6 + hlen]
        trailer = b"\x04\xff" + len(header).to_bytes(4, "big")
        name, prefix = HASHES[hash_algo]
        digest = hashlib.new(name, payload + header + trailer).digest()
        if digest[:2] != left16:
            errors.append("hash mismatch (data does not match signature)")
            continue
        wanted = _issuers(hashed) | _issuers(unhashed)
        for key in keys:
            if wanted and key.key_id not in wanted:
                continue
            k = (key.n.bit_length() + 7) // 8
            em = pow(s, key.e, key.n).to_bytes(k, "big")
            t = prefix + digest
            expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
            if em == expected:
                return key
        errors.append("no pinned key produced this signature")
    raise PGPError("; ".join(errors))
