"""Pure-Python fallback with the *same* API and wire formats as the Rust core (`veil_core`).

Used when the Rust extension is not built. Byte-compatible: shares, key-check values,
ciphertexts and tags produced by either backend are interchangeable (tested in
tests/test_crypto.py). Python cannot guarantee memory zeroization, so the Rust backend is
the recommended one; this fallback wipes best-effort bytearrays only.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__version__ = "py-fallback"
KEY_LEN = 32
NONCE_LEN = 12
_CT_VERSION = 1
_SALT = b"veilproxy-v1"
_PREFIX = "veil1"


# ---- GF(2^8), AES polynomial 0x11b -------------------------------------------------
def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        p ^= a & (-(b & 1) & 0xFF)
        hi = -(a >> 7) & 0xFF
        a = ((a << 1) & 0xFF) ^ (0x1B & hi)
        b >>= 1
    return p


def _inv(a: int) -> int:
    r, base, e = 1, a, 254
    while e:
        if e & 1:
            r = _mul(r, base)
        base = _mul(base, base)
        e >>= 1
    return r


def _crc(k: int, x: int, y: bytes) -> str:
    return hashlib.sha256(_PREFIX.encode() + bytes([k, x]) + y).hexdigest()[:8]


def _encode(k: int, x: int, y: bytes) -> str:
    return f"{_PREFIX}:{k}:{x}:{y.hex()}:{_crc(k, x, y)}"


def _decode(text: str) -> tuple[int, int, bytes]:
    parts = text.strip().split(":")
    if len(parts) != 5 or parts[0] != _PREFIX:
        raise ValueError("malformed share (expected veil1:<k>:<x>:<hex>:<crc>)")
    try:
        k, x, y = int(parts[1]), int(parts[2]), bytes.fromhex(parts[3])
    except ValueError:
        raise ValueError("malformed share: bad fields") from None
    if not (0 < x < 256 and 2 <= k < 256) or not y:
        raise ValueError("malformed share: invalid fields")
    if _crc(k, x, y) != parts[4]:
        raise ValueError("share checksum mismatch (corrupted or mistyped share)")
    return k, x, y


def split_secret(secret: bytes, n: int, k: int) -> list[str]:
    if not secret:
        raise ValueError("secret must not be empty")
    if not (2 <= k <= n <= 255):
        raise ValueError("require 2 <= threshold <= shares <= 255")
    ys = [bytearray() for _ in range(n)]
    for s in secret:
        coeffs = [s] + list(secrets.token_bytes(k - 1))
        for i in range(n):
            x, y = i + 1, 0
            for c in reversed(coeffs):
                y = _mul(y, x) ^ c
            ys[i].append(y)
    return [_encode(k, i + 1, bytes(ys[i])) for i in range(n)]


def _combine(shares: list[str]) -> bytearray:
    if not shares:
        raise ValueError("no shares supplied")
    dec = [_decode(s) for s in shares]
    k, ln = dec[0][0], len(dec[0][2])
    if any(d[0] != k or len(d[2]) != ln for d in dec):
        raise ValueError("shares come from different splits")
    xs = [d[1] for d in dec]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share supplied")
    if len(dec) < k:
        raise ValueError(f"insufficient shares: need {k}, got {len(dec)}")
    used = dec[:k]
    basis = []
    for i, (_, xi, _) in enumerate(used):
        num = den = 1
        for j, (_, xj, _) in enumerate(used):
            if i != j:
                num = _mul(num, xj)
                den = _mul(den, xi ^ xj)
        basis.append(_mul(num, _inv(den)))
    out = bytearray(ln)
    for b in range(ln):
        acc = 0
        for i, (_, _, y) in enumerate(used):
            acc ^= _mul(y[b], basis[i])
        out[b] = acc
    return out


def combine_shares(shares: list[str]) -> bytes:
    return bytes(_combine(shares))


# ---- KDF / AEAD ---------------------------------------------------------------------
def _derive(master: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=_SALT, info=info).derive(master)


def _info(label: str, session: str) -> bytes:
    return label.encode() + b"|" + session.encode()


def _key_check(master: bytes) -> str:
    return _derive(master, b"keycheck", 16).hex()


def generate_shares(n: int, k: int) -> tuple[list[str], str]:
    master = bytearray(secrets.token_bytes(KEY_LEN))
    try:
        return split_secret(bytes(master), n, k), _key_check(bytes(master))
    finally:
        for i in range(len(master)):
            master[i] = 0


class KeyHolder:
    def __init__(self) -> None:
        self._key: bytearray | None = None

    def is_unlocked(self) -> bool:
        return self._key is not None

    def unlock(self, shares: list[str], key_check: str) -> bool:
        secret = _combine(list(shares))
        try:
            if len(secret) != KEY_LEN:
                return False
            if hmac.compare_digest(_key_check(bytes(secret)), key_check):
                self._key = bytearray(secret)
                return True
            return False
        finally:
            for i in range(len(secret)):
                secret[i] = 0

    def lock(self) -> None:
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
        self._key = None

    def _master(self) -> bytes:
        if self._key is None:
            raise ValueError("vault is locked")
        return bytes(self._key)

    def encrypt(self, session: str, plaintext: bytes, aad: bytes) -> bytes:
        key = _derive(self._master(), _info("session", session), KEY_LEN)
        nonce = secrets.token_bytes(NONCE_LEN)
        return bytes([_CT_VERSION]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, session: str, blob: bytes, aad: bytes) -> bytes:
        if len(blob) < 1 + NONCE_LEN + 16 or blob[0] != _CT_VERSION:
            raise ValueError("ciphertext malformed or unsupported version")
        key = _derive(self._master(), _info("session", session), KEY_LEN)
        try:
            return AESGCM(key).decrypt(blob[1 : 1 + NONCE_LEN], blob[1 + NONCE_LEN :], aad)
        except Exception:
            raise ValueError(
                "authentication failed (wrong key, wrong context or tampered data)"
            ) from None

    def tag(self, session: str, data: bytes) -> str:
        key = _derive(self._master(), _info("tag", session), KEY_LEN)
        return hmac.new(key, data, hashlib.sha256).hexdigest()
