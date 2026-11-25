"""The pure parts of the App Store Connect token: base64url, the JWT header and
claims, and the ES256 signature's DER <-> raw (r || s) conversion. No key, no I/O;
the client signs with them."""

from __future__ import annotations

import base64

from .errors import ASCError

AUDIENCE = "appstoreconnect-v1"
TOKEN_LIFETIME = 20 * 60  # Apple refuses a token that lives longer


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_header(key_id: str) -> dict:
    return {"alg": "ES256", "kid": key_id, "typ": "JWT"}


def jwt_claims(issuer: str, now: int) -> dict:
    return {"iss": issuer, "iat": now, "exp": now + TOKEN_LIFETIME, "aud": AUDIENCE}


def _der_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(data[i + 1 : i + 1 + n], "big"), i + 1 + n


def der_to_raw(der: bytes, size: int = 32) -> bytes:
    """ECDSA-Sig-Value (DER SEQUENCE of r, s) -> the JWS form r || s."""
    if not der or der[0] != 0x30:
        raise ASCError("the signature is not a DER sequence")
    _, i = _der_len(der, 1)
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ASCError("the signature has no DER integer where one belongs")
        n, i = _der_len(der, i + 1)
        value = int.from_bytes(der[i : i + n], "big")
        out += value.to_bytes(size, "big")
        i += n
    return out


def raw_to_der(raw: bytes) -> bytes:
    """r || s -> DER, the inverse of der_to_raw (for verifying with openssl)."""
    half = len(raw) // 2

    def integer(b: bytes) -> bytes:
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = integer(raw[:half]) + integer(raw[half:])
    return b"\x30" + bytes([len(body)]) + body
