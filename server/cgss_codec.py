"""Clean-room codec for the CGSS 11.6.3 control-plane body envelope.

The envelope was reconstructed from the final Android 11.6.3 IL2CPP client.
This module intentionally does not embed client-static production constants
(SID salt / viewer-id wrapping key). Those should be supplied locally if a
research workflow actually needs to validate them.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

import msgpack
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_BLOCK_BITS = 128
DYNAMIC_KEY_BYTES = 32


def normalize_udid_iv(udid: str) -> bytes:
    """Convert a UUID-style UDID into the 16-byte AES IV used by the client."""
    compact = udid.replace("-", "")
    try:
        iv = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("UDID must be hexadecimal (hyphens are allowed)") from exc
    if len(iv) != 16:
        raise ValueError(f"UDID must decode to 16 bytes, got {len(iv)}")
    return iv


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != DYNAMIC_KEY_BYTES:
        raise ValueError("CGSS dynamic body key must be 32 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padded = _pkcs7_pad(data)
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != DYNAMIC_KEY_BYTES:
        raise ValueError("CGSS dynamic body key must be 32 bytes")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    return _pkcs7_unpad(padded)


def generate_dynamic_key() -> bytes:
    """Generate a safe 32-byte ASCII key compatible with AES-256.

    The original client generates a 32-character ASCII string through its own
    PRNG/formatting routine. For a compatibility server response, any 32-byte
    ASCII key is sufficient because the key is appended to the encrypted
    envelope itself and recovered by the peer.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return "".join(secrets.choice(alphabet) for _ in range(32)).encode("ascii")


def pack_plain(params: Any) -> bytes:
    """Return the inner Base64(MessagePack(params)) bytes used by PARAM/body."""
    packed = msgpack.packb(params, use_bin_type=True)
    return base64.b64encode(packed)


def unpack_plain(plain_b64: bytes) -> Any:
    packed = base64.b64decode(plain_b64, validate=True)
    return msgpack.unpackb(packed, raw=False, strict_map_key=False)


def encode_body(params: Any, udid: str, *, dynamic_key: bytes | None = None) -> bytes:
    """Encode params into the UTF-8 request/response body envelope.

    final bytes = ASCII(Base64(AES-CBC(Base64(MessagePack(params))) || key32))
    where IV = hex-decode(UDID without '-').
    """
    key = dynamic_key or generate_dynamic_key()
    if len(key) != DYNAMIC_KEY_BYTES:
        raise ValueError("dynamic_key must be exactly 32 bytes")
    # The client key material is an ASCII string. Enforce that property so
    # synthetic fixtures stay compatible with the observed implementation.
    key.decode("ascii")
    iv = normalize_udid_iv(udid)
    ciphertext = encrypt_cbc(pack_plain(params), key, iv)
    return base64.b64encode(ciphertext + key)


def decode_body(body: bytes | str, udid: str) -> Any:
    """Decode a CGSS body envelope into the MessagePack object."""
    if isinstance(body, str):
        body = body.encode("ascii")
    outer = base64.b64decode(body, validate=True)
    if len(outer) <= DYNAMIC_KEY_BYTES:
        raise ValueError("body is too short to contain ciphertext + dynamic key")
    ciphertext, key = outer[:-DYNAMIC_KEY_BYTES], outer[-DYNAMIC_KEY_BYTES:]
    key.decode("ascii")
    iv = normalize_udid_iv(udid)
    plain_b64 = decrypt_cbc(ciphertext, key, iv)
    return unpack_plain(plain_b64)


def compute_param(udid: str, viewer_id: int | str, path: str, plain_b64: bytes | str) -> str:
    """Compute the current 11.6.3 PARAM header.

    Native xrefs show SHA1(UDID + viewerId + Uri.AbsolutePath + innerPlainBase64).
    The caller should pass only the URL absolute path (for example `/load/check`).
    """
    if isinstance(plain_b64, bytes):
        plain_text = plain_b64.decode("ascii")
    else:
        plain_text = plain_b64
    material = f"{udid}{viewer_id}{path}{plain_text}".encode("utf-8")
    return hashlib.sha1(material).hexdigest()


def compute_sid(session_id: str, salt: str) -> str:
    """Compute SID when the locally extracted client salt is supplied."""
    return hashlib.md5((session_id + salt).encode("utf-8"), usedforsecurity=False).hexdigest()
