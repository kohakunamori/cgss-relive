"""CGSS 11.6.3 request-header obfuscation helpers.

``Cryptographer.decode`` was reconstructed from the final Android 11.6.3
arm64 IL2CPP implementation (RVA 0x050c3688).  The custom format is not
cryptography: it prefixes the plaintext UTF-16/string length as four hex
characters, stores each original character (codepoint + 10) at offset 2 of a
four-character noise group, then appends random noise.  Only decoding is
needed by the compatibility server.
"""
from __future__ import annotations


class HeaderDecodeError(ValueError):
    """Raised when a CGSS obfuscated header is structurally invalid."""


def decode_header_value(value: str) -> str:
    """Reverse ``Cute.Cryptographer.encode`` for ASCII-oriented API headers.

    The final client uses this scheme for values such as UDID and USER-ID.
    Production noise digits are intentionally ignored; only the length prefix
    and the every-fourth encoded character carry plaintext information.
    """

    if len(value) < 4:
        raise HeaderDecodeError("encoded header is shorter than the 4-char length prefix")
    try:
        expected = int(value[:4], 16)
    except ValueError as exc:
        raise HeaderDecodeError("encoded header length prefix is not hexadecimal") from exc

    encoded = value[4:]
    out: list[str] = []
    # Final native decode examines positions 2, 6, 10, ... and subtracts 10
    # from the UTF-16 character value until the prefixed plaintext length is
    # reached.  The remaining suffix is random cover data.
    for index in range(2, len(encoded), 4):
        if len(out) >= expected:
            break
        codepoint = ord(encoded[index]) - 10
        if codepoint < 0:
            raise HeaderDecodeError("encoded character underflows the +10 transform")
        out.append(chr(codepoint))

    if len(out) != expected:
        raise HeaderDecodeError(
            f"encoded header ended early: expected {expected} chars, decoded {len(out)}"
        )
    return "".join(out)
