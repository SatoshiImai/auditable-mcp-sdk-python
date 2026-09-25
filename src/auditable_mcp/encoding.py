"""base64url without padding: how a signature (§5.1) and a JWK member (RFC 7517) are written.

§5.1 writes a signature the way JWS does ([RFC-7515] §2), so a key held as a JWK and a signature are
encoded alike. The decoder is strict: a value outside the alphabet, carrying padding, or with stray
bits in its last character is refused, because two decoders that forgive different things turn one
signature into two byte strings.
"""

import base64
import binascii
import re
from typing import Final

_ALPHABET: Final = re.compile(r'[A-Za-z0-9_-]*')
# Standard base64 with padding, how records sealed before v0.3 encoded a signature.
_STANDARD: Final = re.compile(r'[A-Za-z0-9+/]+={0,2}')


def b64url_encode(raw: bytes) -> str:
    """Encode `raw` as base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    # end def


def b64url_decode(value: object) -> bytes | None:
    """Decode strict base64url without padding, or return None for anything else.

    Args:
        value: The encoded value, as read from a document.

    Returns:
        The decoded bytes, or None when `value` is not a string or not canonical base64url.
    """
    if not isinstance(value, str) or not _ALPHABET.fullmatch(value) or len(value) % 4 == 1:
        return None
        # end if
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
        # end try
    # The round trip rejects stray bits in the last character, which the decoder would drop.
    return raw if b64url_encode(raw) == value else None
    # end def


def b64_standard_decode(value: object) -> bytes | None:
    """Decode strict standard base64 with padding, or return None for anything else.

    Records sealed under a version before v0.3 wrote their signatures this way, and a verifier decodes
    each record as its own version encoded it (§11.4). Nothing current is written in this form.

    Args:
        value: The encoded value, as read from a sealed record.

    Returns:
        The decoded bytes, or None when `value` is not a string or not canonical padded base64.
    """
    if not isinstance(value, str) or not _STANDARD.fullmatch(value) or len(value) % 4 != 0:
        return None
        # end if
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
        # end try
    return raw if base64.b64encode(raw).decode('ascii') == value else None
    # end def
