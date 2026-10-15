"""The salted hash of an internal context (§4.3): `action_context_salted_hash`.

The construction of SD-JWT (RFC 9901 §4.2.2, §4.2.3) applied to the whole context as one array-element
Disclosure: the Disclosure is base64url(UTF-8(JSON `[salt, context]`)) and the salted hash is
base64url(SHA-256(ASCII(Disclosure))). The digest is taken over the Disclosure string as the tool encoded
it, so the JSON inside need not be canonical (§8): whoever opens the hash is handed that exact string. A
tool that may be asked to open it retains the Disclosure (§4.3); this module only computes and checks, it
keeps nothing.
"""

import json
import secrets
from hashlib import sha256
from typing import Final

from auditable_mcp.encoding import b64url_decode, b64url_encode

SALTED_HASH_PATTERN: Final = r'^[A-Za-z0-9_-]{43}$'
"""The salted hash's shape: base64url without padding of a 32-byte SHA-256 digest (§4.3)."""

# RFC 9901 §4.2.1 recommends at least 128 bits of salt.
_SALT_BYTES: Final = 16


def new_salt() -> str:
    """Return a fresh base64url salt of 128 bits from a cryptographically secure source."""
    return b64url_encode(secrets.token_bytes(_SALT_BYTES))
    # end def


def disclosure_of(salt: str, context: dict[str, object]) -> str:
    """Return the Disclosure of `context` under `salt` (§4.3).

    Args:
        salt: The base64url salt.
        context: The exact internal context.

    Returns:
        The Disclosure string.
    """
    encoded = json.dumps([salt, context], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return b64url_encode(encoded)
    # end def


def salted_hash_of(disclosure: str) -> str:
    """Return the salted hash of a Disclosure: base64url of the SHA-256 of its ASCII bytes (§4.3)."""
    return b64url_encode(sha256(disclosure.encode('ascii')).digest())
    # end def


def open_salted_hash(disclosure: str, salted_hash: str) -> dict[str, object] | None:
    """Return the context `disclosure` opens if it is the one `salted_hash` commits to, else None.

    A Disclosure that is not base64url, does not hash to `salted_hash`, or does not decode to a
    two-element array of a string salt and an object opens nothing.

    Args:
        disclosure: The Disclosure string the tool retained.
        salted_hash: The `action_context_salted_hash` sealed on the event.

    Returns:
        The context, or None.
    """
    raw = b64url_decode(disclosure)
    if raw is None or salted_hash_of(disclosure) != salted_hash:
        return None
        # end if
    try:
        decoded = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return None
        # end try
    if not isinstance(decoded, list) or len(decoded) != 2 or not isinstance(decoded[0], str):
        return None
        # end if
    context = decoded[1]
    if not isinstance(context, dict):
        return None
        # end if
    return context
    # end def
