"""RFC 8785 (JCS) canonical JSON serialization, the numeric-domain guard, and SHA-256 hashing.

This is the cross-language bedrock of ledger integrity (spec §8). Serialization is delegated to
the `rfc8785` package rather than a hand-rolled serializer; the TypeScript SDK uses `canonicalize`.
Both implement RFC 8785 and produce byte-identical output, verified against the shared conformance
vectors under `spec/vectors/`.
"""

import math
from hashlib import sha256
from typing import Any, cast

import rfc8785

# §8.1: JCS serializes numbers as IEEE-754 doubles, so integer-valued numbers must stay within the
# safe-integer range or canonicalization diverges across runtimes.
MAX_SAFE_INTEGER = 2**53 - 1

# The action_context_hash commitment (§4.3) names its algorithm; only SHA-256 is defined in v0.1.
CONTEXT_HASH_PREFIX = 'sha256:'


class CanonicalizationError(ValueError):
    """A value cannot be canonicalized under the §8.1 numeric domain."""

    # end class


def has_unsafe_number(value: object) -> bool:
    """Report whether any number in `value` falls outside the §8.1 canonicalization domain.

    Rejected values are non-finite floats (which have no JCS form) and integer-valued numbers whose
    magnitude exceeds ``MAX_SAFE_INTEGER``. A runtime cannot distinguish an exact integer beyond that
    bound (which would lose precision as a double) from an integer-valued float, so both are
    conservatively rejected to preserve cross-language identity. A host uses this to reject such an
    event gracefully (§7.1) instead of letting canonicalization raise at seal time.

    Args:
        value: Any JSON-compatible value.

    Returns:
        True if some contained number is not canonicalizable.
    """
    # bool is an int subclass but is never a numeric-domain concern; check it first.
    if isinstance(value, bool):
        return False
        # end if
    if isinstance(value, int):
        return abs(value) > MAX_SAFE_INTEGER
        # end if
    if isinstance(value, float):
        return not math.isfinite(value) or (value.is_integer() and abs(value) > MAX_SAFE_INTEGER)
        # end if
    if isinstance(value, dict):
        return any(has_unsafe_number(item) for item in value.values())
        # end if
    if isinstance(value, list):
        return any(has_unsafe_number(item) for item in value)
        # end if
    return False
    # end def


def canonicalize(value: object) -> str:
    """Serialize a JSON-compatible value to its RFC 8785 (JCS) canonical string.

    Args:
        value: Any JSON-compatible value (dict, list, str, int, float, bool, None).

    Returns:
        The RFC 8785 canonical JSON string.

    Raises:
        CanonicalizationError: If any contained number is outside the §8.1 domain.
    """
    if has_unsafe_number(value):
        raise CanonicalizationError('a numeric value is not canonicalizable (non-finite or outside ±(2^53-1)) (§8.1)')
        # end if
    # `value` is validated JSON above; rfc8785 types its parameter as a narrower JSON union.
    return rfc8785.dumps(cast(Any, value)).decode('utf-8')
    # end def


def sha256_hex(data: str) -> str:
    """Return the lowercase hex-encoded SHA-256 of `data` encoded as UTF-8."""
    return sha256(data.encode('utf-8')).hexdigest()
    # end def


def hash_canonical(value: object) -> str:
    """Return the ``sha256:<hex>`` commitment over the canonical form of `value` (§4.3).

    This is the ``action_context_hash`` construction: a tool-authored commitment carrying an
    algorithm prefix, distinct from the bare-hex chain hashes of §8.2.

    Args:
        value: The exact internal context to commit to.

    Returns:
        The ``sha256:<hex>`` digest string.
    """
    return f'{CONTEXT_HASH_PREFIX}{sha256_hex(canonicalize(value))}'
    # end def
