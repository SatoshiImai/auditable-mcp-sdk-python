"""Unit tests for the canonicalization numeric-domain guard (§8.1)."""

import pytest

from auditable_mcp.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonicalize,
    has_unsafe_number,
    hash_canonical,
    sha256_hex,
)


def test_key_ordering_is_lexicographic() -> None:
    """JCS orders object keys lexicographically regardless of insertion order."""
    assert canonicalize({'b': 1, 'a': 2}) == '{"a":2,"b":1}'
    # end def


def test_booleans_are_never_treated_as_unsafe_numbers() -> None:
    """bool is an int subclass but must not be flagged by the numeric-domain guard."""
    assert has_unsafe_number(True) is False
    assert has_unsafe_number({'flag': False}) is False
    # end def


def test_integer_at_the_safe_boundary_is_accepted() -> None:
    """An integer exactly at ±(2^53-1) stays inside the canonicalization domain."""
    assert has_unsafe_number(MAX_SAFE_INTEGER) is False
    assert canonicalize({'n': MAX_SAFE_INTEGER}) == f'{{"n":{MAX_SAFE_INTEGER}}}'
    # end def


def test_integer_beyond_the_safe_boundary_is_rejected() -> None:
    """An integer beyond ±(2^53-1) cannot round-trip as a double and must be rejected."""
    assert has_unsafe_number(MAX_SAFE_INTEGER + 1) is True
    with pytest.raises(CanonicalizationError):
        canonicalize({'n': MAX_SAFE_INTEGER + 1})
        # end with
    # end def


def test_non_finite_floats_are_rejected() -> None:
    """Infinity and NaN have no JCS form and must be rejected."""
    assert has_unsafe_number(float('inf')) is True
    assert has_unsafe_number(float('nan')) is True
    # end def


def test_nested_unsafe_numbers_are_detected() -> None:
    """The guard recurses into nested objects and arrays."""
    assert has_unsafe_number({'a': [1, {'b': MAX_SAFE_INTEGER + 1}]}) is True
    # end def


def test_context_hash_carries_the_algorithm_prefix() -> None:
    """hash_canonical emits a `sha256:<hex>` commitment (§4.3)."""
    digest = hash_canonical({'tables': ['users']})
    assert digest.startswith('sha256:')
    assert digest == f'sha256:{sha256_hex(canonicalize({"tables": ["users"]}))}'
    # end def
