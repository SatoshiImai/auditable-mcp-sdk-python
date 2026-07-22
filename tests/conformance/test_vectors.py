"""Cross-language conformance: reproduce every golden vector byte-for-byte (spec §8.4, §11.1).

These are the tests that prove the SDK speaks the same wire as the TypeScript SDK. If any of them
fails, the SDK is non-conformant — not merely different.
"""

from typing import Any

from auditable_mcp import (
    AuditEvent,
    canonicalize,
    compute_record_hash,
    sha256_hex,
)
from auditable_mcp.hashing import GENESIS_HASH


def test_canonicalization_vectors_reproduce_exact_bytes_and_hash(
    canonicalization_vectors: list[dict[str, Any]],
) -> None:
    """Every canonicalization vector must reproduce the exact JCS string and SHA-256."""
    for vector in canonicalization_vectors:
        canonical = canonicalize(vector['value'])
        assert canonical == vector['canonical'], vector['name']
        assert sha256_hex(canonical) == vector['sha256'], vector['name']
        # end for


def test_event_vectors_canonicalize_and_hash_exactly(event_vectors: list[dict[str, Any]]) -> None:
    """Each golden event canonicalizes to the exact bytes and hash."""
    for vector in event_vectors:
        canonical = canonicalize(vector['event'])
        assert canonical == vector['canonical'], vector['name']
        assert sha256_hex(canonical) == vector['sha256'], vector['name']
        # end for


def test_event_vectors_roundtrip_through_the_pydantic_model(event_vectors: list[dict[str, Any]]) -> None:
    """Parsing a golden event into AuditEvent and re-emitting it preserves the exact wire bytes."""
    for vector in event_vectors:
        event = AuditEvent.model_validate(vector['event'])
        assert event.to_wire() == vector['event'], vector['name']
        assert canonicalize(event.to_wire()) == vector['canonical'], vector['name']
        # end for


def test_event_vectors_validate_against_the_shared_schema(
    event_vectors: list[dict[str, Any]],
    event_schema_validator: Any,
) -> None:
    """Every golden event — and the model's re-emission of it — validates against the shared schema."""
    for vector in event_vectors:
        assert not list(event_schema_validator.iter_errors(vector['event'])), vector['name']
        emitted = AuditEvent.model_validate(vector['event']).to_wire()
        assert not list(event_schema_validator.iter_errors(emitted)), vector['name']
        # end for


def test_chain_vector_record_hashes_and_links_reproduce(chain_vector: dict[str, Any]) -> None:
    """Recompute each record hash from the §8.2 preimage and verify the chain links to the digest."""
    previous_hash = GENESIS_HASH
    for index, record in enumerate(chain_vector['records']):
        assert record['seq'] == index
        assert record['previous_hash'] == previous_hash
        recomputed = compute_record_hash(
            record['event'],
            record['seq'],
            record['host_ts'],
            record['previous_hash'],
        )
        assert recomputed == record['record_hash'], f'record {index}'
        previous_hash = recomputed
        # end for
    assert previous_hash == chain_vector['digest']
