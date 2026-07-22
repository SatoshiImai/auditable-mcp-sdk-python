"""Unit tests for the per-partition sealed ledger."""

from typing import Any

from auditable_mcp.hashing import GENESIS_HASH
from auditable_mcp.ledger import Ledger, SealedRecord


def _attempt(event_id: str) -> dict[str, object]:
    """Build a minimal attempt wire event."""
    return {
        'id': event_id,
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    # end def


def test_empty_ledger_digest_is_genesis() -> None:
    """An empty partition anchors from the 64-zero genesis link."""
    ledger = Ledger('tenant-a')
    assert len(ledger) == 0
    assert ledger.digest() == GENESIS_HASH
    # end def


def test_append_assigns_monotonic_seq_and_links_the_chain() -> None:
    """Each append takes the next seq and links to the prior record hash."""
    ledger = Ledger('tenant-a')
    first = ledger.append(_attempt('00000000-0000-4000-8000-000000000001'), '2026-07-15T00:00:01.000Z')
    second = ledger.append(_attempt('00000000-0000-4000-8000-000000000002'), '2026-07-15T00:00:02.000Z')
    assert first.seq == 0
    assert first.previous_hash == GENESIS_HASH
    assert second.seq == 1
    assert second.previous_hash == first.record_hash
    assert ledger.digest() == second.record_hash
    # end def


def test_records_returns_a_copy() -> None:
    """Mutating the returned list must not affect the ledger's internal state."""
    ledger = Ledger('tenant-a')
    ledger.append(_attempt('00000000-0000-4000-8000-000000000001'), '2026-07-15T00:00:01.000Z')
    snapshot = ledger.records()
    snapshot.clear()
    assert len(ledger) == 1
    # end def


def test_sealing_the_golden_chain_reproduces_its_hashes_and_digest(chain_vector: dict[str, Any]) -> None:
    """Feeding the golden chain's events into a fresh ledger reproduces every record hash byte-for-byte."""
    ledger = Ledger('golden')
    for record in chain_vector['records']:
        sealed = ledger.append(record['event'], record['host_ts'])
        assert sealed.record_hash == record['record_hash'], f'seq {record["seq"]}'
        # end for
    assert ledger.digest() == chain_vector['digest']
    # end def


def test_sealed_record_dict_roundtrip(chain_vector: dict[str, Any]) -> None:
    """A record survives a persistence round-trip through to_dict/from_dict unchanged."""
    original = SealedRecord.from_dict(chain_vector['records'][0])
    restored = SealedRecord.from_dict(original.to_dict())
    assert restored == original
    assert restored.record_hash == chain_vector['records'][0]['record_hash']
    # end def
