"""Unit tests for the ledger verifier."""

import dataclasses
from typing import Any

from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.verify import verify_ledger


def _event(event_id: str, outcome: str = 'attempted', **overrides: object) -> dict[str, object]:
    """Build a wire event with an overridable outcome and fields."""
    event: dict[str, object] = {
        'id': event_id,
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
    }
    event.update(overrides)
    return event
    # end def


def _sealed_pair() -> Ledger:
    """Seal an attempt and its success outcome into a fresh partition."""
    ledger = Ledger('tenant-a')
    ledger.append(_event('00000000-0000-4000-8000-000000000001', 'attempted'), '2026-07-15T00:00:01.000Z')
    ledger.append(_event('00000000-0000-4000-8000-000000000001', 'success'), '2026-07-15T00:00:02.000Z')
    return ledger
    # end def


def _kinds(records: list[SealedRecord], anchored: str | None = None) -> set[str]:
    """Return the set of issue kinds from verifying `records`."""
    return {issue.kind for issue in verify_ledger(records, anchored).issues}
    # end def


def test_clean_ledger_verifies_ok() -> None:
    """A well-formed, correlated chain reports ok with the tail digest."""
    ledger = _sealed_pair()
    report = verify_ledger(ledger.records(), ledger.digest())
    assert report.ok
    assert report.count == 2
    assert report.computed_digest == ledger.digest()
    # end def


def test_golden_chain_verifies_ok(chain_vector: dict[str, Any]) -> None:
    """The golden sealed chain, reloaded from its dict form, verifies against its anchored digest."""
    records = [SealedRecord.from_dict(record) for record in chain_vector['records']]
    report = verify_ledger(records, chain_vector['digest'])
    assert report.ok
    assert report.computed_digest == chain_vector['digest']
    # end def


def test_tampered_event_body_is_localized() -> None:
    """Mutating a sealed event body breaks its record hash and the following link."""
    records = _sealed_pair().records()
    records[1] = dataclasses.replace(records[1], event=_event('00000000-0000-4000-8000-000000000001', 'failed'))
    report = verify_ledger(records)
    assert not report.ok
    assert 'record-hash-mismatch' in {issue.kind for issue in report.issues}
    # end def


def test_sequence_gap_is_detected() -> None:
    """A missing record leaves a forward seq gap (and a broken link)."""
    ledger = Ledger('tenant-a')
    for n in range(1, 4):
        ledger.append(_event(f'00000000-0000-4000-8000-00000000000{n}'), f'2026-07-15T00:00:0{n}.000Z')
        # end for
    records = ledger.records()
    del records[1]  # drop the middle record: seqs become [0, 2]
    assert 'seq-gap' in _kinds(records)
    # end def


def test_out_of_order_records_are_detected() -> None:
    """Reordered records fail the position check."""
    records = _sealed_pair().records()
    records.reverse()
    assert 'seq-out-of-order' in _kinds(records)
    # end def


def test_anchored_digest_mismatch_is_flagged() -> None:
    """A rewound or rewritten chain diverges from the out-of-band anchor."""
    ledger = _sealed_pair()
    report = verify_ledger(ledger.records(), anchored_digest='f' * 64)
    assert not report.ok
    assert any(issue.kind == 'digest-mismatch' and issue.seq is None for issue in report.issues)
    # end def


def test_outcome_without_attempt_is_flagged() -> None:
    """A success outcome with no correlating attempt is an anomaly, with the chain otherwise intact."""
    ledger = Ledger('tenant-a')
    ledger.append(_event('00000000-0000-4000-8000-0000000000ff', 'success'), '2026-07-15T00:00:01.000Z')
    kinds = _kinds(ledger.records())
    assert 'outcome-without-attempt' in kinds
    assert 'record-hash-mismatch' not in kinds
    # end def


def test_malformed_event_is_flagged_as_schema_invalid() -> None:
    """A sealed but malformed event is caught structurally without breaking the hash checks."""
    ledger = Ledger('tenant-a')
    malformed = _event('00000000-0000-4000-8000-000000000001')
    del malformed['target_resource']
    ledger.append(malformed, '2026-07-15T00:00:01.000Z')
    kinds = _kinds(ledger.records())
    assert 'schema-invalid' in kinds
    assert 'record-hash-mismatch' not in kinds
    # end def
