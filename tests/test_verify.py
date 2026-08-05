"""Unit tests for the ledger verifier."""

import dataclasses
from typing import Any, cast

from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import first_sealed_validation_error, first_validation_error
from auditable_mcp.verify import RecordAdapter, verify_chain, verify_ledger


def _event(event_id: str, outcome: str = 'attempted', **overrides: object) -> dict[str, object]:
    """Build a wire event with an overridable outcome and fields."""
    event: dict[str, object] = {
        'id': event_id,
        'spec_version': 'auditable-mcp/0.2',
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


def test_prior_version_sealed_chain_still_verifies() -> None:
    """A chain sealed under an earlier published spec_version verifies: its bytes are immutable evidence."""
    ledger = Ledger('tenant-a')
    legacy = 'auditable-mcp/0.1.1'
    ledger.append(
        _event('00000000-0000-4000-8000-000000000001', 'attempted', spec_version=legacy), '2026-07-15T00:00:01.000Z'
    )
    ledger.append(
        _event('00000000-0000-4000-8000-000000000001', 'success', spec_version=legacy), '2026-07-15T00:00:02.000Z'
    )
    report = verify_ledger(ledger.records())
    assert report.ok
    assert report.issues == []
    # end def


def test_ingest_strict_but_verification_lenient_on_spec_version() -> None:
    """Read/write split: ingest rejects a prior spec_version; the sealed-record verifier accepts it."""
    legacy = _event('00000000-0000-4000-8000-000000000001', spec_version='auditable-mcp/0.1.1')
    assert first_validation_error(legacy) is not None
    assert first_sealed_validation_error(legacy) is None
    # end def


def _enveloped(amcp_event: dict[str, object]) -> dict[str, object]:
    """Wrap an a-MCP event the way a SEP-3004 host would: nested under an envelope key."""
    return {'schema': 'sep3004', 'sealed_at': '2026-07-15T00:00:00Z', 'amcp': amcp_event}
    # end def


def test_verify_ledger_reaches_into_an_envelope_via_adapter() -> None:
    """An injected adapter lets the verifier correlate and schema-check a-MCP events sealed in envelopes."""
    ledger = Ledger('tenant-a')
    ledger.append(_enveloped(_event('00000000-0000-4000-8000-000000000001', 'attempted')), '2026-07-15T00:00:01.000Z')
    ledger.append(_enveloped(_event('00000000-0000-4000-8000-000000000001', 'success')), '2026-07-15T00:00:02.000Z')
    adapter = RecordAdapter(
        id_of=lambda event: cast('dict[str, object]', event['amcp'])['id'],
        is_attempt=lambda event: cast('dict[str, object]', event['amcp'])['outcome'] == 'attempted',
        event_of=lambda event: event['amcp'],
    )
    report = verify_ledger(ledger.records(), adapter=adapter)
    assert report.ok
    assert report.issues == []
    # end def


def test_default_adapter_cannot_read_an_envelope() -> None:
    """Without an adapter the envelope's top level is not an a-MCP event: schema-invalid is raised."""
    ledger = Ledger('tenant-a')
    ledger.append(_enveloped(_event('00000000-0000-4000-8000-000000000001', 'attempted')), '2026-07-15T00:00:01.000Z')
    assert 'schema-invalid' in _kinds(ledger.records())
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
    assert 'seq-gap' in _kinds(records)
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
    assert 'orphaned-outcome' in kinds
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


def _boundary_event(event_id: str, outcome: str = 'attempted', **overrides: object) -> dict[str, object]:
    """A richer, deliberately non-A-MCP envelope sealed through the same `Ledger` primitive."""
    event: dict[str, object] = {
        'id': event_id,
        'actor': 'odin',
        'tenant': 'tenant-a',
        'category': 'boundary',
        'outcome': outcome,
    }
    event.update(overrides)
    return event
    # end def


def _sealed_boundary_pair() -> Ledger:
    """Seal a boundary attempt and a host-side outcome that the A-MCP schema forbids by construction."""
    ledger = Ledger('tenant-a')
    ledger.append(_boundary_event('call-1', 'attempted'), '2026-07-15T00:00:01.000Z')
    ledger.append(_boundary_event('call-1', 'denied'), '2026-07-15T00:00:02.000Z')
    return ledger
    # end def


def test_verify_chain_accepts_a_non_amcp_envelope() -> None:
    """A non-A-MCP chain passes chain verification; verify_ledger rejects the same records as schema-invalid."""
    ledger = _sealed_boundary_pair()
    records = ledger.records()
    chain = verify_chain(records, ledger.digest())
    assert chain.ok
    assert chain.computed_digest == ledger.digest()
    assert 'schema-invalid' in {issue.kind for issue in verify_ledger(records, ledger.digest()).issues}
    # end def


def test_verify_chain_still_detects_tampering_on_a_non_amcp_envelope() -> None:
    """The schema-free path keeps the integrity checks: a mutated boundary body breaks its record hash."""
    records = _sealed_boundary_pair().records()
    records[1] = dataclasses.replace(records[1], event=_boundary_event('call-1', 'expired'))
    report = verify_chain(records)
    assert not report.ok
    kinds = {issue.kind for issue in report.issues}
    assert 'record-hash-mismatch' in kinds
    assert 'schema-invalid' not in kinds
    # end def


def test_verify_chain_detects_a_seq_gap_on_a_non_amcp_envelope() -> None:
    """A dropped boundary record still surfaces a seq gap under the schema-free path."""
    ledger = Ledger('tenant-a')
    for n in range(1, 4):
        ledger.append(_boundary_event(f'call-{n}'), f'2026-07-15T00:00:0{n}.000Z')
        # end for
    records = ledger.records()
    del records[1]
    assert 'seq-gap' in {issue.kind for issue in verify_chain(records).issues}
    # end def
