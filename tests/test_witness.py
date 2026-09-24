"""Unit tests for the witness axis (§5.2, §7.1, §7.2): the host side."""

import base64

import pytest
from cryptography.exceptions import InvalidSignature

from auditable_mcp.hashing import witness_payload
from auditable_mcp.host import AuditHost
from auditable_mcp.l2 import Ed25519WitnessSigner, generate_tool_key
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import SPEC_VERSION, AcceptResponse, AuditCapability, Level, Witness

_HOST_KEY_ID = 'host-key-2026'


class _Clock:
    """A deterministic host clock, so two chains sealed from the same events are comparable."""

    def __init__(self) -> None:
        """Start the counter at the first tick."""
        self._tick = 0
        # end def

    def now(self) -> str:
        """Return the next fixed timestamp."""
        self._tick += 1
        return f'2026-07-15T00:00:{self._tick:02d}.000Z'
        # end def

    # end class


def _event(event_id: str, outcome: str = 'attempted') -> dict[str, object]:
    """A minimal valid event, varying only what a test needs."""
    return {
        'id': event_id,
        'spec_version': SPEC_VERSION,
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call-1',
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
    }
    # end def


def _capability(witness: Witness) -> AuditCapability:
    """A host capability declaring a position on the witness axis."""
    return AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', witness=witness)
    # end def


def _signing_host() -> tuple[AuditHost, Ed25519WitnessSigner, object]:
    """A host that declares it signs, with the key a verifier's registry would hold."""
    key = generate_tool_key(_HOST_KEY_ID)
    signer = Ed25519WitnessSigner(key.key_id, key.private_key)
    host = AuditHost('tenant-a', _capability(Witness.HOST), witness_signer=signer, clock=_Clock())
    return host, signer, key.private_key.public_key()
    # end def


def test_a_host_declaring_it_signs_must_be_given_a_signer() -> None:
    """Declaring the axis and not providing the means would leave every record unwitnessed (§11.2)."""
    with pytest.raises(ValueError, match='WitnessSigner'):
        AuditHost('tenant-a', _capability(Witness.HOST))
        # end with
    # end def


@pytest.mark.asyncio
async def test_an_accept_from_a_signing_host_carries_a_verifiable_witness() -> None:
    """The signature covers the host-assigned fields the accept returns (§7.1)."""
    host, _signer, public_key = _signing_host()
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.host_key_id == _HOST_KEY_ID
    assert response.host_signature is not None
    payload = witness_payload(response.seq, response.host_ts, response.previous_hash, response.record_hash)
    public_key.verify(base64.b64decode(response.host_signature), payload)  # type: ignore[attr-defined]
    # end def


@pytest.mark.asyncio
async def test_a_non_signing_host_returns_no_witness_fields() -> None:
    """A host that declares `none` returns neither field; the pair is all-or-nothing (§7.1)."""
    host = AuditHost('tenant-a', _capability(Witness.NONE))
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.host_signature is None
    assert response.host_key_id is None
    # end def


@pytest.mark.asyncio
async def test_sealed_outcome_records_are_witnessed_too() -> None:
    """audit/outcome has no response channel, so the signature is written into the ledger (§7.2)."""
    host, _signer, public_key = _signing_host()
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_event(event_id))
    await host.handle_outcome(_event(event_id, outcome='success'))
    outcomes = [record for record in host.records() if record.event['outcome'] != 'attempted']
    assert outcomes, 'the outcome was not sealed'
    for record in outcomes:
        assert record.host_key_id == _HOST_KEY_ID
        assert record.host_signature is not None
        payload = witness_payload(record.seq, record.host_ts, record.previous_hash, record.record_hash)
        public_key.verify(base64.b64decode(record.host_signature), payload)  # type: ignore[attr-defined]
        # end for
    # end def


@pytest.mark.asyncio
async def test_a_wrong_key_does_not_verify() -> None:
    """The signature is evidence only against the key a registry binds to the host (§5.2)."""
    host, _signer, _public_key = _signing_host()
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.host_signature is not None
    stranger = generate_tool_key('someone-else').private_key.public_key()
    payload = witness_payload(response.seq, response.host_ts, response.previous_hash, response.record_hash)
    with pytest.raises(InvalidSignature):
        stranger.verify(base64.b64decode(response.host_signature), payload)
        # end with
    # end def


@pytest.mark.asyncio
async def test_the_witness_does_not_move_the_record_hash() -> None:
    """A chain sealed with a witness and the same chain sealed without one agree (§5.2, §8.2)."""
    ids = [f'00000000-0000-4000-8000-00000000000{n}' for n in (1, 2, 3)]
    witnessed, _signer, _public_key = _signing_host()
    plain = AuditHost('tenant-a', _capability(Witness.NONE), clock=_Clock())
    for host in (witnessed, plain):
        for event_id in ids:
            await host.handle_attempt(_event(event_id))
            await host.handle_outcome(_event(event_id, outcome='success'))
            # end for
        # end for
    assert [record.record_hash for record in witnessed.records()] == [record.record_hash for record in plain.records()]
    assert witnessed.digest() == plain.digest()
    assert any(record.host_signature is not None for record in witnessed.records())
    assert all(record.host_signature is None for record in plain.records())
    # end def


def test_an_unwitnessed_record_persists_exactly_as_before() -> None:
    """The fields are omitted when absent, so stored records from before v0.3 are unchanged (§7.1)."""
    record = SealedRecord(
        event=_event('00000000-0000-4000-8000-000000000001'),
        seq=0,
        host_ts='2026-07-15T00:00:02.000Z',
        previous_hash='0' * 64,
        record_hash='a' * 64,
    )
    stored = record.to_dict()
    assert 'host_signature' not in stored
    assert 'host_key_id' not in stored
    assert SealedRecord.from_dict(stored) == record
    # end def


def test_a_witnessed_record_round_trips_through_persistence() -> None:
    """A verifier reading the ledger later needs both fields, so both survive storage (§7.1)."""
    record = SealedRecord(
        event=_event('00000000-0000-4000-8000-000000000001'),
        seq=0,
        host_ts='2026-07-15T00:00:02.000Z',
        previous_hash='0' * 64,
        record_hash='a' * 64,
        host_signature='ZmFrZS13aXRuZXNzLXNpZ25hdHVyZQ==',
        host_key_id=_HOST_KEY_ID,
    )
    assert SealedRecord.from_dict(record.to_dict()) == record
    # end def
