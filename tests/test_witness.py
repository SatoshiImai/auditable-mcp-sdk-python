"""Unit tests for the witness axis (§5.2, §7.1, §7.2): the host side."""

import base64

import pytest
from cryptography.exceptions import InvalidSignature

from auditable_mcp.hashing import compute_record_hash, witness_payload
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    Ed25519WitnessSigner,
    KeyRegistry,
    SignatureAlgorithm,
    WitnessRegistryVerifier,
    generate_tool_key,
)
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import (
    EXTENSION_ID,
    SPEC_VERSION,
    AcceptResponse,
    AuditCapability,
    Level,
    TargetResource,
    UnavailableResponse,
    Witness,
)
from auditable_mcp.session import AmcpAbortedError, AmcpSession
from auditable_mcp.verify import verify_ledger

_HOST_KEY_ID = 'host-key-2026'


class _FixedDeps:
    """Deterministic id/time source for reproducible tool-side events."""

    def __init__(self) -> None:
        """Start the id counter at zero."""
        self._n = 0
        # end def

    def new_id(self) -> str:
        """Return the next deterministic UUID-shaped id."""
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'
        # end def

    def now(self) -> str:
        """Return a fixed valid ISO-8601 timestamp."""
        return '2026-07-15T00:00:01.000Z'
        # end def

    # end class


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


class _CannedEndpoint:
    """A host that answers every attempt with one crafted response, so §7.2's order can be exercised."""

    def __init__(self, response: AcceptResponse) -> None:
        """Configure the canned accept and start an empty outcome log."""
        self._response = response
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """A declaration the in-process transport can negotiate against."""
        return _capability(Witness.HOST)
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AcceptResponse:
        """Return the canned accept."""
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Record the outcome the tool emitted."""
        self.outcomes.append(event)
        # end def

    # end class


def _canned(*, host_signature: str | None = None, host_key_id: str | None = None, record_hash: str = 'a' * 64):
    """An accept whose fields a test controls, including a deliberately wrong record hash."""
    return AcceptResponse(
        seq=0,
        record_hash=record_hash,
        host_ts='2026-07-15T00:00:02.000Z',
        previous_hash='0' * 64,
        host_signature=host_signature,
        host_key_id=host_key_id,
    )
    # end def


async def _run(session: AmcpSession) -> None:
    """Drive one audited action, letting AmcpAbortedError escape."""
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        pass
        # end async with
    # end def


def _registry_for(key_id: str, public_key: object) -> WitnessRegistryVerifier:
    """A witness verifier holding one host key, as an onboarded registry would."""
    registry = KeyRegistry()
    registry.register(key_id, public_key, SignatureAlgorithm.ED25519)  # type: ignore[arg-type]
    return WitnessRegistryVerifier(registry)
    # end def


def test_requiring_a_witness_without_a_verifier_is_refused() -> None:
    """Requiring one without the means to check it would accept any bytes as a signature (§11.3)."""
    endpoint = _CannedEndpoint(_canned())
    with pytest.raises(ValueError, match='WitnessVerifier'):
        AmcpSession(InProcessTransport(endpoint), 'call-1', require_witness=True)
        # end with
    # end def


@pytest.mark.asyncio
async def test_a_required_witness_that_is_absent_aborts_host_unwitnessed() -> None:
    """An accept carrying no signature fails a tool that requires one (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned())
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_witness=True,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert [outcome['reason'] for outcome in endpoint.outcomes] == ['host-unwitnessed']
    # end def


@pytest.mark.asyncio
async def test_a_signature_that_does_not_verify_aborts_host_signature_invalid() -> None:
    """A present signature the tool checked and rejected stops the action (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ==', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert [outcome['reason'] for outcome in endpoint.outcomes] == ['host-signature-invalid']
    # end def


@pytest.mark.asyncio
async def test_a_tool_that_checked_must_act_on_the_result_even_without_requiring_one() -> None:
    """`require_witness` is False here; having verified, the tool still applies the bullet (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ==', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_witness=False,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-signature-invalid'
    # end def


@pytest.mark.asyncio
async def test_an_unknown_host_key_does_not_establish_the_witness() -> None:
    """A host_key_id with no current entry - never registered, or revoked - fails (§10.9)."""
    other = generate_tool_key('another-host')
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ==', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        witness_verifier=_registry_for('another-host', other.private_key.public_key()),
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-signature-invalid'
    # end def


@pytest.mark.asyncio
async def test_an_absent_witness_precedes_a_hash_mismatch() -> None:
    """Both conditions hold; the sealed reason is the first that applies, not the last (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    # The canned record_hash cannot match what the tool computes, so Polluted Stop would fire too.
    endpoint = _CannedEndpoint(_canned())
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        polluted_stop=True,
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_witness=True,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-unwitnessed'
    # end def


@pytest.mark.asyncio
async def test_an_invalid_witness_precedes_a_hash_mismatch() -> None:
    """A response is authenticated before its contents are interpreted (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ==', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        'call-1',
        deps=_FixedDeps(),
        polluted_stop=True,
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_witness=True,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-signature-invalid'
    # end def


@pytest.mark.asyncio
async def test_a_real_signing_host_and_a_requiring_tool_complete_the_action() -> None:
    """End to end: the host signs, the tool verifies against the registry, and the body runs (§7.1)."""
    key = generate_tool_key(_HOST_KEY_ID)
    host = AuditHost(
        'tenant-a',
        _capability(Witness.HOST),
        witness_signer=Ed25519WitnessSigner(key.key_id, key.private_key),
        clock=_Clock(),
    )
    session = AmcpSession(
        InProcessTransport(host),
        'call-1',
        deps=_FixedDeps(),
        polluted_stop=True,
        witness_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_witness=True,
    )
    ran = False
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        ran = True
        # end async with
    assert ran
    assert all(record.host_signature is not None for record in host.records())
    # end def


async def _witnessed_chain(signer: Ed25519WitnessSigner) -> list[SealedRecord]:
    """Three attempt/outcome pairs sealed by a host that signs."""
    host = AuditHost('tenant-a', _capability(Witness.HOST), witness_signer=signer, clock=_Clock())
    for n in (1, 2, 3):
        event_id = f'00000000-0000-4000-8000-00000000000{n}'
        await host.handle_attempt(_event(event_id))
        await host.handle_outcome(_event(event_id, outcome='success'))
        # end for
    return host.records()
    # end def


@pytest.mark.asyncio
async def test_a_verifier_with_the_registry_confirms_every_witness() -> None:
    """With the host key, the chain is both sound and fully checked (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _witnessed_chain(Ed25519WitnessSigner(key.key_id, key.private_key))
    verifier = _registry_for(_HOST_KEY_ID, key.private_key.public_key())
    report = verify_ledger(records, witness_checker=verifier.check)
    assert report.ok
    assert report.unchecked == ()
    assert report.complete
    # end def


@pytest.mark.asyncio
async def test_a_verifier_without_the_registry_says_it_did_not_check() -> None:
    """An unchecked signature and a valid one are not the same finding (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _witnessed_chain(Ed25519WitnessSigner(key.key_id, key.private_key))
    report = verify_ledger(records)
    assert report.ok, 'the chain itself is sound'
    assert report.unchecked == ('witness',)
    assert not report.complete, 'silence must not read as verified'
    # end def


@pytest.mark.asyncio
async def test_a_chain_with_no_witness_is_not_reported_as_unchecked() -> None:
    """Nothing applicable was skipped, so the absence of a registry costs nothing (§5.2, §11.4)."""
    host = AuditHost('tenant-a', _capability(Witness.NONE), clock=_Clock())
    await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    report = verify_ledger(host.records())
    assert report.ok
    assert report.unchecked == ()
    assert report.complete
    # end def


@pytest.mark.asyncio
async def test_a_witness_that_does_not_verify_is_an_anomaly() -> None:
    """A signature present and failing is reported; absence is a state, not a finding (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _witnessed_chain(Ed25519WitnessSigner(key.key_id, key.private_key))
    stranger = generate_tool_key(_HOST_KEY_ID)
    verifier = _registry_for(_HOST_KEY_ID, stranger.private_key.public_key())
    report = verify_ledger(records, witness_checker=verifier.check)
    assert not report.ok
    assert {issue.kind for issue in report.issues} == {'host-signature-invalid'}
    assert len(report.issues) == len(records)
    # end def


def test_the_golden_witnessed_chain_verifies_and_reports_its_unchecked_witness(
    chain_witnessed_vector: dict[str, object],
) -> None:
    """The vector's signature is fixed test data, so a verifier without a registry must say so."""
    records = [SealedRecord.from_dict(record) for record in chain_witnessed_vector['records']]  # type: ignore[union-attr]
    report = verify_ledger(records, chain_witnessed_vector['digest'])  # type: ignore[arg-type]
    assert report.ok
    assert report.unchecked == ('witness',)
    # end def


class _FailingSigner:
    """A signer whose backend is down, as an HSM or KMS client would be."""

    key_id = _HOST_KEY_ID

    async def sign(self, payload: bytes) -> str:
        """Fail the way an injected third-party client fails: with its own error type."""
        raise RuntimeError('KMS unreachable')
        # end def

    # end class


def test_the_extension_identifier_is_part_of_the_sdk() -> None:
    """[SEP-2133] keys the capability by this identifier; an integrator should not retype it (§6.1)."""
    assert EXTENSION_ID == 'com.timberlandchapel/auditable-mcp'
    # end def


def test_a_host_declaring_none_must_not_hold_a_signer() -> None:
    """§7.1: such a host MUST NOT return the fields, and holding a signer is the only way to."""
    with pytest.raises(ValueError, match='must not hold'):
        AuditHost('tenant-a', _capability(Witness.NONE), witness_signer=_FailingSigner())
        # end with
    # end def


@pytest.mark.asyncio
async def test_a_signer_failure_fails_closed_as_unavailable() -> None:
    """A host that declared it signs cannot record without the signature (§7.1, §7.6)."""
    host = AuditHost('tenant-a', _capability(Witness.HOST), witness_signer=_FailingSigner(), clock=_Clock())
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, UnavailableResponse)
    assert response.reason == 'internal-error'
    assert response.retryable is True
    assert host.records() == [], 'nothing may be committed when the record cannot be signed'
    # end def


@pytest.mark.asyncio
async def test_an_unverified_level_2_signature_is_named_unchecked() -> None:
    """§11.4 names both registries: an unchecked event signature is not a verified one."""
    host = AuditHost('tenant-a', _capability(Witness.NONE), clock=_Clock())
    signed = {
        **_event('00000000-0000-4000-8000-000000000001'),
        'key_id': 'k1',
        'signer_seq': 1,
        'signature': 'ZmFrZQ==',
    }
    await host.handle_attempt(signed)
    report = verify_ledger(host.records())
    assert report.ok
    assert report.unchecked == ('level-2-signature',)
    assert not report.complete
    # end def


def test_a_stored_half_pair_is_reported_not_ignored() -> None:
    """A stored record is not schema-checked, so the verifier is the last place to catch it (§7.1)."""
    event = _event('00000000-0000-4000-8000-000000000001')
    record_hash = compute_record_hash(event, 0, '2026-07-15T00:00:02.000Z', '0' * 64)
    for witness in ({'host_signature': 'ZmFrZQ=='}, {'host_key_id': _HOST_KEY_ID}):
        record = SealedRecord(
            event=event,
            seq=0,
            host_ts='2026-07-15T00:00:02.000Z',
            previous_hash='0' * 64,
            record_hash=record_hash,
            **witness,  # type: ignore[arg-type]
        )
        report = verify_ledger([record])
        assert not report.ok, witness
        assert [issue.kind for issue in report.issues] == ['host-signature-invalid'], witness
        # end for
    # end def
