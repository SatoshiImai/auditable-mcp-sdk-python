"""Unit tests for the countersignature axis (§5.2, §7.1, §7.2): the host side."""

from collections.abc import Callable, Mapping
from typing import Any, cast

import pytest
from cryptography.exceptions import InvalidSignature

from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.hashing import compute_record_hash, countersignature_payload
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    CountersignatureRegistryVerifier,
    Ed25519Countersigner,
    KeyRegistry,
    KeyRegistryVerifier,
    KeyRole,
    SignatureAlgorithm,
    generate_tool_key,
)
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import (
    EXTENSION_ID,
    SPEC_VERSION,
    AcceptResponse,
    AuditCapability,
    Countersign,
    Level,
    TargetResource,
    UnavailableResponse,
)
from auditable_mcp.session import AmcpAbortedError, AmcpSession
from auditable_mcp.verify import RecordAdapter, verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
LOG_ID = 'tenant-a'

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
        'session_id': SESSION,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
    }
    # end def


def _capability(countersign: Countersign) -> AuditCapability:
    """A host capability declaring a position on the countersignature axis."""
    return AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=countersign)
    # end def


def _signing_host() -> tuple[AuditHost, Ed25519Countersigner, object]:
    """A host that declares it signs, with the key a verifier's registry would hold."""
    key = generate_tool_key(_HOST_KEY_ID)
    signer = Ed25519Countersigner(key.key_id, key.private_key)
    host = AuditHost('tenant-a', _capability(Countersign.HOST), countersigner=signer, clock=_Clock())
    host.open_session(SESSION)
    return host, signer, key.private_key.public_key()
    # end def


def test_a_host_declaring_it_signs_must_be_given_a_signer() -> None:
    """Declaring the axis and not providing the means would leave every record uncountersigned (§11.2)."""
    with pytest.raises(ValueError, match='Countersigner'):
        AuditHost('tenant-a', _capability(Countersign.HOST))
        # end with
    # end def


@pytest.mark.asyncio
async def test_an_accept_from_a_signing_host_carries_a_verifiable_countersign() -> None:
    """The signature covers the host-assigned fields the accept returns (§7.1)."""
    host, _signer, public_key = _signing_host()
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.host_key_id == _HOST_KEY_ID
    assert response.host_signature is not None
    payload = countersignature_payload(
        response.seq, response.host_ts, LOG_ID, response.previous_hash, response.record_hash
    )
    public_key.verify(b64url_decode(response.host_signature), payload)  # type: ignore[attr-defined]
    # end def


@pytest.mark.asyncio
async def test_a_non_signing_host_returns_no_countersign_fields() -> None:
    """A host that declares `none` returns neither field; the pair is all-or-nothing (§7.1)."""
    host = AuditHost('tenant-a', _capability(Countersign.NONE))
    host.open_session(SESSION)
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.host_signature is None
    assert response.host_key_id is None
    assert response.log_id is None
    # end def


@pytest.mark.asyncio
async def test_sealed_outcome_records_are_countersigned_too() -> None:
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
        payload = countersignature_payload(record.seq, record.host_ts, LOG_ID, record.previous_hash, record.record_hash)
        public_key.verify(b64url_decode(record.host_signature), payload)  # type: ignore[attr-defined]
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
    payload = countersignature_payload(
        response.seq, response.host_ts, LOG_ID, response.previous_hash, response.record_hash
    )
    with pytest.raises(InvalidSignature):
        stranger.verify(b64url_decode(response.host_signature), payload)
        # end with
    # end def


@pytest.mark.asyncio
async def test_the_countersign_does_not_move_the_record_hash() -> None:
    """A chain sealed with a countersign and the same chain sealed without one agree (§5.2, §8.2)."""
    ids = [f'00000000-0000-4000-8000-00000000000{n}' for n in (1, 2, 3)]
    countersigned, _signer, _public_key = _signing_host()
    plain = AuditHost('tenant-a', _capability(Countersign.NONE), clock=_Clock())
    plain.open_session(SESSION)
    for host in (countersigned, plain):
        for event_id in ids:
            await host.handle_attempt(_event(event_id))
            await host.handle_outcome(_event(event_id, outcome='success'))
            # end for
        # end for
    assert [record.record_hash for record in countersigned.records()] == [
        record.record_hash for record in plain.records()
    ]
    assert countersigned.digest() == plain.digest()
    assert any(record.host_signature is not None for record in countersigned.records())
    assert all(record.host_signature is None for record in plain.records())
    # end def


def test_an_uncountersigned_record_persists_exactly_as_before() -> None:
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
    assert 'log_id' not in stored
    assert SealedRecord.from_dict(stored) == record
    # end def


def test_a_countersigned_record_round_trips_through_persistence() -> None:
    """A verifier reading the ledger later needs both fields, so both survive storage (§7.1)."""
    record = SealedRecord(
        event=_event('00000000-0000-4000-8000-000000000001'),
        seq=0,
        host_ts='2026-07-15T00:00:02.000Z',
        previous_hash='0' * 64,
        record_hash='a' * 64,
        host_signature='ZmFrZS1jb3VudGVyc2lnbmF0dXJl',
        host_key_id=_HOST_KEY_ID,
        log_id=LOG_ID,
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
        return _capability(Countersign.HOST)
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """The one session this endpoint serves."""
        return SESSION
        # end def

    async def close_session(self, session_id: str) -> None:
        """Nothing to close."""
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> AcceptResponse:
        """Return the canned accept."""
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
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
        log_id=None if host_signature is None else LOG_ID,
    )
    # end def


async def _run(session: AmcpSession) -> None:
    """Drive one audited action, letting AmcpAbortedError escape."""
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        pass
        # end async with
    # end def


def _registry_for(key_id: str, public_key: object) -> CountersignatureRegistryVerifier:
    """A countersign verifier holding one host key, as an onboarded registry would."""
    registry = KeyRegistry(KeyRole.HOST)
    registry.register(key_id, public_key, SignatureAlgorithm.ED25519)  # type: ignore[arg-type]
    return CountersignatureRegistryVerifier(registry)
    # end def


def test_requiring_a_countersign_without_a_verifier_is_refused() -> None:
    """Requiring one without the means to check it would accept any bytes as a signature (§11.3)."""
    endpoint = _CannedEndpoint(_canned())
    with pytest.raises(ValueError, match='CountersignatureVerifier'):
        AmcpSession(InProcessTransport(endpoint), endpoint.open_session(), require_countersign=True)
        # end with
    # end def


@pytest.mark.asyncio
async def test_a_required_countersign_that_is_absent_aborts_host_uncountersigned() -> None:
    """An accept carrying no signature fails a tool that requires one (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned())
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_countersign=True,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert [outcome['reason'] for outcome in endpoint.outcomes] == ['host-uncountersigned']
    # end def


@pytest.mark.asyncio
async def test_a_signature_that_does_not_verify_aborts_host_signature_invalid() -> None:
    """A present signature the tool checked and rejected stops the action (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert [outcome['reason'] for outcome in endpoint.outcomes] == ['host-signature-invalid']
    # end def


@pytest.mark.asyncio
async def test_a_tool_that_checked_must_act_on_the_result_even_without_requiring_one() -> None:
    """`require_countersign` is False here; having verified, the tool still applies the bullet (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_countersign=False,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-signature-invalid'
    # end def


@pytest.mark.asyncio
async def test_an_unknown_host_key_does_not_establish_the_countersign() -> None:
    """A host_key_id with no current entry - never registered, or revoked - fails (§10.9)."""
    other = generate_tool_key('another-host')
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        countersignature_verifier=_registry_for('another-host', other.private_key.public_key()),
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-signature-invalid'
    # end def


@pytest.mark.asyncio
async def test_an_absent_countersign_precedes_a_hash_mismatch() -> None:
    """Both conditions hold; the sealed reason is the first that applies, not the last (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    # The canned record_hash cannot match what the tool computes, so Polluted Stop would fire too.
    endpoint = _CannedEndpoint(_canned())
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        polluted_stop=True,
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_countersign=True,
    )
    with pytest.raises(AmcpAbortedError):
        await _run(session)
        # end with
    assert endpoint.outcomes[0]['reason'] == 'host-uncountersigned'
    # end def


@pytest.mark.asyncio
async def test_an_invalid_countersign_precedes_a_hash_mismatch() -> None:
    """A response is authenticated before its contents are interpreted (§7.2)."""
    key = generate_tool_key(_HOST_KEY_ID)
    endpoint = _CannedEndpoint(_canned(host_signature='ZmFrZQ', host_key_id=_HOST_KEY_ID))
    session = AmcpSession(
        InProcessTransport(endpoint),
        endpoint.open_session(),
        deps=_FixedDeps(),
        polluted_stop=True,
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_countersign=True,
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
        _capability(Countersign.HOST),
        countersigner=Ed25519Countersigner(key.key_id, key.private_key),
        clock=_Clock(),
    )
    session = AmcpSession(
        InProcessTransport(host),
        host.open_session(),
        deps=_FixedDeps(),
        polluted_stop=True,
        countersignature_verifier=_registry_for(_HOST_KEY_ID, key.private_key.public_key()),
        require_countersign=True,
    )
    ran = False
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        ran = True
        # end async with
    assert ran
    assert all(record.host_signature is not None for record in host.records())
    # end def


async def _countersigned_chain(signer: Ed25519Countersigner) -> list[SealedRecord]:
    """Three attempt/outcome pairs sealed by a host that signs."""
    host = AuditHost('tenant-a', _capability(Countersign.HOST), countersigner=signer, clock=_Clock())
    host.open_session(SESSION)
    for n in (1, 2, 3):
        event_id = f'00000000-0000-4000-8000-00000000000{n}'
        await host.handle_attempt(_event(event_id))
        await host.handle_outcome(_event(event_id, outcome='success'))
        # end for
    return host.records()
    # end def


@pytest.mark.asyncio
async def test_a_verifier_with_the_registry_confirms_every_countersign() -> None:
    """With the host key, the chain is both sound and fully checked (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _countersigned_chain(Ed25519Countersigner(key.key_id, key.private_key))
    verifier = _registry_for(_HOST_KEY_ID, key.private_key.public_key())
    report = verify_ledger(records, countersignature_checker=verifier.check)
    assert report.ok
    assert report.unchecked == ()
    assert report.complete
    # end def


@pytest.mark.asyncio
async def test_a_verifier_without_the_registry_says_it_did_not_check() -> None:
    """An unchecked signature and a valid one are not the same finding (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _countersigned_chain(Ed25519Countersigner(key.key_id, key.private_key))
    report = verify_ledger(records)
    assert report.ok, 'the chain itself is sound'
    assert report.unchecked == ('countersignature',)
    assert not report.complete, 'silence must not read as verified'
    # end def


@pytest.mark.asyncio
async def test_a_chain_with_no_countersign_is_not_reported_as_unchecked() -> None:
    """Nothing applicable was skipped, so the absence of a registry costs nothing (§5.2, §11.4)."""
    host = AuditHost('tenant-a', _capability(Countersign.NONE), clock=_Clock())
    host.open_session(SESSION)
    await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    report = verify_ledger(host.records())
    assert report.ok
    assert report.unchecked == ()
    assert report.complete
    # end def


@pytest.mark.asyncio
async def test_a_countersign_that_does_not_verify_is_an_anomaly() -> None:
    """A signature present and failing is reported; absence is a state, not a finding (§11.4)."""
    key = generate_tool_key(_HOST_KEY_ID)
    records = await _countersigned_chain(Ed25519Countersigner(key.key_id, key.private_key))
    stranger = generate_tool_key(_HOST_KEY_ID)
    verifier = _registry_for(_HOST_KEY_ID, stranger.private_key.public_key())
    report = verify_ledger(records, countersignature_checker=verifier.check)
    assert not report.ok
    assert {issue.kind for issue in report.issues} == {'host-signature-invalid'}
    assert len(report.issues) == len(records)
    # end def


def test_the_golden_countersigned_chain_verifies_and_reports_its_unchecked_countersign(
    chain_countersigned_vector: dict[str, object],
) -> None:
    """A verifier without the host registry must say the countersignatures went unchecked (§11.4)."""
    records = [SealedRecord.from_dict(record) for record in chain_countersigned_vector['records']]  # type: ignore[union-attr]
    report = verify_ledger(records, chain_countersigned_vector['digest'])  # type: ignore[arg-type]
    assert report.ok
    assert report.unchecked == ('countersignature',)
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
        AuditHost('tenant-a', _capability(Countersign.NONE), countersigner=_FailingSigner())
        # end with
    # end def


@pytest.mark.asyncio
async def test_a_signer_failure_fails_closed_as_unavailable() -> None:
    """A host that declared it signs cannot record without the signature (§7.1, §7.6)."""
    host = AuditHost('tenant-a', _capability(Countersign.HOST), countersigner=_FailingSigner(), clock=_Clock())
    host.open_session(SESSION)
    response = await host.handle_attempt(_event('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, UnavailableResponse)
    assert response.reason == 'internal-error'
    assert host.records() == [], 'nothing may be committed when the record cannot be signed'
    # end def


@pytest.mark.asyncio
async def test_an_unverified_level_2_signature_is_named_unchecked() -> None:
    """§11.4 names both registries: an unchecked event signature is not a verified one."""
    host = AuditHost('tenant-a', _capability(Countersign.NONE), clock=_Clock())
    host.open_session(SESSION)
    signed = {
        **_event('00000000-0000-4000-8000-000000000001'),
        'key_id': 'k1',
        'signer_seq': 0,
        'signature': 'ZmFrZQ',
    }
    await host.handle_attempt(signed)
    report = verify_ledger(host.records())
    assert report.ok
    assert report.unchecked == ('level-2-signature',)
    assert not report.complete
    # end def


def test_a_stored_partial_triple_is_reported_not_ignored() -> None:
    """A stored record is not schema-checked, so the verifier is the last place to catch it (§7.1)."""
    event = _event('00000000-0000-4000-8000-000000000001')
    record_hash = compute_record_hash(event, 0, '2026-07-15T00:00:02.000Z', '0' * 64)
    partial = (
        {'host_signature': 'ZmFrZQ'},
        {'host_key_id': _HOST_KEY_ID},
        {'log_id': LOG_ID},
        {'host_signature': 'ZmFrZQ', 'host_key_id': _HOST_KEY_ID},
    )
    for countersign in partial:
        record = SealedRecord(
            event=event,
            seq=0,
            host_ts='2026-07-15T00:00:02.000Z',
            previous_hash='0' * 64,
            record_hash=record_hash,
            **countersign,  # type: ignore[arg-type]
        )
        report = verify_ledger([record])
        assert not report.ok, countersign
        assert [issue.kind for issue in report.issues] == ['host-signature-invalid'], countersign
        # end for
    # end def


def test_the_identifier_is_reachable_from_the_package() -> None:
    """An integrator imports the package, not the module; an unexported constant is not shipped."""
    import auditable_mcp

    assert auditable_mcp.EXTENSION_ID == EXTENSION_ID
    assert 'EXTENSION_ID' in auditable_mcp.__all__
    # end def


def _enveloped(record_event: dict[str, object]) -> tuple[SealedRecord, RecordAdapter]:
    """A record sealed inside an envelope, with the adapter that reaches into it (§10.10)."""
    envelope: dict[str, object] = {'principal_id': 'tenant-a', 'extensions': {'auditable-mcp': record_event}}
    record_hash = compute_record_hash(envelope, 0, '2026-07-15T00:00:02.000Z', '0' * 64)
    record = SealedRecord(
        event=envelope, seq=0, host_ts='2026-07-15T00:00:02.000Z', previous_hash='0' * 64, record_hash=record_hash
    )
    inner = cast('Callable[[Mapping[str, object]], Any]', lambda e: e['extensions']['auditable-mcp'])  # type: ignore[index]
    adapter = RecordAdapter(
        id_of=lambda e: inner(e)['id'],
        is_attempt=lambda e: inner(e)['outcome'] == 'attempted',
        event_of=inner,
        principal_of=lambda e: e.get('principal_id'),
    )
    return record, adapter
    # end def


def test_an_enveloped_level_2_signature_is_also_named_unchecked() -> None:
    """The signature lives inside the envelope, which is the deployment §10.10 recommends (§11.4)."""
    signed = {
        **_event('00000000-0000-4000-8000-000000000001'),
        'key_id': 'k1',
        'signer_seq': 0,
        'signature': 'ZmFrZQ',
    }
    record, adapter = _enveloped(signed)
    report = verify_ledger([record], adapter=adapter, expected_principal='tenant-a')
    assert report.ok
    assert report.unchecked == ('level-2-signature',)
    assert not report.complete
    # end def


def test_a_schema_issue_does_not_erase_what_was_left_unchecked() -> None:
    """§11.4's report survives the schema branch; a rebuilt report that drops it says less (§7.1)."""
    bad_event: dict[str, object] = {'not': 'an audit event'}
    record = SealedRecord(
        event=bad_event,
        seq=0,
        host_ts='2026-07-15T00:00:02.000Z',
        previous_hash='0' * 64,
        record_hash=compute_record_hash(bad_event, 0, '2026-07-15T00:00:02.000Z', '0' * 64),
        host_signature='ZmFrZQ',
        host_key_id=_HOST_KEY_ID,
        log_id=LOG_ID,
    )
    report = verify_ledger([record])
    assert not report.ok
    assert 'schema-invalid' in {issue.kind for issue in report.issues}
    assert report.unchecked == ('countersignature',)
    # end def


def test_the_whole_countersign_axis_is_on_the_public_surface() -> None:
    """Every analogous name for the level axis is exported; an integrator implements these seams.

    `Countersign` is the sharpest case: the capability REQUIRES the field, so a user who cannot import the
    enum has to write the string. The rest mirror names the package already exports for Level 2 -
    `Ed25519Signer`, `KeyRegistryVerifier`, `compute_record_hash`, `EventSigner`, `SignatureVerifier`.
    """
    import auditable_mcp

    expected = {
        'EXTENSION_ID',
        'Ed25519Countersigner',
        'Posture',
        'UnnegotiatedCallError',
        'Countersign',
        'CountersignatureChecker',
        'CountersignatureRegistryVerifier',
        'Countersigner',
        'CountersignatureVerifier',
        'transport_for',
        'verify_detached_signature',
        'countersignature_payload',
        'countersign_satisfies',
    }
    assert expected <= set(auditable_mcp.__all__), sorted(expected - set(auditable_mcp.__all__))
    for name in expected:
        assert hasattr(auditable_mcp, name), name
        # end for
    # end def


def test_a_level_2_tool_cannot_switch_polluted_stop_off() -> None:
    """§11.3 makes it REQUIRED under Level 2; a signer is this SDK's Level-2 marker (§7.2)."""

    class _Signer:
        async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
            return event
            # end def

        # end class

    endpoint = _CannedEndpoint(_canned())
    with pytest.raises(ValueError, match='Polluted Stop'):
        AmcpSession(InProcessTransport(endpoint), endpoint.open_session(), signer=_Signer(), polluted_stop=False)
        # end with
    # end def


def _l2_record(seq: int, signer_seq: int, previous: str, *, key_id: str = 'k1') -> SealedRecord:
    """A sealed record carrying Level-2 fields, chained onto `previous`."""
    event = {
        **_event(f'00000000-0000-4000-8000-00000000000{seq + 1}'),
        'key_id': key_id,
        'signer_seq': signer_seq,
        'signature': 'ZmFrZQ',
    }
    host_ts = f'2026-07-15T00:00:{seq + 2:02d}.000Z'
    return SealedRecord(
        event=event,
        seq=seq,
        host_ts=host_ts,
        previous_hash=previous,
        record_hash=compute_record_hash(event, seq, host_ts, previous),
    )
    # end def


def test_a_forward_signer_seq_gap_is_reported() -> None:
    """§7.4, §11.4: the one suppression signal a ledger carries, computable with no registry."""
    first = _l2_record(0, 0, '0' * 64)
    second = _l2_record(1, 5, first.record_hash)
    report = verify_ledger([first, second])
    gaps = [issue.detail for issue in report.issues if issue.kind == 'signer-seq-gap']
    assert len(gaps) == 1, 'values 1 to 4 are one run missing from the session'
    assert 'signer_seq 1..4' in gaps[0]
    # end def


def test_a_session_that_does_not_start_at_zero_is_a_gap() -> None:
    """§7.4: every session numbers from 0, so a missing first event is visible too (§11.4)."""
    report = verify_ledger([_l2_record(0, 1, '0' * 64)])
    assert [issue.kind for issue in report.issues] == ['signer-seq-gap']
    # end def


def test_contiguous_signer_seqs_are_not_a_gap() -> None:
    """Attempts and their outcomes both consume a signer_seq, so N and N+1 are contiguous (§7.4)."""
    first = _l2_record(0, 0, '0' * 64)
    second = _l2_record(1, 1, first.record_hash)
    report = verify_ledger([first, second])
    assert 'signer-seq-gap' not in {issue.kind for issue in report.issues}
    # end def


def test_a_supplied_signature_checker_reports_an_invalid_one() -> None:
    """A verifier holding the registry can perform §11.4's Level-2 Validation, not only skip it."""
    record = _l2_record(0, 0, '0' * 64)
    report = verify_ledger([record], signature_checker=lambda _event: False)
    assert not report.ok
    assert 'signature-invalid' in {issue.kind for issue in report.issues}
    assert report.unchecked == (), 'it was checked, so nothing is unchecked'
    # end def


def test_without_a_signature_checker_the_level_2_records_are_unchecked() -> None:
    """The alternative to verifying is saying so, never reporting a clean result (§11.4)."""
    report = verify_ledger([_l2_record(0, 0, '0' * 64)])
    assert report.ok
    assert report.unchecked == ('level-2-signature',)
    # end def


def test_one_registry_cannot_serve_both_roles() -> None:
    """§10.9: the two registries share no entry, and one registry holding one role is how that holds."""
    tool_keys = KeyRegistry(KeyRole.TOOL)
    host_keys = KeyRegistry(KeyRole.HOST)
    with pytest.raises(ValueError, match='host-key registry'):
        CountersignatureRegistryVerifier(tool_keys)
        # end with
    with pytest.raises(ValueError, match='tool-key registry'):
        KeyRegistryVerifier(host_keys)
        # end with
    # end def


def test_a_tool_cannot_sign_itself_into_the_host_countersigned_state() -> None:
    """§5.2 rests on the tool holding no key the verifier's registry binds to a host."""
    tool_key = generate_tool_key('tool-k1')
    shared = KeyRegistry(KeyRole.TOOL)
    shared.register_tool_key(tool_key)
    # The misuse the guard forbids: handing the tool-key registry to the countersignature verifier, which would
    # resolve `host_key_id: "tool-k1"` and accept a signature the tool made with its own key.
    with pytest.raises(ValueError):
        CountersignatureRegistryVerifier(shared)
        # end with
    # A host-key registry that the tool's key was never put into refuses it, as §5.2 requires.
    host_keys = KeyRegistry(KeyRole.HOST)
    verifier = CountersignatureRegistryVerifier(host_keys)
    payload = countersignature_payload(0, '2026-07-15T00:00:02.000Z', LOG_ID, '0' * 64, 'a' * 64)
    forged = b64url_encode(tool_key.private_key.sign(payload))
    assert not verifier.check('tool-k1', forged, payload)
    # end def
