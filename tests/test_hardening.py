"""Regression tests for the host, session, registry, model, and verifier findings of the v0.3 review."""

import base64

import anyio
import pytest

from auditable_mcp.hashing import compute_record_hash, countersignature_payload
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    CountersignatureRegistryVerifier,
    Ed25519Countersigner,
    Ed25519Signer,
    KeyRegistry,
    KeyRegistryVerifier,
    KeyRole,
    SignatureAlgorithm,
    assert_registries_disjoint,
    generate_tool_key,
    public_jwk,
    public_key_of,
    sign_event,
    signature_payload,
)
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import (
    SPEC_VERSION,
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    Countersign,
    Level,
    RejectResponse,
    TargetResource,
    UnavailableResponse,
)
from auditable_mcp.session import AmcpAbortedError, AmcpSession, SessionNumbering
from auditable_mcp.storage import RepositoryError
from auditable_mcp.verify import ExpectedIdentity, unaccounted_signer_seq, verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
OTHER_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc1'
LOG_ID = 'tenant-a'
TS = '2026-07-15T00:00:01.000Z'


class _Clock:
    """A monotonic host clock producing valid timestamps."""

    def __init__(self) -> None:
        """Start at zero."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-07-15T00:00:{self._n:02d}.000Z'
        # end def

    # end class


class _FixedDeps:
    """Deterministic id/time source producing valid UUIDs."""

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
        """Return a fixed valid timestamp."""
        return TS
        # end def

    # end class


def _event(event_id: int, outcome: str = 'attempted', session_id: str = SESSION, **extra: object) -> dict[str, object]:
    """A valid Level-1 event."""
    event: dict[str, object] = {
        'id': f'00000000-0000-4000-8000-{event_id:012x}',
        'spec_version': SPEC_VERSION,
        'ts': TS,
        'session_id': session_id,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
    }
    event.update(extra)
    return event
    # end def


def _l1(countersign: Countersign = Countersign.NONE) -> AuditCapability:
    """A Level-1 capability."""
    return AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=countersign)
    # end def


def _l2() -> AuditCapability:
    """A Level-2 capability."""
    return AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE)
    # end def


class _L2:
    """A Level-2 host with one registered tool key, and a way to sign events under it."""

    def __init__(self) -> None:
        """Register the key and open the session."""
        self.key = generate_tool_key('tool-key')
        self.registry = KeyRegistry()
        self.registry.register_tool_key(self.key)
        self.host = AuditHost('tenant-a', _l2(), verifier=KeyRegistryVerifier(self.registry), clock=_Clock())
        self.host.open_session(SESSION)
        # end def

    def signed(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Sign `event` at `signer_seq`."""
        return sign_event(event, self.key.key_id, signer_seq, self.key.private_key)
        # end def

    def kinds(self) -> list[str]:
        """The anomaly kinds the host recorded."""
        return [anomaly.kind for anomaly in self.host.anomalies()]
        # end def

    # end class


class _CannedEndpoint:
    """A host that answers every attempt with one crafted response."""

    def __init__(self, response: AttemptResponse) -> None:
        """Hold the canned response."""
        self._response = response
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """What the in-process transport negotiates against."""
        return _l1(Countersign.HOST)
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
    ) -> AttemptResponse:
        """Return the canned response."""
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Record the outcome."""
        self.outcomes.append(event)
        # end def

    # end class


async def _act(session: AmcpSession) -> None:
    """Drive one audited action, letting AmcpAbortedError escape."""
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        pass
        # end async with
    # end def


def _host_registry() -> tuple[KeyRegistry, Ed25519Countersigner]:
    """A host-key registry and the countersigner whose key it holds."""
    key = generate_tool_key('host-key')
    registry = KeyRegistry(KeyRole.HOST)
    registry.register(key.key_id, key.public_key, SignatureAlgorithm.ED25519)
    return registry, Ed25519Countersigner(key.key_id, key.private_key)
    # end def


class TestACountersignatureRequiresPollutedStop:
    """§7.2: the countersignature binds only `record_hash`; Polluted Stop binds it to the tool's event."""

    async def test_a_genuine_countersigned_accept_for_another_record_is_refused_at_level_1(self) -> None:
        """A replayed accept verifies as a countersignature, and the recomputed hash is what refuses it."""
        registry, countersigner = _host_registry()
        fields = ('2026-07-15T00:00:02.000Z', '0' * 64, 'b' * 64)
        signature = await countersigner.sign(countersignature_payload(0, fields[0], LOG_ID, fields[1], fields[2]))
        replayed = AcceptResponse(
            seq=0,
            host_ts=fields[0],
            previous_hash=fields[1],
            record_hash=fields[2],
            host_signature=signature,
            host_key_id=countersigner.key_id,
            log_id=LOG_ID,
        )
        endpoint = _CannedEndpoint(replayed)
        session = AmcpSession(
            InProcessTransport(endpoint),
            SESSION,
            deps=_FixedDeps(),
            countersignature_verifier=CountersignatureRegistryVerifier(registry),
            require_countersign=True,
        )
        with pytest.raises(AmcpAbortedError) as raised:
            await _act(session)
            # end with
        assert raised.value.reason == 'hash-mismatch'
        # end def

    def test_polluted_stop_cannot_be_switched_off_when_a_countersignature_is_required(self) -> None:
        """Switching it off would leave the requirement unenforceable (§11.3)."""
        registry, _countersigner = _host_registry()
        with pytest.raises(ValueError, match='Polluted Stop'):
            AmcpSession(
                InProcessTransport(_CannedEndpoint(UnavailableResponse())),
                SESSION,
                countersignature_verifier=CountersignatureRegistryVerifier(registry),
                require_countersign=True,
                polluted_stop=False,
            )
            # end with
        # end def

    # end class


class TestTheReplayWindowIsTheDecidedSet:
    """§7.4: a replay is a value already decided, not a value below the highest decided."""

    async def test_an_attempt_sent_again_after_unavailable_is_accepted_after_a_later_one(self) -> None:
        """Seq 1 answered unavailable, seq 2 accepted, then seq 1 again: not a replay (§7.1)."""
        l2 = _L2()
        first = await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        assert isinstance(first, AcceptResponse)
        retried = l2.signed(_event(2), 1)
        l2.host.persistence_available = False
        assert isinstance(await l2.host.handle_attempt(retried, session_id=SESSION), UnavailableResponse)
        l2.host.persistence_available = True
        assert isinstance(await l2.host.handle_attempt(l2.signed(_event(3), 2), session_id=SESSION), AcceptResponse)
        assert isinstance(await l2.host.handle_attempt(retried, session_id=SESSION), AcceptResponse)
        assert 'replay-detected' not in l2.kinds()
        # end def

    async def test_an_outcome_lost_to_a_persistence_failure_is_not_decided(self) -> None:
        """Failing to record an outcome is not a decision, as `unavailable` is not one for an attempt."""
        l2 = _L2()
        await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        outcome = l2.signed(_event(1, 'success'), 1)
        l2.host.persistence_available = False
        await l2.host.handle_outcome(outcome, session_id=SESSION)
        l2.host.persistence_available = True
        await l2.host.handle_outcome(dict(outcome), session_id=SESSION)
        assert [record.event['outcome'] for record in l2.host.records()] == ['attempted', 'success']
        assert l2.kinds() == []
        # end def

    async def test_a_decided_value_is_a_replay(self) -> None:
        """Another event under a `signer_seq` the host already decided is refused `replay-detected`."""
        l2 = _L2()
        await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        answer = await l2.host.handle_attempt(l2.signed(_event(2), 0), session_id=SESSION)
        assert isinstance(answer, RejectResponse)
        assert answer.reason == 'replay-detected'
        # end def

    async def test_an_attempt_of_a_concluded_operation_is_a_replay(self) -> None:
        """§7.1 step 4: attempt 0 unavailable, its refusal sealed at 1, then attempt 0 again is refused."""
        l2 = _L2()
        attempt = l2.signed(_event(1), 0)
        l2.host.persistence_available = False
        assert isinstance(await l2.host.handle_attempt(attempt, session_id=SESSION), UnavailableResponse)
        l2.host.persistence_available = True
        refusal = l2.signed(_event(1, 'aborted', reason='host-unavailable'), 1)
        await l2.host.handle_outcome(refusal, session_id=SESSION)
        answer = await l2.host.handle_attempt(dict(attempt), session_id=SESSION)
        assert isinstance(answer, RejectResponse)
        assert answer.reason == 'replay-detected'
        assert [record.event['outcome'] for record in l2.host.records()] == ['aborted']
        assert l2.kinds() == ['replay-detected']
        # end def

    async def test_a_sealed_attempt_repeated_after_its_outcome_is_answered_from_the_ledger(self) -> None:
        """§7.1 step 4: the byte-identical repeat is checked before the concluded operation."""
        l2 = _L2()
        attempt = l2.signed(_event(1), 0)
        first = await l2.host.handle_attempt(attempt, session_id=SESSION)
        await l2.host.handle_outcome(l2.signed(_event(1, 'success'), 1), session_id=SESSION)
        assert await l2.host.handle_attempt(dict(attempt), session_id=SESSION) == first
        assert l2.kinds() == []
        # end def

    # end class


class TestOutcomeValidationOrder:
    """§7.2, §6: an outcome is validated as an attempt is, then correlated; each drop names its kind."""

    async def test_an_unsigned_outcome_is_a_signature_failure_before_it_is_an_orphan(self) -> None:
        """Signature comes before correlation, and a missing signature is `signature-invalid` (§6)."""
        l2 = _L2()
        await l2.host.handle_outcome(_event(9, 'success'), session_id=SESSION)
        assert l2.kinds() == ['signature-invalid']
        assert l2.host.records() == []
        # end def

    async def test_an_outcome_under_an_unknown_key_is_a_signature_failure(self) -> None:
        """An unknown key is not a Tier-1 anomaly kind; §6 files it under `signature-invalid`."""
        l2 = _L2()
        stranger = generate_tool_key('stranger')
        event = sign_event(_event(9, 'success'), stranger.key_id, 0, stranger.private_key)
        await l2.host.handle_outcome(event, session_id=SESSION)
        assert l2.kinds() == ['signature-invalid']
        # end def

    async def test_a_refused_attempt_is_recorded_under_the_anomaly_kind_not_the_reject_reason(self) -> None:
        """§7.6: `l2-unsigned` and `unknown-key` answer the tool; the anomaly set files both as `signature-invalid`."""
        l2 = _L2()
        stranger = generate_tool_key('stranger')
        unknown = await l2.host.handle_attempt(
            sign_event(_event(1), stranger.key_id, 0, stranger.private_key), session_id=SESSION
        )
        unsigned = await l2.host.handle_attempt(_event(2), session_id=SESSION)
        assert [unknown.to_wire()['reason'], unsigned.to_wire()['reason']] == ['unknown-key', 'l2-unsigned']
        assert l2.kinds() == ['signature-invalid', 'signature-invalid']
        # end def

    async def test_a_signed_outcome_with_no_attempt_is_an_orphan(self) -> None:
        """Correlation runs only after the signature verified."""
        l2 = _L2()
        await l2.host.handle_outcome(l2.signed(_event(9, 'success'), 0), session_id=SESSION)
        assert l2.kinds() == ['orphaned-outcome']
        # end def

    async def test_an_outcome_of_another_session_is_a_replay(self) -> None:
        """The session is checked before anything else about the event (§6.3)."""
        l2 = _L2()
        l2.host.open_session(OTHER_SESSION)
        await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        await l2.host.handle_outcome(l2.signed(_event(1, 'success'), 1), session_id=OTHER_SESSION)
        assert l2.kinds() == ['replay-detected']
        assert len(l2.host.records()) == 1
        # end def

    async def test_a_second_different_outcome_for_one_operation_is_a_replay(self) -> None:
        """One terminal record per (`session_id`, `id`); a repeat of the same bytes is not an anomaly."""
        l2 = _L2()
        await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        success = l2.signed(_event(1, 'success'), 1)
        await l2.host.handle_outcome(success, session_id=SESSION)
        await l2.host.handle_outcome(success, session_id=SESSION)
        await l2.host.handle_outcome(l2.signed(_event(1, 'failed'), 2), session_id=SESSION)
        assert [record.event['outcome'] for record in l2.host.records()] == ['attempted', 'success']
        assert l2.kinds() == ['replay-detected']
        # end def

    async def test_a_byte_identical_level_2_outcome_repeat_is_no_anomaly(self) -> None:
        """Uniqueness disposes of the repeat before the sequence check sees its decided value (§7.4)."""
        l2 = _L2()
        await l2.host.handle_attempt(l2.signed(_event(1), 0), session_id=SESSION)
        success = l2.signed(_event(1, 'success'), 1)
        await l2.host.handle_outcome(success, session_id=SESSION)
        await l2.host.handle_outcome(dict(success), session_id=SESSION)
        assert len(l2.host.records()) == 2
        assert l2.kinds() == []
        # end def

    # end class


class TestRevokedKeys:
    """§10.9: a revoked entry stays; it verifies what it signed and confirms nothing new."""

    async def test_a_host_refuses_a_new_event_under_a_revoked_key_as_unknown(self) -> None:
        """Forward-looking revocation, while the sealed record still verifies offline."""
        l2 = _L2()
        sealed = l2.signed(_event(1), 0)
        assert isinstance(await l2.host.handle_attempt(sealed, session_id=SESSION), AcceptResponse)
        l2.registry.revoke(l2.key.key_id)
        answer = await l2.host.handle_attempt(l2.signed(_event(2), 1), session_id=SESSION)
        assert isinstance(answer, RejectResponse)
        assert answer.reason == 'unknown-key'
        verifier = KeyRegistryVerifier(l2.registry)
        assert verifier.check(sealed)
        report = verify_ledger(l2.host.records(), signature_checker=verifier.check)
        assert report.complete
        # end def

    async def test_a_tool_refuses_an_accept_countersigned_under_a_revoked_host_key(self) -> None:
        """A revoked key confirms nothing new, so the tool aborts `host-signature-invalid` (§7.2)."""
        registry, countersigner = _host_registry()
        host = AuditHost('tenant-a', _l1(Countersign.HOST), countersigner=countersigner, clock=_Clock())
        host.open_session(SESSION)
        registry.revoke(countersigner.key_id)
        verifier = CountersignatureRegistryVerifier(registry)
        session = AmcpSession(
            InProcessTransport(host),
            SESSION,
            deps=_FixedDeps(),
            countersignature_verifier=verifier,
            require_countersign=True,
        )
        with pytest.raises(AmcpAbortedError) as raised:
            await _act(session)
            # end with
        assert raised.value.reason == 'host-signature-invalid'
        report = verify_ledger(host.records(), countersignature_checker=verifier.check)
        assert report.complete
        # end def

    def test_revocation_is_not_lifted_by_registering_the_key_again(self) -> None:
        """A key_id binds one key for life, and its revocation with it."""
        registry = KeyRegistry()
        key = generate_tool_key('k')
        registry.register_tool_key(key)
        registry.revoke(key.key_id)
        registry.register_tool_key(key)
        assert registry.current(key.key_id) is None
        # end def

    # end class


class TestTheTwoRegistriesShareNoKey:
    """§10.9: a key registered for a tool is never also registered for a host."""

    def test_a_shared_key_is_refused(self) -> None:
        """The same key under two names is still one key."""
        key = generate_tool_key('tool-key')
        tools, hosts = KeyRegistry(), KeyRegistry(KeyRole.HOST)
        tools.register_tool_key(key)
        hosts.register('host-key', key.public_key, SignatureAlgorithm.ED25519)
        with pytest.raises(ValueError, match='share no key'):
            assert_registries_disjoint(tools, hosts)
            # end with
        # end def

    def test_disjoint_registries_pass(self) -> None:
        """Different keys, whatever their names."""
        tools, hosts = KeyRegistry(), KeyRegistry(KeyRole.HOST)
        tools.register_tool_key(generate_tool_key('same-name'))
        other = generate_tool_key('same-name')
        hosts.register(other.key_id, other.public_key, SignatureAlgorithm.ED25519)
        assert_registries_disjoint(tools, hosts)
        # end def

    # end class


class TestTheCanonicalizationDomain:
    """§4, §8.1: lowercase UUIDs, Unicode scalar values only, and integral numbers written as floats."""

    async def test_a_lone_surrogate_in_a_member_name_is_schema_invalid(self) -> None:
        """JCS cannot serialize it, so the host refuses it before anything else (§8.1)."""
        host = AuditHost('tenant-a', _l1(), clock=_Clock())
        host.open_session(SESSION)
        answer = await host.handle_attempt(_event(1, action_context={'\ud800': 1}), session_id=SESSION)
        assert isinstance(answer, RejectResponse)
        assert answer.reason == 'schema-invalid'
        # end def

    async def test_an_uppercase_uuid_is_schema_invalid(self) -> None:
        """UUIDs are compared as strings, in the one form the schema admits (§4)."""
        host = AuditHost('tenant-a', _l1(), clock=_Clock())
        host.open_session(SESSION)
        event = {**_event(1), 'id': '0000000A-0000-4000-8000-00000000000A'}
        answer = await host.handle_attempt(event, session_id=SESSION)
        assert isinstance(answer, RejectResponse)
        assert answer.reason == 'schema-invalid'
        # end def

    async def test_an_integral_signer_seq_written_as_a_float_is_accepted_and_hashed_as_received(self) -> None:
        """JSON Schema's `integer` admits `0.0`, and JCS writes it as `0`, so the record is the same."""
        l2 = _L2()
        event = {**l2.signed(_event(1), 0), 'signer_seq': 0.0}
        answer = await l2.host.handle_attempt(event, session_id=SESSION)
        assert isinstance(answer, AcceptResponse)
        assert answer.record_hash == compute_record_hash(l2.signed(_event(1), 0), 0, answer.host_ts, '0' * 64)
        assert l2.kinds() == []
        # end def

    # end class


class TestTheVerifierNeverRaises:
    """§11.4: a malformed record is a finding, and the chain is checked on either side of it."""

    def test_an_out_of_domain_number_is_reported_and_the_chain_continues(self) -> None:
        """No exception, one `schema-invalid`, and the records after it still link."""
        ledger = Ledger('tenant-a')
        first = ledger.append(_event(1), TS)
        bad = SealedRecord(
            event=_event(2, action_context={'n': 2**60}),
            seq=1,
            host_ts=TS,
            previous_hash=first.record_hash,
            record_hash='c' * 64,
        )
        after_event = _event(3)
        after = SealedRecord(
            event=after_event,
            seq=2,
            host_ts=TS,
            previous_hash=bad.record_hash,
            record_hash=compute_record_hash(after_event, 2, TS, bad.record_hash),
        )
        report = verify_ledger([first, bad, after])
        assert [(issue.seq, issue.kind) for issue in report.issues] == [(1, 'schema-invalid')]
        # end def

    def test_an_earlier_version_record_is_verified_in_its_own_encoding(self) -> None:
        """A v0.2 record names `call_id` and signs in padded standard base64 (§11.4)."""
        key = generate_tool_key('legacy')
        registry = KeyRegistry()
        registry.register_tool_key(key)
        event: dict[str, object] = {
            'id': '0000000A-0000-4000-8000-00000000000A',
            'spec_version': 'auditable-mcp/0.2',
            'ts': TS,
            'call_id': 'call-1',
            'action_type': 'db.read',
            'mutates': False,
            'egress': False,
            'target_resource': {'kind': 'table', 'ref': 'customers'},
            'outcome': 'attempted',
            'key_id': key.key_id,
            'signer_seq': 0,
        }
        event['signature'] = base64.b64encode(key.private_key.sign(signature_payload(event))).decode('ascii')
        ledger = Ledger('tenant-a')
        ledger.append(event, TS)
        report = verify_ledger(ledger.records(), signature_checker=KeyRegistryVerifier(registry).check)
        assert report.issues == []
        assert report.complete
        # end def

    def test_two_sealed_records_under_one_signer_seq_are_a_replay(self) -> None:
        """The same (`key_id`, `session_id`, `signer_seq`) sealed twice is reported (§7.4, §11.4)."""
        ledger = Ledger('tenant-a')
        stamp = {'key_id': 'k1', 'signature': 'c2ln'}
        ledger.append(_event(1, signer_seq=0, **stamp), TS)
        ledger.append(_event(2, signer_seq=0, **stamp), TS)
        kinds = [issue.kind for issue in verify_ledger(ledger.records()).issues]
        assert kinds == ['replay-detected']
        # end def

    def test_a_refusal_is_correlated_within_its_own_session(self) -> None:
        """An attempt sealed in another session with the same `id` does not make the refusal an attempt's."""
        stamp = {'key_id': 'k1', 'signature': 'c2ln'}
        events = [
            _event(1, session_id=OTHER_SESSION, signer_seq=0, **stamp),
            _event(1, 'aborted', reason='host-rejected', signer_seq=1, **stamp),
        ]
        assert unaccounted_signer_seq(events) == []
        # end def

    async def test_the_expected_identity_binds_every_record(self) -> None:
        """§10.10: a mismatched `log_id`, a key outside the set, or no countersignature is `principal-mismatch`."""
        _registry, countersigner = _host_registry()
        host = AuditHost('tenant-a', _l1(Countersign.HOST), countersigner=countersigner, clock=_Clock())
        host.open_session(SESSION)
        await host.handle_attempt(_event(1), session_id=SESSION)
        records = host.records()
        expected = ExpectedIdentity(log_id=LOG_ID, host_key_ids=frozenset({countersigner.key_id}))
        assert verify_ledger(records, expected_identity=expected).issues == []
        for other in (
            ExpectedIdentity(log_id='tenant-b', host_key_ids=expected.host_key_ids),
            ExpectedIdentity(log_id=LOG_ID, host_key_ids=frozenset({'another-host-key'})),
        ):
            mismatched = verify_ledger(records, expected_identity=other)
            assert [issue.kind for issue in mismatched.issues] == ['principal-mismatch']
            # end for
        ledger = Ledger('tenant-a')
        ledger.append(_event(1), TS)
        unbound = verify_ledger(ledger.records(), expected_identity=expected)
        assert [issue.kind for issue in unbound.issues] == ['principal-mismatch']
        # end def

    def test_a_record_that_cannot_be_canonicalized_still_has_its_identity_checked(self) -> None:
        """§11.4: the identity check runs for a record the verifier cannot otherwise validate."""
        record = SealedRecord(
            event=_event(1, action_context={'note': 'a\ud800b'}),
            seq=0,
            host_ts=TS,
            previous_hash='0' * 64,
            record_hash='0' * 64,
            host_signature='c2ln',
            host_key_id='another-host-key',
            log_id=LOG_ID,
        )
        expected = ExpectedIdentity(log_id=LOG_ID, host_key_ids=frozenset({'host-key'}))
        kinds = sorted(issue.kind for issue in verify_ledger([record], expected_identity=expected).issues)
        assert kinds == ['principal-mismatch', 'schema-invalid']
        # end def

    def test_an_uncountersigned_record_is_invalid_where_the_countersignature_is_required(self) -> None:
        """§11.4: a stripped countersignature is `host-signature-invalid` when the requirement is an input."""
        ledger = Ledger('tenant-a')
        ledger.append(_event(1), TS)
        assert verify_ledger(ledger.records()).issues == []
        required = verify_ledger(ledger.records(), countersignature_required=True)
        assert [issue.kind for issue in required.issues] == ['host-signature-invalid']
        # end def

    def test_an_earlier_version_sealed_after_a_later_one_is_schema_invalid(self) -> None:
        """§11.4: a chain's versions do not go backwards."""
        earlier = _event(2, spec_version='auditable-mcp/0.2', call_id='7')
        del earlier['session_id']
        ledger = Ledger('tenant-a')
        ledger.append(earlier, TS)
        ledger.append(_event(1), TS)
        assert verify_ledger(ledger.records()).issues == []
        regressed = Ledger('tenant-a')
        regressed.append(_event(1), TS)
        regressed.append(earlier, TS)
        issues = verify_ledger(regressed.records()).issues
        assert [(issue.seq, issue.kind) for issue in issues] == [(1, 'schema-invalid')]
        # end def

    def test_a_refusal_sealed_before_an_attempt_with_its_id_accounts_for_a_value(self) -> None:
        """§7.2, §11.4: an attempt sealed after the refusal does not correlate to it."""
        stamp = {'key_id': 'k1', 'signature': 'c2ln'}
        events = [
            _event(1, 'aborted', reason='host-unavailable', signer_seq=1, **stamp),
            _event(1, signer_seq=2, **stamp),
        ]
        assert unaccounted_signer_seq(events) == []
        # end def

    # end class


class TestAJwkNamesTheFullySpecifiedAlgorithm:
    """§5.1: `EdDSA` is not an identifier of this specification."""

    def test_the_polymorphic_eddsa_is_refused(self) -> None:
        """Nothing in v0.3 wrote it, so nothing needs to read it."""
        key = generate_tool_key('k')
        jwk = {**public_jwk(key.key_id, key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL), 'alg': 'EdDSA'}
        with pytest.raises(ValueError, match='EdDSA'):
            public_key_of(jwk)
            # end with
        # end def

    # end class


class TestSessionsAreNeverReissued:
    """§6.3: a host issues a session id it has never issued, not even for a session that has ended."""

    async def test_a_closed_session_id_cannot_be_issued_again(self) -> None:
        """Otherwise the old call's accept could be replayed into the new session."""
        host = AuditHost('tenant-a', _l1(), clock=_Clock())
        host.open_session(SESSION)
        await host.handle_attempt(_event(1), session_id=SESSION)
        await host.close_session(SESSION)
        with pytest.raises(ValueError, match='already issued'):
            host.open_session(SESSION)
            # end with
        # end def

    # end class


class _AckLost:
    """A store whose first append lands and then reports failure, as a lost acknowledgement does."""

    def __init__(self) -> None:
        """Start empty, primed to lose one acknowledgement."""
        self.rows: list[SealedRecord] = []
        self._lose_next = True
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Store the record, then fail once."""
        if any(row.seq == record.seq for row in self.rows):
            raise RepositoryError(f'seq {record.seq} is taken')
            # end if
        self.rows.append(record)
        if self._lose_next:
            self._lose_next = False
            raise RepositoryError('timed out waiting for the acknowledgement')
            # end if
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """The last stored record."""
        return self.rows[-1] if self.rows else None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Every stored record."""
        return list(self.rows)
        # end def

    # end class


class TestAnAmbiguousAppend:
    """§7.1 atomic sealing across a store that can commit and lose the acknowledgement."""

    async def test_the_host_adopts_a_record_that_landed_instead_of_forking_the_chain(self) -> None:
        """The next seal re-reads the tail; the stored chain stays one chain."""
        store = _AckLost()
        host = AuditHost('tenant-a', _l1(), repository=store, clock=_Clock())
        host.open_session(SESSION)
        assert isinstance(await host.handle_attempt(_event(1), session_id=SESSION), UnavailableResponse)
        assert isinstance(await host.handle_attempt(_event(2), session_id=SESSION), AcceptResponse)
        assert [row.seq for row in store.rows] == [0, 1]
        assert verify_ledger(await store.read_all('tenant-a')).ok
        # end def

    async def test_the_adopted_attempt_sent_again_is_answered_from_the_ledger(self) -> None:
        """The tool was told `unavailable`; the byte-identical attempt gets the original accept (§7.1)."""
        store = _AckLost()
        host = AuditHost('tenant-a', _l1(), repository=store, clock=_Clock())
        host.open_session(SESSION)
        await host.handle_attempt(_event(1), session_id=SESSION)
        again = await host.handle_attempt(_event(1), session_id=SESSION)
        assert isinstance(again, AcceptResponse)
        assert again.seq == 0
        await host.handle_outcome(_event(1, 'success'), session_id=SESSION)
        await host.close_session(SESSION)
        assert [row.seq for row in store.rows] == [0, 1]
        assert host.anomalies() == []
        # end def

    async def test_a_seal_cancelled_after_its_append_landed_is_adopted_by_the_next(self) -> None:
        """A cancellation mid-append is as ambiguous as a lost acknowledgement, and is settled the same way."""
        store = _SlowAck()
        host = AuditHost('tenant-a', _l1(), repository=store, clock=_Clock())
        host.open_session(SESSION)
        other = '0198f3a2-5c1e-7000-8000-00000000abc9'
        host.open_session(other)
        with anyio.move_on_after(0.05):
            await host.handle_attempt(_event(1), session_id=SESSION)
            # end with
        assert [row.seq for row in store.rows] == [0]
        assert host.records() == []
        store.slow = False
        answer = await host.handle_attempt(_event(2, session_id=other), session_id=other)
        assert isinstance(answer, AcceptResponse)
        assert answer.seq == 1
        assert verify_ledger(await store.read_all('tenant-a')).ok
        # end def

    async def test_a_countersign_cancelled_mid_seal_leaves_the_tail_to_be_re_read(self) -> None:
        """Nothing is written, and the next seal still settles the tail before it seals."""
        store = _AckLost()
        signer = _HangingCountersigner()
        host = AuditHost('tenant-a', _l1(Countersign.HOST), repository=store, countersigner=signer, clock=_Clock())
        host.open_session(SESSION)
        with anyio.move_on_after(0.05):
            await host.handle_attempt(_event(1), session_id=SESSION)
            # end with
        assert host._tail_uncertain
        signer.hang = False
        store._lose_next = False
        assert isinstance(await host.handle_attempt(_event(2), session_id=SESSION), AcceptResponse)
        assert [row.seq for row in store.rows] == [0]
        # end def

    # end class


class _SlowAck(_AckLost):
    """A store whose append lands and whose acknowledgement then takes long enough to be cancelled."""

    def __init__(self) -> None:
        """Start empty, slow to acknowledge, and losing no acknowledgement outright."""
        super().__init__()
        self._lose_next = False
        self.slow = True
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Store the record, then wait on the acknowledgement."""
        await super().append(partition, record)
        if self.slow:
            await anyio.sleep(10)
            # end if
        # end def

    # end class


class _HangingCountersigner:
    """A countersigner whose KMS call hangs until released."""

    key_id = 'host-key-1'

    def __init__(self) -> None:
        """Hang until `hang` is cleared."""
        self.hang = True
        # end def

    async def sign(self, payload: bytes) -> str:
        """Hang, or return a fixed signature."""
        if self.hang:
            await anyio.sleep(10)
            # end if
        return 'AAAA'
        # end def

    # end class


class TestSessionNumbering:
    """§7.4: the sequence belongs to the audit session, shared by every `AmcpSession` serving it."""

    async def test_two_sessions_over_one_numbering_continue_one_sequence(self) -> None:
        """A handler invoked again for a later request of the call continues from where it left off."""
        l2 = _L2()

        class _Carrying(InProcessTransport):
            """An in-process transport that carries the call's numbering, as the MCP binding does."""

            numbering = SessionNumbering()

            # end class

        transport = _Carrying(l2.host)
        signer = Ed25519Signer.from_tool_key(l2.key)
        deps = _FixedDeps()
        for _request in range(2):
            session = AmcpSession(transport, SESSION, signer=signer, deps=deps)
            await _act(session)
            # end for
        numbers = [record.event['signer_seq'] for record in l2.host.records()]
        assert numbers == [0, 1, 2, 3]
        assert 'replay-detected' not in l2.kinds()
        # end def

    # end class
