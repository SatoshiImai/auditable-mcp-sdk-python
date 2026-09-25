"""Unit tests for the host audit subsystem."""

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.models import (
    SPEC_VERSION,
    AcceptResponse,
    AuditCapability,
    Countersign,
    Level,
    RejectResponse,
    UnavailableResponse,
)
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


class _Clock:
    """A monotonic host clock producing valid ISO-8601 timestamps."""

    def __init__(self) -> None:
        """Start at zero."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-07-15T00:00:{self._n:02d}.000Z'
        # end def


class _FixedDeps:
    """Deterministic id/time source for the session integration tests."""

    def __init__(self) -> None:
        """Start the id counter at zero."""
        self._n = 0
        # end def

    def new_id(self) -> str:
        """Return the next deterministic id."""
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'
        # end def

    def now(self) -> str:
        """Return a fixed valid timestamp."""
        return '2026-07-15T00:00:01.000Z'
        # end def


class _StubSigner:
    """Stamps monotonic L2 fields so an L2 session can drive the host."""

    key_id = 'k1'

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Add key_id, the number the session's section holds, and a placeholder signature."""
        return {**event, 'key_id': self.key_id, 'signer_seq': signer_seq, 'signature': 'stub'}
        # end def


class _OkVerifier:
    """A verifier that accepts every signature."""

    async def verify(self, event: dict[str, object]) -> str | None:
        """Always verify."""
        return None
        # end def


class _SwitchableVerifier:
    """Accepts until told the signatures are forged."""

    def __init__(self) -> None:
        """Start accepting."""
        self.forged = False
        # end def

    async def verify(self, event: dict[str, object]) -> str | None:
        """Reject as forged once switched."""
        return 'signature-invalid' if self.forged else None
        # end def


class _BadVerifier:
    """A verifier that rejects every signature."""

    async def verify(self, event: dict[str, object]) -> str | None:
        """Always reject as forged."""
        return 'signature-invalid'
        # end def


def _attempt(event_id: str, **overrides: object) -> dict[str, object]:
    """Build a wire attempt event."""
    event: dict[str, object] = {
        'id': event_id,
        'spec_version': SPEC_VERSION,
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    event.update(overrides)
    return event
    # end def


def _signed(event: dict[str, object], sequence: int) -> dict[str, object]:
    """Stamp an event with L2 fields at a given sequence."""
    return {**event, 'key_id': 'k1', 'signer_seq': sequence, 'signature': 'stub'}
    # end def


def _l1_host() -> AuditHost:
    """Build an L1 host with a deterministic clock and the test's audit session open."""
    host = AuditHost('tenant-a', clock=_Clock())
    host.open_session(SESSION)
    return host
    # end def


async def test_valid_attempt_is_accepted_and_sealed() -> None:
    """A well-formed attempt is sealed and answered with a Verifiable Accept."""
    host = _l1_host()
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, AcceptResponse)
    assert response.seq == 0
    assert len(host.records()) == 1
    # end def


async def test_malformed_attempt_is_rejected() -> None:
    """An attempt failing the shared shape is rejected and flagged."""
    host = _l1_host()
    bad = _attempt('00000000-0000-4000-8000-000000000001')
    del bad['target_resource']
    response = await host.handle_attempt(bad)
    assert isinstance(response, RejectResponse)
    assert response.reason == 'schema-invalid'
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())
    # end def


async def test_attempt_must_carry_attempted_outcome() -> None:
    """An attempt whose outcome is not `attempted` is rejected."""
    host = _l1_host()
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001', outcome='success'))
    assert isinstance(response, RejectResponse)
    assert response.reason == 'schema-invalid'
    # end def


async def test_non_canonicalizable_number_is_rejected() -> None:
    """An integer beyond the §8.1 domain is rejected before it can break canonicalization."""
    host = _l1_host()
    event = _attempt('00000000-0000-4000-8000-000000000001', action_context={'n': 2**53})
    response = await host.handle_attempt(event)
    assert isinstance(response, RejectResponse)
    assert response.reason == 'schema-invalid'
    # end def


async def test_a_byte_identical_repeat_is_answered_from_the_ledger() -> None:
    """§7.1: the same attempt sent again gets the original accept, and nothing is sealed twice."""
    host = _l1_host()
    event = _attempt('00000000-0000-4000-8000-000000000001')
    first = await host.handle_attempt(event)
    assert await host.handle_attempt(dict(event)) == first
    assert len(host.records()) == 1
    assert host.anomalies() == []
    # end def


async def test_an_id_repeated_with_different_bytes_is_a_replay() -> None:
    """§7.1: the host cannot tell a changed event under a sealed id from a replay, and rejects it."""
    host = _l1_host()
    await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    response = await host.handle_attempt(
        _attempt('00000000-0000-4000-8000-000000000001', target_resource={'kind': 'table', 'ref': 'salaries'})
    )
    assert isinstance(response, RejectResponse)
    assert response.reason == 'replay-detected'
    assert len(host.records()) == 1
    # end def


async def test_an_event_outside_the_calls_session_is_rejected() -> None:
    """§6.3: a session the host did not issue, or not the one the call carries, is a replay."""
    host = _l1_host()
    other = '0198f3a2-5c1e-7000-8000-00000000ffff'
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001', session_id=other))
    assert isinstance(response, RejectResponse)
    assert response.reason == 'replay-detected'
    host.open_session(other)
    response = await host.handle_attempt(
        _attempt('00000000-0000-4000-8000-000000000001', session_id=other), session_id=SESSION
    )
    assert isinstance(response, RejectResponse)
    assert host.records() == []
    # end def


async def test_a_closed_session_accepts_nothing() -> None:
    """§6.3: the call ended, so an event for it arrives too late to be sealed."""
    host = _l1_host()
    await host.close_session(SESSION)
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, RejectResponse)
    assert host.records() == []
    # end def


async def test_an_accepted_attempt_left_unresolved_is_recorded_when_the_call_ends() -> None:
    """§6.3: the host observes the call's end, so a trailing outcome's loss is visible to it."""
    host = _l1_host()
    await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    await host.close_session(SESSION)
    assert [anomaly.kind for anomaly in host.anomalies()] == ['unresolved-attempt']
    # end def


async def test_a_session_is_issued_once() -> None:
    """§6.3: a session id the host issued before would let one call's events stand for another's."""
    host = _l1_host()
    with pytest.raises(ValueError):
        host.open_session(SESSION)
        # end with
    # end def


async def test_persistence_failure_fails_closed() -> None:
    """A persistence failure yields unavailable, sealing nothing; the identical attempt may come again."""
    host = _l1_host()
    host.persistence_available = False
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, UnavailableResponse)
    assert len(host.records()) == 0
    host.persistence_available = True
    assert isinstance(await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001')), AcceptResponse)
    # end def


async def test_correlated_outcome_is_sealed() -> None:
    """An outcome sharing an accepted attempt's id is sealed as the next record."""
    host = _l1_host()
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_attempt(event_id))
    await host.handle_outcome(_attempt(event_id, outcome='success'))
    assert [r.event['outcome'] for r in host.records()] == ['attempted', 'success']
    assert host.anomalies() == []
    assert verify_ledger(host.records(), host.digest()).ok
    # end def


async def test_attempted_on_outcome_channel_is_dropped_not_sealed() -> None:
    """§6: an `attempted` outcome on the audit/outcome channel is invalid — flagged schema-invalid, never sealed."""
    host = _l1_host()
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_attempt(event_id))
    await host.handle_outcome(_attempt(event_id, outcome='attempted'))
    assert [r.event['outcome'] for r in host.records()] == ['attempted']
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())
    # end def


async def test_success_outcome_without_attempt_is_flagged() -> None:
    """A success referencing no accepted attempt is an anomaly and is not sealed (§7.2)."""
    host = _l1_host()
    await host.handle_outcome(_attempt('00000000-0000-4000-8000-0000000000ff', outcome='success'))
    orphan = next(a for a in host.anomalies() if a.kind == 'orphaned-outcome')
    assert 'without an accepted attempt' in orphan.detail
    assert len(host.records()) == 0
    # end def


async def test_aborted_outcome_without_attempt_is_sealed_as_a_refusal() -> None:
    """§7.2, §10.4: an aborted outcome for a never-accepted attempt is a record, not an anomaly."""
    host = _l1_host()
    await host.handle_outcome(
        _attempt('00000000-0000-4000-8000-0000000000ff', outcome='aborted', reason='host-rejected')
    )
    assert host.anomalies() == []
    assert [record.event['outcome'] for record in host.records()] == ['aborted']
    # end def


def test_l2_host_requires_a_verifier() -> None:
    """Constructing an L2 host without a verifier fails fast."""
    with pytest.raises(ValueError):
        AuditHost(
            'tenant-a',
            AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        )
        # end with
    # end def


def test_host_accepts_a_partial_capability_and_stamps_its_own_version() -> None:
    """A partial input needs no spec_version; the local host stamps its own (§6.1)."""
    host = AuditHost('tenant-a', {'level': Level.L1})
    assert host.capability.spec_version == SPEC_VERSION
    assert host.capability.level == Level.L1
    # end def


def _l2_host(verifier: object) -> AuditHost:
    """Build an L2 host with the given verifier and the test's audit session open."""
    host = AuditHost(
        'tenant-a',
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        verifier=verifier,  # type: ignore[arg-type]
        clock=_Clock(),
    )
    host.open_session(SESSION)
    return host


async def test_l2_unsigned_attempt_is_rejected() -> None:
    """Under L2, an attempt missing the signature fields is rejected."""
    host = _l2_host(_OkVerifier())
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, RejectResponse)
    assert response.reason == 'l2-unsigned'
    # end def


async def test_l2_forged_signature_is_rejected() -> None:
    """Under L2, a signature that does not verify is rejected."""
    host = _l2_host(_BadVerifier())
    response = await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000001'), 0))
    assert isinstance(response, RejectResponse)
    assert response.reason == 'signature-invalid'
    # end def


async def test_l2_sequence_replay_is_rejected() -> None:
    """Under L2, a sequence at or below the last accepted one for a key is a replay."""
    host = _l2_host(_OkVerifier())
    await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000001'), 5))
    response = await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000002'), 5))
    assert isinstance(response, RejectResponse)
    assert response.reason == 'replay-detected'
    # end def


async def test_l2_sequence_gap_is_flagged_but_accepted() -> None:
    """Under L2, a forward gap is flagged as a possible suppression but the valid event is accepted."""
    host = _l2_host(_OkVerifier())
    await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000001'), 0))
    response = await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000002'), 2))
    assert isinstance(response, AcceptResponse)
    assert any(a.kind == 'signer-seq-gap' for a in host.anomalies())
    # end def


async def test_outcome_after_reject_is_flagged() -> None:
    """An outcome for an id that was rejected (never accepted) is flagged distinctly."""
    host = _l2_host(_OkVerifier())
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_attempt(event_id))  # unsigned under L2 -> rejected, id remembered
    await host.handle_outcome(_signed(_attempt(event_id, outcome='success'), 0))
    orphan = next(a for a in host.anomalies() if a.kind == 'orphaned-outcome')
    assert 'rejected id' in orphan.detail
    # end def


async def test_session_over_real_host_produces_a_verifiable_chain() -> None:
    """An L1 session wired to a real host seals a clean, anomaly-free, verifiable chain."""
    host = _l1_host()
    session = AmcpSession(InProcessTransport(host), host.open_session(), deps=_FixedDeps())
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    assert [r.event['outcome'] for r in host.records()] == ['attempted', 'success']
    assert host.anomalies() == []
    assert verify_ledger(host.records(), host.digest()).ok
    # end def


async def test_l2_session_over_real_host_tracks_sequence() -> None:
    """An L2 session (stub signer + verifier) seals a verifiable chain and advances the key sequence."""
    host = _l2_host(_OkVerifier())
    session = AmcpSession(InProcessTransport(host), host.open_session(), deps=_FixedDeps(), signer=_StubSigner())
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    records = host.records()
    assert [r.event['outcome'] for r in records] == ['attempted', 'success']
    assert records[0].event['signer_seq'] == 0
    assert records[1].event['signer_seq'] == 1
    assert host.anomalies() == []
    assert verify_ledger(records, host.digest()).ok
    # end def


_L2 = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE)


class TestAnOutcomeThatFailsLevel2Validation:
    """§6, §8.3: an outcome is validated like an attempt, and a failure is dropped and flagged."""

    @pytest.mark.asyncio
    async def test_a_forged_outcome_is_not_sealed_and_is_flagged(self) -> None:
        """§6: the host cannot reject a notification, so the anomaly set is where the failure goes."""
        verifier = _SwitchableVerifier()
        host = _l2_host(verifier)
        attempt = _signed(_attempt('00000000-0000-4000-8000-000000000001'), 0)
        await host.handle_attempt(attempt)
        verifier.forged = True
        before = len(host.records())
        await host.handle_outcome(_signed({**attempt, 'outcome': 'success'}, 1))
        assert len(host.records()) == before, 'a forged outcome was sealed'
        assert [anomaly.kind for anomaly in host.anomalies()] == ['signature-invalid']
        # end def

    @pytest.mark.asyncio
    async def test_a_replayed_outcome_sequence_is_not_sealed_and_is_flagged(self) -> None:
        """§7.4: a signer_seq at or below the last accepted is a replay, on either channel."""
        host = _l2_host(_OkVerifier())
        attempt = _signed(_attempt('00000000-0000-4000-8000-000000000001'), 0)
        await host.handle_attempt(attempt)
        before = len(host.records())
        await host.handle_outcome(_signed({**attempt, 'outcome': 'success'}, 0))
        assert len(host.records()) == before, 'a replayed outcome was sealed'
        assert 'replay-detected' in [anomaly.kind for anomaly in host.anomalies()]
        # end def

    # end class


@pytest.mark.asyncio
async def test_an_outcome_with_an_uncanonicalizable_number_is_dropped_and_flagged() -> None:
    """§8.1 applies on both channels, and §6 leaves the anomaly set as the only place to say so."""
    host = _l1_host()
    attempt = _attempt('00000000-0000-4000-8000-000000000001')
    await host.handle_attempt(attempt)
    before = len(host.records())
    await host.handle_outcome({**attempt, 'outcome': 'success', 'action_context': {'rows': 2**53}})
    assert len(host.records()) == before, 'an uncanonicalizable outcome was sealed'
    assert 'schema-invalid' in [anomaly.kind for anomaly in host.anomalies()]
    # end def
