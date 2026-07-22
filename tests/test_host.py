"""Unit tests for the host audit subsystem."""

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.models import (
    AcceptResponse,
    AuditCapability,
    Level,
    RejectResponse,
    UnavailableResponse,
)
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger


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

    def __init__(self) -> None:
        """Start the sequence at zero."""
        self._seq = 0
        # end def

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Add key_id, a monotonic sequence, and a placeholder signature."""
        self._seq += 1
        return {**event, 'key_id': 'k1', 'sequence': self._seq, 'signature': 'stub'}
        # end def


class _OkVerifier:
    """A verifier that accepts every signature."""

    async def verify(self, event: dict[str, object]) -> str | None:
        """Always verify."""
        return None
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
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
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
    return {**event, 'key_id': 'k1', 'sequence': sequence, 'signature': 'stub'}
    # end def


def _l1_host() -> AuditHost:
    """Build an L1 host with a deterministic clock."""
    return AuditHost('tenant-a', clock=_Clock())
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
    assert response.reason == 'attempt-must-be-attempted'
    # end def


async def test_non_canonicalizable_number_is_rejected() -> None:
    """An integer beyond the §8.1 domain is rejected before it can break canonicalization."""
    host = _l1_host()
    event = _attempt('00000000-0000-4000-8000-000000000001', action_context={'n': 2**53})
    response = await host.handle_attempt(event)
    assert isinstance(response, RejectResponse)
    assert response.reason == 'numeric-domain'
    # end def


async def test_duplicate_attempt_id_is_rejected_as_replay() -> None:
    """A second attempt with an already-accepted id is a replay."""
    host = _l1_host()
    event = _attempt('00000000-0000-4000-8000-000000000001')
    await host.handle_attempt(event)
    response = await host.handle_attempt(event)
    assert isinstance(response, RejectResponse)
    assert response.reason == 'attempt-replay'
    assert len(host.records()) == 1
    # end def


async def test_persistence_failure_fails_closed() -> None:
    """A persistence failure yields a retryable unavailable, sealing nothing."""
    host = _l1_host()
    host.persistence_available = False
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, UnavailableResponse)
    assert response.retryable is True
    assert len(host.records()) == 0
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


async def test_success_outcome_without_attempt_is_flagged() -> None:
    """A success referencing no accepted attempt is an anomaly and is not sealed (§7.2)."""
    host = _l1_host()
    await host.handle_outcome(_attempt('00000000-0000-4000-8000-0000000000ff', outcome='success'))
    assert any(a.kind == 'outcome-without-attempt' for a in host.anomalies())
    assert len(host.records()) == 0
    # end def


async def test_aborted_outcome_without_attempt_is_not_an_anomaly() -> None:
    """A fail-closed aborted outcome for a never-accepted attempt is honest, not tampering (§10.4)."""
    host = _l1_host()
    await host.handle_outcome(
        _attempt('00000000-0000-4000-8000-0000000000ff', outcome='aborted', reason='host-rejected')
    )
    assert host.anomalies() == []
    assert len(host.records()) == 0
    # end def


def test_l2_host_requires_a_verifier() -> None:
    """Constructing an L2 host without a verifier fails fast."""
    with pytest.raises(ValueError):
        AuditHost('tenant-a', AuditCapability(level=Level.L2))
        # end with
    # end def


def _l2_host(verifier: object) -> AuditHost:
    """Build an L2 host with the given verifier."""
    return AuditHost('tenant-a', AuditCapability(level=Level.L2), verifier=verifier, clock=_Clock())  # type: ignore[arg-type]


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
    assert response.reason == 'signer-sequence-replay'
    # end def


async def test_l2_sequence_gap_is_flagged_but_accepted() -> None:
    """Under L2, a forward gap is flagged as a possible suppression but the valid event is accepted."""
    host = _l2_host(_OkVerifier())
    await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000001'), 0))
    response = await host.handle_attempt(_signed(_attempt('00000000-0000-4000-8000-000000000002'), 2))
    assert isinstance(response, AcceptResponse)
    assert any(a.kind == 'signer-sequence-gap' for a in host.anomalies())
    # end def


async def test_outcome_after_reject_is_flagged() -> None:
    """An outcome for an id that was rejected (never accepted) is flagged distinctly."""
    host = _l2_host(_OkVerifier())
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_attempt(event_id))  # unsigned under L2 -> rejected, id remembered
    await host.handle_outcome(_signed(_attempt(event_id, outcome='success'), 0))
    assert any(a.kind == 'outcome-after-reject' for a in host.anomalies())
    # end def


async def test_session_over_real_host_produces_a_verifiable_chain() -> None:
    """An L1 session wired to a real host seals a clean, anomaly-free, verifiable chain."""
    host = _l1_host()
    session = AmcpSession(InProcessTransport(host), 'call_1', deps=_FixedDeps())
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
    session = AmcpSession(InProcessTransport(host), 'call_1', deps=_FixedDeps(), signer=_StubSigner())
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    records = host.records()
    assert [r.event['outcome'] for r in records] == ['attempted', 'success']
    assert records[0].event['sequence'] == 1
    assert records[1].event['sequence'] == 2
    assert host.anomalies() == []
    assert verify_ledger(records, host.digest()).ok
    # end def
