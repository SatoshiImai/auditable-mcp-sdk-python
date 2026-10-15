"""Two host surfaces for a binding whose sessions are not a-MCP's calls.

A session that outlives a restart (`AuditHost.resume`'s `open_sessions`), and an outcome whose fate the
binding acknowledges (`record_outcome`). Neither changes how a host serving a-MCP's own bindings behaves.
The same cases as the TypeScript SDK's `host-lifetime.test.ts`.
"""

from auditable_mcp.host import AuditHost, OutcomeDisposition
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Countersign, Level
from auditable_mcp.storage.memory import InMemoryLedgerRepository
from auditable_mcp.storage.repository import RepositoryError

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
_L2 = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE)


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

    # end class


class _OkVerifier:
    """A verifier that accepts every signature."""

    async def verify(self, event: dict[str, object]) -> str | None:
        """Always verify."""
        return None
        # end def

    # end class


class _FailingRepository:
    """A repository whose `append` always fails."""

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Refuse the append."""
        raise RepositoryError('storage down')
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Hold nothing."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Hold nothing."""
        return []
        # end def

    # end class


def _id(n: int) -> str:
    """A stable valid event id."""
    return f'00000000-0000-4000-8000-{n:012x}'
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


class TestRecordOutcome:
    """`record_outcome` reports what became of an outcome (§7.2)."""

    async def test_sealed_then_repeat_for_the_byte_identical_copy(self) -> None:
        host = AuditHost('tenant-a', clock=_Clock())
        host.open_session(SESSION)
        attempt = _attempt(_id(1))
        await host.handle_attempt(attempt, session_id=SESSION)
        outcome = {**attempt, 'outcome': 'success'}
        assert await host.record_outcome(outcome) == OutcomeDisposition.SEALED
        assert await host.record_outcome(outcome) == OutcomeDisposition.REPEAT
        # end def

    async def test_refused_with_the_anomaly_recorded_for_an_outcome_with_no_accepted_attempt(self) -> None:
        host = AuditHost('tenant-a', clock=_Clock())
        host.open_session(SESSION)
        assert await host.record_outcome(_attempt(_id(1), outcome='success')) == OutcomeDisposition.REFUSED
        assert [anomaly.kind for anomaly in host.anomalies()] == ['orphaned-outcome']
        # end def

    async def test_not_recorded_when_persistence_fails(self) -> None:
        host = AuditHost('tenant-a', clock=_Clock())
        host.open_session(SESSION)
        attempt = _attempt(_id(1))
        await host.handle_attempt(attempt, session_id=SESSION)
        host.persistence_available = False
        assert await host.record_outcome({**attempt, 'outcome': 'success'}) == OutcomeDisposition.NOT_RECORDED
        assert host.anomalies() == []
        # end def

    async def test_not_recorded_when_the_store_refuses_the_append(self) -> None:
        host = AuditHost('tenant-a', clock=_Clock(), repository=_FailingRepository())
        host.open_session(SESSION)
        aborted = _attempt(_id(1), outcome='aborted', reason='host-unavailable')
        assert await host.record_outcome(aborted) == OutcomeDisposition.NOT_RECORDED
        # end def

    # end class


class TestResumeWithOpenSessions:
    """`AuditHost.resume(..., open_sessions=...)`."""

    async def _before_restart(self) -> tuple[InMemoryLedgerRepository, object, dict[str, object]]:
        repo = InMemoryLedgerRepository()
        host = AuditHost('tenant-a', _L2, clock=_Clock(), repository=repo, verifier=_OkVerifier())
        host.open_session(SESSION)
        await host.handle_attempt(_signed(_attempt(_id(1)), 0), session_id=SESSION)
        await host.handle_outcome(_signed({**_attempt(_id(1)), 'outcome': 'success'}, 1))
        pending = _signed(_attempt(_id(2)), 2)
        second = await host.handle_attempt(pending, session_id=SESSION)
        return repo, second, pending
        # end def

    async def _resume(self, repo: InMemoryLedgerRepository, *, open_sessions: tuple[str, ...] = ()) -> AuditHost:
        return await AuditHost.resume(
            'tenant-a', _L2, repository=repo, verifier=_OkVerifier(), clock=_Clock(), open_sessions=open_sessions
        )
        # end def

    async def test_keeps_the_named_session_open(self) -> None:
        """A pending attempt is not unresolved, and its outcome seals."""
        repo, _, _ = await self._before_restart()
        host = await self._resume(repo, open_sessions=(SESSION,))
        assert host.anomalies() == []
        success = _signed({**_attempt(_id(2)), 'outcome': 'success'}, 3)
        assert await host.record_outcome(success) == OutcomeDisposition.SEALED
        assert (await host.handle_attempt(_signed(_attempt(_id(3)), 4), session_id=SESSION)).status == 'accept'
        # end def

    async def test_answers_a_byte_identical_resend_from_the_ledger(self) -> None:
        """§7.1, as before the restart."""
        repo, second, pending = await self._before_restart()
        host = await self._resume(repo, open_sessions=(SESSION,))
        assert await host.handle_attempt(pending, session_id=SESSION) == second
        # end def

    async def test_refuses_a_signer_seq_the_session_decided_before_the_restart(self) -> None:
        """§7.4."""
        repo, _, _ = await self._before_restart()
        host = await self._resume(repo, open_sessions=(SESSION,))
        reused = await host.handle_attempt(_signed(_attempt(_id(4)), 1), session_id=SESSION)
        assert reused.status == 'reject'
        assert getattr(reused, 'reason', None) == 'replay-detected'
        # end def

    async def test_refuses_a_second_outcome_for_an_operation_sealed_before_the_restart(self) -> None:
        """§7.2."""
        repo, _, _ = await self._before_restart()
        host = await self._resume(repo, open_sessions=(SESSION,))
        differing = _signed({**_attempt(_id(1)), 'outcome': 'failed'}, 3)
        assert await host.record_outcome(differing) == OutcomeDisposition.REFUSED
        assert [anomaly.kind for anomaly in host.anomalies()] == ['replay-detected']
        # end def

    async def test_without_open_sessions_ends_every_session(self) -> None:
        """§6.3, as before."""
        repo, _, _ = await self._before_restart()
        host = await self._resume(repo)
        assert [anomaly.kind for anomaly in host.anomalies()] == ['unresolved-attempt']
        refused = await host.handle_attempt(_signed(_attempt(_id(3)), 3), session_id=SESSION)
        assert refused.status == 'reject'
        # end def

    # end class
