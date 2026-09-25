"""Unit tests for the durable-ledger repository interface and host persistence."""

import logging

import pytest

from auditable_mcp.hashing import GENESIS_HASH
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.ledger import Ledger, SealedRecord
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
from auditable_mcp.storage import InMemoryLedgerRepository, RepositoryError
from auditable_mcp.verify import verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


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


class _FixedDeps:
    """Deterministic id/time source producing valid UUIDs, offset by `start` to avoid collisions."""

    def __init__(self, start: int = 0) -> None:
        """Start the id counter at `start`."""
        self._n = start
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


class _FlakyRepository:
    """An in-memory repository whose `append` fails while `fail` is set (to test fail-closed)."""

    def __init__(self) -> None:
        """Initialize empty and healthy."""
        self._records: dict[str, list[SealedRecord]] = {}
        self.fail = False
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Append unless `fail` is set."""
        if self.fail:
            raise RepositoryError('storage down')
            # end if
        self._records.setdefault(partition, []).append(record)
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Return the last record of `partition`, or None."""
        records = self._records.get(partition)
        return records[-1] if records else None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Return every record of `partition`."""
        return list(self._records.get(partition, []))
        # end def


class _OkVerifier:
    """A verifier that accepts every signature."""

    async def verify(self, event: dict[str, object]) -> str | None:
        """Always verify."""
        return None
        # end def


def _signed(event: dict[str, object], sequence: int) -> dict[str, object]:
    """Stamp an event with L2 fields at a given sequence."""
    return {**event, 'key_id': 'k1', 'signer_seq': sequence, 'signature': 'stub'}
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


async def test_in_memory_repository_isolates_partitions() -> None:
    """Records written to one partition are never returned for another (§10.5)."""
    repo = InMemoryLedgerRepository()
    ledger = Ledger('a')
    record = ledger.append(_attempt('00000000-0000-4000-8000-000000000001'), '2026-07-15T00:00:01.000Z')
    await repo.append('a', record)
    assert await repo.read_all('a') == [record]
    assert await repo.read_all('b') == []
    assert await repo.load_tail('a') == record
    assert await repo.load_tail('b') is None
    # end def


def test_seal_is_pure_and_commit_advances() -> None:
    """seal computes without mutating; commit advances the count and tail."""
    ledger = Ledger('t')
    sealed = ledger.seal(_attempt('00000000-0000-4000-8000-000000000001'), '2026-07-15T00:00:01.000Z')
    assert len(ledger) == 0
    assert ledger.digest() == GENESIS_HASH
    ledger.commit(sealed)
    assert len(ledger) == 1
    assert ledger.digest() == sealed.record_hash
    # end def


def test_resume_from_restores_chain_state_without_history() -> None:
    """A resumed ledger continues the chain from the tail while holding no prior records."""
    source = Ledger('t')
    source.append(_attempt('00000000-0000-4000-8000-000000000001'), '2026-07-15T00:00:01.000Z')
    tail = source.append(_attempt('00000000-0000-4000-8000-000000000002'), '2026-07-15T00:00:02.000Z')

    resumed = Ledger('t')
    resumed.resume_from(tail)
    assert len(resumed) == 2
    assert resumed.digest() == tail.record_hash
    assert resumed.records() == []
    linked = resumed.append(_attempt('00000000-0000-4000-8000-000000000003'), '2026-07-15T00:00:03.000Z')
    assert linked.seq == 2
    assert linked.previous_hash == tail.record_hash
    # end def


async def test_host_persists_accepted_records() -> None:
    """A host with a repository writes every sealed record; the stored chain verifies."""
    repo = InMemoryLedgerRepository()
    host = AuditHost('tenant-a', repository=repo, clock=_Clock())
    session = AmcpSession(InProcessTransport(host), host.open_session(), deps=_FixedDeps())
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    stored = await repo.read_all('tenant-a')
    assert [r.event['outcome'] for r in stored] == ['attempted', 'success']
    assert [r.record_hash for r in stored] == [r.record_hash for r in host.records()]
    assert verify_ledger(stored, host.digest()).ok
    # end def


async def test_host_resumes_the_persisted_chain() -> None:
    """A resumed host continues the same hash chain; the full stored ledger verifies."""
    repo = InMemoryLedgerRepository()
    host1 = AuditHost('tenant-a', repository=repo, clock=_Clock())
    session1 = AmcpSession(InProcessTransport(host1), host1.open_session(), deps=_FixedDeps(start=0))
    async with session1.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    tail_before = host1.digest()

    host2 = await AuditHost.resume('tenant-a', repository=repo, clock=_Clock())
    assert host2.digest() == tail_before
    session2 = AmcpSession(InProcessTransport(host2), host2.open_session(), deps=_FixedDeps(start=10))
    async with session2.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with

    stored = await repo.read_all('tenant-a')
    assert len(stored) == 4
    assert stored[2].previous_hash == tail_before  # the post-restart chain links to the old tail
    assert verify_ledger(stored, host2.digest()).ok
    # end def


async def test_resume_ends_the_sessions_before_the_restart_and_never_issues_them_again() -> None:
    """§6.3: a restart ends every session, and a session id in the ledger is never issued again."""
    repo = InMemoryLedgerRepository()
    host1 = AuditHost('tenant-a', repository=repo, clock=_Clock())
    host1.open_session(SESSION)
    attempt = _attempt('00000000-0000-4000-8000-000000000001')
    await host1.handle_attempt(attempt)

    host2 = await AuditHost.resume('tenant-a', repository=repo, clock=_Clock())
    refused = await host2.handle_attempt(attempt)
    assert isinstance(refused, RejectResponse)
    assert refused.reason == 'replay-detected'
    with pytest.raises(ValueError):
        host2.open_session(SESSION)
        # end with
    assert len(await repo.read_all('tenant-a')) == 1
    # end def


async def test_resume_records_every_attempt_the_restart_left_unresolved() -> None:
    """A restart ends every call in flight: an attempt with no outcome after it is `unresolved-attempt` (§6.3)."""
    repo = InMemoryLedgerRepository()
    host1 = AuditHost('tenant-a', repository=repo, clock=_Clock())
    done = AmcpSession(InProcessTransport(host1), host1.open_session(), deps=_FixedDeps(start=0))
    async with done.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    host1.open_session(SESSION)
    left_open = '00000000-0000-4000-8000-0000000000aa'
    await host1.handle_attempt(_attempt(left_open))

    host2 = await AuditHost.resume('tenant-a', repository=repo, clock=_Clock())
    assert [(anomaly.id, anomaly.kind) for anomaly in host2.anomalies()] == [(left_open, 'unresolved-attempt')]
    # The session the attempt was made in is not open on the resumed host.
    refused = await host2.handle_attempt(_attempt('00000000-0000-4000-8000-0000000000ab'))
    assert isinstance(refused, RejectResponse)
    # end def


async def test_resume_of_an_empty_store_holds_no_anomaly() -> None:
    """Resuming at first start is safe: nothing was in flight."""
    host = await AuditHost.resume('tenant-a', repository=InMemoryLedgerRepository(), clock=_Clock())
    assert host.anomalies() == []
    assert host.records() == []
    # end def


async def test_attempt_persistence_failure_fails_closed_and_the_identical_attempt_may_come_again() -> None:
    """A persistence failure on an attempt yields unavailable, seals nothing, and does not block a resend (§7.1)."""
    repo = _FlakyRepository()
    repo.fail = True
    host = AuditHost('tenant-a', repository=repo, clock=_Clock())
    host.open_session(SESSION)
    response = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(response, UnavailableResponse)
    assert host.records() == []

    repo.fail = False
    retry = await host.handle_attempt(_attempt('00000000-0000-4000-8000-000000000001'))
    assert isinstance(retry, AcceptResponse)
    # end def


async def test_outcome_persistence_failure_is_logged_not_flagged(caplog: pytest.LogCaptureFixture) -> None:
    """A persistence failure on an outcome is a completeness gap (§10.8): logged, not a Tier-1 anomaly (§7.6)."""
    repo = _FlakyRepository()
    host = AuditHost('tenant-a', repository=repo, clock=_Clock())
    host.open_session(SESSION)
    event_id = '00000000-0000-4000-8000-000000000001'
    await host.handle_attempt(_attempt(event_id))
    repo.fail = True
    with caplog.at_level(logging.ERROR, logger='auditable_mcp.host'):
        await host.handle_outcome(_attempt(event_id, outcome='success'))
    assert host.anomalies() == []
    assert len(host.records()) == 1
    assert any('could not persist' in record.message for record in caplog.records)
    # end def


async def test_lost_outcome_does_not_advance_the_signer_seq_tracker() -> None:
    """A lost outcome was received but not sealed, so the next value is neither a gap nor a replay (§7.4)."""
    repo = _FlakyRepository()
    host = AuditHost(
        'tenant-a',
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        verifier=_OkVerifier(),
        repository=repo,
        clock=_Clock(),
    )
    host.open_session(SESSION)
    first = '00000000-0000-4000-8000-000000000001'
    assert isinstance(await host.handle_attempt(_signed(_attempt(first), 0)), AcceptResponse)
    repo.fail = True
    await host.handle_outcome(_signed(_attempt(first, outcome='success'), 1))
    repo.fail = False
    second = '00000000-0000-4000-8000-000000000002'
    assert isinstance(await host.handle_attempt(_signed(_attempt(second), 2)), AcceptResponse)
    assert host.anomalies() == []
    # end def


def test_resuming_an_empty_partition_starts_at_genesis() -> None:
    """A host resuming a partition that holds nothing is a fresh chain, not an error."""
    ledger = Ledger('tenant-a')
    ledger.resume_from(None)
    assert ledger.digest() == GENESIS_HASH
    assert len(ledger) == 0
    # end def
