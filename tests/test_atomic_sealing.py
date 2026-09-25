"""Unit tests for §7.1 atomic sealing: what concurrent seals do to one partition's chain."""

import asyncio

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Countersign, Level
from auditable_mcp.verify import verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'

CAPABILITY = AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE)
COUNTERSIGNING = AuditCapability(
    spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.HOST
)
CONCURRENT = 5


class _SlowRepository:
    """A store that yields to the loop before it writes, as any real one does."""

    def __init__(self) -> None:
        """Start with nothing stored."""
        self.rows: list[SealedRecord] = []
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Yield once, then store."""
        await asyncio.sleep(0)
        self.rows.append(record)
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """No persisted tail."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Return what was stored."""
        return list(self.rows)
        # end def

    # end class


class _SlowSigner:
    """A countersign signer that yields to the loop, as an HSM or KMS client does."""

    key_id = 'host-key-1'

    async def sign(self, payload: bytes) -> str:
        """Yield once, then return a fixed signature."""
        await asyncio.sleep(0)
        return 'AAAA'
        # end def

    # end class


def _attempt(n: int) -> dict[str, object]:
    """A valid attempt event with a distinct id."""
    return {
        'id': f'00000000-0000-4000-8000-{n:012x}',
        'spec_version': SPEC_VERSION,
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    # end def


async def _seal_concurrently(host: AuditHost, count: int = CONCURRENT) -> list[SealedRecord]:
    """Send `count` attempts at once and return what the partition holds afterwards."""
    await asyncio.gather(*(host.handle_attempt(_attempt(n)) for n in range(1, count + 1)))
    return host.records()
    # end def


def _assert_chain_holds(records: list[SealedRecord]) -> None:
    """Every §7.1 consequence of atomic sealing, read off the ledger."""
    assert len(records) == CONCURRENT
    seqs = [record.seq for record in records]
    assert seqs == sorted(seqs), 'the chain is not in sequence order'
    assert len(set(seqs)) == CONCURRENT, 'two records took the same seq (§7.1)'
    previous = [record.previous_hash for record in records]
    assert len(set(previous)) == CONCURRENT, 'two records claim the same predecessor (§7.1)'
    assert verify_ledger(records).ok, 'the chain does not verify'
    # end def


async def test_a_durable_host_seals_concurrent_attempts_atomically() -> None:
    """Persistence sits between taking a position and committing it, which is the window (§7.1)."""
    host = AuditHost('tenant-a', CAPABILITY, repository=_SlowRepository())
    host.open_session(SESSION)
    _assert_chain_holds(await _seal_concurrently(host))
    # end def


async def test_a_countersigning_host_seals_concurrent_attempts_atomically() -> None:
    """So does signing: an HSM call is the same window, and the one production hosts always have."""
    host = AuditHost('tenant-a', COUNTERSIGNING, countersigner=_SlowSigner())
    host.open_session(SESSION)
    _assert_chain_holds(await _seal_concurrently(host))
    # end def


async def test_an_in_memory_host_seals_concurrent_attempts_atomically() -> None:
    """The configuration with no window of its own must not acquire one either."""
    host = AuditHost('tenant-a', CAPABILITY)
    host.open_session(SESSION)
    _assert_chain_holds(await _seal_concurrently(host))
    # end def


async def test_concurrent_duplicates_do_not_both_pass_the_uniqueness_check() -> None:
    """§7.1 forbids sealing a second attempt record for an `id`, and the check reads shared state.

    The duplicates are byte-identical, so every one of them is answered with the one accept.
    """
    host = AuditHost('tenant-a', CAPABILITY, repository=_SlowRepository())
    host.open_session(SESSION)
    event = _attempt(1)
    responses = await asyncio.gather(*(host.handle_attempt(dict(event)) for _ in range(CONCURRENT)))
    assert len(host.records()) == 1, 'a duplicate attempt id was sealed more than once'
    assert all(response == responses[0] for response in responses)
    assert responses[0].status == 'accept'
    # end def


async def test_partitions_are_not_serialized_against_each_other() -> None:
    """§7.1 constrains one partition; §10.5 keeps them independent, and so must the lock."""
    hosts = [AuditHost(f'tenant-{n}', CAPABILITY, repository=_SlowRepository()) for n in range(3)]
    for host in hosts:
        host.open_session(SESSION)
        # end for
    await asyncio.gather(*(_seal_concurrently(host) for host in hosts))
    for host in hosts:
        _assert_chain_holds(host.records())
        # end for
    # end def


@pytest.mark.parametrize('outcome', ['success', 'failed'])
async def test_outcomes_seal_into_the_same_chain_atomically(outcome: str) -> None:
    """An outcome takes a position in the same chain, so it is in the same section (§8.3)."""
    host = AuditHost('tenant-a', CAPABILITY, repository=_SlowRepository())
    host.open_session(SESSION)
    await _seal_concurrently(host)
    await asyncio.gather(*(host.handle_outcome({**_attempt(n), 'outcome': outcome}) for n in range(1, CONCURRENT + 1)))
    records = host.records()
    assert len(records) == CONCURRENT * 2
    assert len({record.seq for record in records}) == CONCURRENT * 2
    assert verify_ledger(records).ok
    # end def
