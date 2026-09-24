"""Unit tests for §7.4 atomic numbering: what concurrent Level-2 actions tell the host."""

import asyncio

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import KeyRegistry, KeyRegistryVerifier, generate_tool_key, sign_event
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Level, TargetResource, Witness
from auditable_mcp.session import AmcpAbortedError, AmcpSession

L2 = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', witness=Witness.NONE)
CONCURRENT = 4


class _UnevenSigner:
    """Takes `signer_seq`, then awaits unevenly - the shape of every remote signer (§5.1 KMS).

    The even-numbered events take longer, so left alone the odd ones overtake them and the tool emits
    in the opposite order to the one it numbered.
    """

    def __init__(self, key: object) -> None:
        """Bind the key and start the sequence at zero."""
        self._key = key
        self._next = 0
        # end def

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Number, wait as a remote signer does, then sign."""
        signer_seq = self._next
        self._next += 1
        await asyncio.sleep(0.01 if signer_seq % 2 == 0 else 0.0)
        return sign_event(event, self._key.key_id, signer_seq, self._key.private_key)  # type: ignore[attr-defined]
        # end def

    # end class


class _UnhashableSigner:
    """A signer that cannot key its own lock, so §7.4's section cannot be held for it."""

    __hash__ = None  # type: ignore[assignment]

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Never reached: the session refuses to be constructed."""
        return event
        # end def

    # end class


def _l2_host() -> tuple[AuditHost, object]:
    """An L2 host that verifies against a registry holding one tool key."""
    key = generate_tool_key('tool-1')
    registry = KeyRegistry()
    registry.register_tool_key(key)
    return AuditHost('tenant-a', L2, verifier=KeyRegistryVerifier(registry)), key
    # end def


async def _run(session: AmcpSession, n: int) -> str:
    """Run one audited action and report how it ended."""
    try:
        async with session.action(
            f'db.read{n}', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
        ):
            pass
            # end async with
    except AmcpAbortedError as aborted:
        return f'aborted:{aborted.reason}'
        # end try
    return 'ok'
    # end def


async def test_concurrent_actions_emit_in_the_order_they_were_numbered() -> None:
    """§7.4: a tool that numbers 1 and 2 and emits 2 first tells the host its own event is a replay."""
    host, key = _l2_host()
    session = AmcpSession(InProcessTransport(host), 'call-1', signer=_UnevenSigner(key))
    results = await asyncio.gather(*(_run(session, n) for n in range(CONCURRENT)))
    assert results == ['ok'] * CONCURRENT, 'a legitimate operation was refused'
    sealed = [record.event['signer_seq'] for record in host.records()]
    assert sealed == list(range(CONCURRENT * 2)), 'the host did not see the order the tool numbered'
    assert not host.anomalies(), 'the ledger records the tool as having replayed its own events'
    # end def


async def test_sessions_sharing_one_signer_share_the_section() -> None:
    """`signer_seq` is per `key_id`, and one tool serves many `tools/call`s with one key."""
    host, key = _l2_host()
    signer = _UnevenSigner(key)
    sessions = [AmcpSession(InProcessTransport(host), f'call-{n}', signer=signer) for n in range(2)]
    results = await asyncio.gather(*(_run(sessions[n % 2], n) for n in range(CONCURRENT)))
    assert results == ['ok'] * CONCURRENT
    assert [record.event['signer_seq'] for record in host.records()] == list(range(CONCURRENT * 2))
    assert not host.anomalies()
    # end def


async def test_terminal_outcomes_are_numbered_and_emitted_in_one_order() -> None:
    """§7.4 counts attempts AND outcomes, so the outcome path is inside the same section."""
    host, key = _l2_host()
    session = AmcpSession(InProcessTransport(host), 'call-1', signer=_UnevenSigner(key))
    released = asyncio.Event()

    async def held(n: int) -> str:
        """Hold the block until every attempt is in, so only the outcomes race."""
        try:
            async with session.action(
                f'db.read{n}', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                await released.wait()
                # end async with
        except AmcpAbortedError as aborted:
            return f'aborted:{aborted.reason}'
            # end try
        return 'ok'
        # end def

    running = [asyncio.create_task(held(n)) for n in range(CONCURRENT)]
    while len(host.records()) < CONCURRENT:
        await asyncio.sleep(0)
        # end while
    released.set()
    assert await asyncio.gather(*running) == ['ok'] * CONCURRENT
    assert [record.event['signer_seq'] for record in host.records()] == list(range(CONCURRENT * 2))
    assert not host.anomalies()
    # end def


async def test_a_level_1_session_is_not_serialized() -> None:
    """Level 1 numbers nothing, so §7.4 asks for no section and concurrency keeps its value."""
    host = AuditHost('tenant-a')
    session = AmcpSession(InProcessTransport(host), 'call-1')
    assert await asyncio.gather(*(_run(session, n) for n in range(CONCURRENT))) == ['ok'] * CONCURRENT
    assert len(host.records()) == CONCURRENT * 2
    # end def


def test_a_signer_that_cannot_key_its_own_lock_is_refused() -> None:
    """The section is held per signer, so a signer with value equality is refused at construction."""
    host = AuditHost('tenant-a', L2, verifier=KeyRegistryVerifier(KeyRegistry()))
    with pytest.raises(TypeError):
        AmcpSession(InProcessTransport(host), 'call-1', signer=_UnhashableSigner())  # type: ignore[arg-type]
        # end with
    # end def
