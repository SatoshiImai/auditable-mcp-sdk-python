"""Unit tests for §7.4 atomic numbering: what concurrent Level-2 actions tell the host."""

import asyncio

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import KeyRegistry, KeyRegistryVerifier, generate_tool_key, sign_event
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Countersign, Level, TargetResource
from auditable_mcp.session import AmcpAbortedError, AmcpSession

L2 = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE)
CONCURRENT = 4


class _UnevenSigner:
    """Takes `signer_seq`, then awaits unevenly - the shape of every remote signer (§5.1 KMS).

    The even-numbered events take longer, so left alone the odd ones overtake them and the tool emits
    in the opposite order to the one it numbered.
    """

    def __init__(self, key: object) -> None:
        """Bind the key."""
        self._key = key
        # end def

    @property
    def key_id(self) -> str:
        """The key this signer stamps, which names the sequence it advances."""
        return self._key.key_id  # type: ignore[attr-defined,no-any-return]
        # end def

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Wait as a remote signer does, then sign the number the section holds."""
        await asyncio.sleep(0.01 if signer_seq % 2 == 0 else 0.0)
        return sign_event(event, self._key.key_id, signer_seq, self._key.private_key)  # type: ignore[attr-defined]
        # end def

    # end class


class _UnhashableSigner:
    """A signer with value equality and no identity hash."""

    __hash__ = None  # type: ignore[assignment]
    key_id = 'k1'

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
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
    session = AmcpSession(InProcessTransport(host), host.open_session(), signer=_UnevenSigner(key))
    results = await asyncio.gather(*(_run(session, n) for n in range(CONCURRENT)))
    assert results == ['ok'] * CONCURRENT, 'a legitimate operation was refused'
    sealed = [record.event['signer_seq'] for record in host.records()]
    assert sealed == list(range(CONCURRENT * 2)), 'the host did not see the order the tool numbered'
    assert not host.anomalies(), 'the ledger records the tool as having replayed its own events'
    # end def


async def test_sessions_sharing_one_signer_number_independently() -> None:
    """`signer_seq` is per key within a session (§7.4), so concurrent calls under one key share nothing."""
    host, key = _l2_host()
    signer = _UnevenSigner(key)
    sessions = [AmcpSession(InProcessTransport(host), host.open_session(), signer=signer) for n in range(2)]
    results = await asyncio.gather(*(_run(sessions[n % 2], n) for n in range(CONCURRENT)))
    assert results == ['ok'] * CONCURRENT
    for session in sessions:
        numbers = [r.event['signer_seq'] for r in host.records() if r.event['session_id'] == session.session_id]
        assert numbers == list(range(CONCURRENT)), 'each session is numbered from 0, in the order it emitted'
        # end for
    assert not host.anomalies()
    # end def


async def test_terminal_outcomes_are_numbered_and_emitted_in_one_order() -> None:
    """§7.4 counts attempts AND outcomes, so the outcome path is inside the same section."""
    host, key = _l2_host()
    session = AmcpSession(InProcessTransport(host), host.open_session(), signer=_UnevenSigner(key))
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
    session = AmcpSession(InProcessTransport(host), host.open_session())
    assert await asyncio.gather(*(_run(session, n) for n in range(CONCURRENT))) == ['ok'] * CONCURRENT
    assert len(host.records()) == CONCURRENT * 2
    # end def


async def test_a_signer_per_call_from_one_stored_key_needs_no_shared_count() -> None:
    """§7.4's sequence belongs to the session, so building a signer per call from one key is safe.

    Each call's events are 0 and 1, and neither host view nor verifier reads the second call as a replay.
    """
    host, key = _l2_host()
    first = AmcpSession(InProcessTransport(host), host.open_session(), signer=_UnevenSigner(key))
    second = AmcpSession(InProcessTransport(host), host.open_session(), signer=_UnevenSigner(key))
    assert [await _run(first, 0), await _run(second, 1)] == ['ok', 'ok']
    assert [record.event['signer_seq'] for record in host.records()] == [0, 1, 0, 1]
    assert not host.anomalies()
    # end def


def test_an_unhashable_signer_is_accepted() -> None:
    """The sequence lives in the session, so a signer with value equality needs no identity hash."""
    host = AuditHost('tenant-a', L2, verifier=KeyRegistryVerifier(KeyRegistry()))
    AmcpSession(InProcessTransport(host), host.open_session(), signer=_UnhashableSigner())  # type: ignore[arg-type]
    # end def
