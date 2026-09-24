"""Unit tests for the MCP wire binding: the two §6 methods on a real MCP connection."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import anyio
import pytest
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.models import InitializationOptions
from mcp.shared.memory import create_client_server_memory_streams
from mcp.shared.message import SessionMessage
from mcp.types import (
    METHOD_NOT_FOUND,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ServerCapabilities,
    TextContent,
    Tool,
    ToolsCapability,
)

from auditable_mcp.degradation import transport_for
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.mcp import (
    ATTEMPT_METHOD,
    ID_PREFIX,
    OUTCOME_METHOD,
    HandshakeNotSeenError,
    McpAuditReceiver,
    McpAuditTransport,
    McpBindingError,
    UnnegotiatedSendError,
    audit_extension,
    capability_of,
    declare,
    declare_into,
)
from auditable_mcp.models import (
    SPEC_VERSION,
    AttemptResponse,
    AuditCapability,
    Level,
    TargetResource,
    Witness,
)
from auditable_mcp.session import AmcpAbortedError, AmcpSession
from auditable_mcp.transport import unavailable
from auditable_mcp.verify import verify_ledger

TOOL_CAPABILITY = AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', witness=Witness.NONE)
CALL_TIMEOUT = 5.0

# A Verifiable Accept as it appears on the wire (§7.1).
_ACCEPTED: dict[str, object] = {
    'status': 'accept',
    'seq': 0,
    'record_hash': '0' * 64,
    'host_ts': '2026-07-15T00:00:01.000Z',
    'previous_hash': '0' * 64,
}


class _Clock:
    """A deterministic host clock."""

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


class _FixedDeps:
    """Deterministic id/time source."""

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


class _SilentEndpoint:
    """A host that never answers an attempt, to exercise the bound §6 puts on the wait."""

    def __init__(self) -> None:
        """Declare the same capability an ordinary L1 host would."""
        self.capability = TOOL_CAPABILITY
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Block until cancelled."""
        await anyio.sleep_forever()
        return unavailable()
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Accept and discard."""
        # end def

    # end class


class _RaisingEndpoint:
    """A host whose audit subsystem is defective, to exercise §6's result-not-error rule."""

    def __init__(self) -> None:
        """Declare the same capability an ordinary L1 host would."""
        self.capability = TOOL_CAPABILITY
        self.outcomes = 0
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Fail the way a broken host does."""
        raise RuntimeError('the ledger is on fire')
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Fail the same way, on the channel that cannot answer."""
        self.outcomes += 1
        raise RuntimeError('the ledger is still on fire')
        # end def

    # end class


def _host(**kwargs: object) -> AuditHost:
    """An L1 audit host with a deterministic clock."""
    return AuditHost('tenant-a', TOOL_CAPABILITY, clock=_Clock(), **kwargs)  # type: ignore[arg-type]
    # end def


def _initialize_request(request_id: int = 1, declaring: AuditCapability | None = None) -> SessionMessage:
    """The `initialize` request an MCP client sends; `declaring` stands in for a host seam's injection."""
    capabilities: dict[str, object] = {}
    if declaring is not None:
        declare_into(capabilities, declaring)
        # end if
    return SessionMessage(
        message=JSONRPCMessage(
            JSONRPCRequest(
                jsonrpc='2.0',
                id=request_id,
                method='initialize',
                params={
                    'protocolVersion': '2026-07-28',
                    'capabilities': capabilities,
                    'clientInfo': {'name': 'h', 'version': '1'},
                },
            )
        )
    )
    # end def


async def _settle(predicate: Callable[[], bool]) -> None:
    """Let the pumps run until `predicate` holds, failing rather than hanging if it never does."""
    with anyio.fail_after(CALL_TIMEOUT):
        while not predicate():
            await anyio.sleep(0)
            # end while
        # end with
    # end def


class _Drain:
    """Stands in for a session: reads what the seam passes through and keeps it for inspection."""

    def __init__(self) -> None:
        """Start with nothing seen."""
        self.seen: list[object] = []
        # end def

    async def run(self, stream: object) -> None:
        """Consume the seam's session-side stream until it closes."""
        async for message in stream:  # type: ignore[attr-defined]
            self.seen.append(message)
            # end for
        # end def

    def methods(self) -> list[str]:
        """The JSON-RPC methods that reached the session."""
        return [
            message.message.root.method
            for message in self.seen
            if isinstance(message, SessionMessage) and hasattr(message.message.root, 'method')
        ]
        # end def

    # end class


@asynccontextmanager
async def _seams(
    endpoint: object,
    *,
    request_timeout: float = CALL_TIMEOUT,
) -> AsyncIterator[tuple[McpAuditTransport, McpAuditReceiver, _Drain]]:
    """Two seams facing each other with the handshake done, and no MCP session on either side."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with (
            McpAuditReceiver(client_streams[0], client_streams[1], endpoint) as receiver,  # type: ignore[arg-type]
            McpAuditTransport(
                server_streams[0], server_streams[1], TOOL_CAPABILITY, request_timeout=request_timeout
            ) as transport,
        ):
            tool_side, host_side = _Drain(), _Drain()
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(tool_side.run, transport.read_stream)
                tasks.start_soon(host_side.run, receiver.read_stream)
                await receiver.write_stream.send(_initialize_request())
                await _settle(lambda: transport.handshake_seen)
                yield transport, receiver, tool_side
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


def _build_server(transport: McpAuditTransport | None, fallback: InProcessTransport) -> Server:
    """A tool server whose one tool records the operation it performs, however the session negotiated."""
    server = Server('audited-tool')

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [Tool(name='read_customers', description='read', inputSchema={'type': 'object'})]
        # end def

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, object]) -> list[TextContent]:
        if transport is None:
            chosen: object = fallback
        else:
            chosen = transport_for(transport.negotiate(TOOL_CAPABILITY), negotiated=transport, fallback=fallback)
            # end if
        session = AmcpSession(chosen, 'call-1', deps=_FixedDeps())  # type: ignore[arg-type]
        async with session.action(
            'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
        ):
            pass
            # end async with
        return [TextContent(type='text', text='read 1 row')]
        # end def

    return server
    # end def


@asynccontextmanager
async def _connection(
    endpoint: object | None,
    fallback_host: AuditHost,
) -> AsyncIterator[tuple[ClientSession, McpAuditTransport]]:
    """A live MCP session between a real client and a real server, audited when `endpoint` is given."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY) as transport:
            server = _build_server(transport, InProcessTransport(fallback_host))
            options = InitializationOptions(
                server_name='audited-tool',
                server_version='0.0.0',
                capabilities=ServerCapabilities(tools=ToolsCapability()),
            )
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                if endpoint is None:
                    async with ClientSession(client_streams[0], client_streams[1]) as session:
                        await session.initialize()
                        yield session, transport
                        # end async with
                else:
                    async with McpAuditReceiver(client_streams[0], client_streams[1], endpoint) as receiver:  # type: ignore[arg-type]
                        async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                            await session.initialize()
                            yield session, transport
                            # end async with
                        # end async with
                    # end if
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


class TestDeclaration:
    """§6.1: putting the capability in `extensions` and taking a peer's back out."""

    def test_declare_keeps_the_extensions_a_party_already_had(self) -> None:
        """A party may speak more than one extension, and this one does not displace the others."""
        capabilities = ServerCapabilities(tools=ToolsCapability(), extensions={'org.example/other': {}})
        declared = declare(capabilities, TOOL_CAPABILITY)
        extensions = declared.model_dump(mode='json', exclude_none=True)['extensions']
        assert set(extensions) == {'org.example/other', 'com.timberlandchapel/auditable-mcp'}
        assert capability_of(declared) == TOOL_CAPABILITY
        # end def

    def test_declare_does_not_change_the_capabilities_it_was_given(self) -> None:
        """The caller's object is theirs; a helper that mutated it would declare behind their back."""
        capabilities = ServerCapabilities(tools=ToolsCapability())
        declare(capabilities, TOOL_CAPABILITY)
        assert capability_of(capabilities) is None
        # end def

    def test_the_declaration_is_the_capability_object_itself(self) -> None:
        """[SEP-2133] carries the settings object at the identifier, not a wrapper around it."""
        assert audit_extension(TOOL_CAPABILITY) == {'com.timberlandchapel/auditable-mcp': TOOL_CAPABILITY.to_wire()}
        # end def

    def test_a_peer_that_declared_nothing_reads_as_no_declaration(self) -> None:
        """Which is the ordinary MCP host, and §6.2 rather than a mismatch governs it."""
        assert capability_of(ServerCapabilities()) is None
        assert capability_of({}) is None
        assert capability_of(None) is None
        # end def

    def test_a_declaration_that_does_not_validate_is_not_a_declaration(self) -> None:
        """Reading a malformed settings object as valid would negotiate against something unagreed."""
        assert capability_of({'extensions': {'com.timberlandchapel/auditable-mcp': {'level': 'L1'}}}) is None
        assert capability_of({'extensions': {'com.timberlandchapel/auditable-mcp': 'L1'}}) is None
        # end def

    def test_declare_into_writes_through_a_wire_mapping(self) -> None:
        """The session builds its own capabilities, so the binding declares on the serialized form."""
        capabilities: dict[str, object] = {'roots': {}}
        declare_into(capabilities, TOOL_CAPABILITY)
        assert capability_of(capabilities) == TOOL_CAPABILITY
        assert capabilities['roots'] == {}
        # end def

    # end class


class TestHandshake:
    """§6.1: what each side declares, and what it does before the handshake has happened."""

    async def test_each_side_reads_the_other_s_declaration(self) -> None:
        """The host's requirement reaches the tool without the integrator carrying it there."""
        host = _host()
        async with _seams(host) as (transport, _receiver, _seen):
            assert transport.host_capability == host.capability
            # end async with
        # end def

    async def test_negotiating_before_the_handshake_refuses(self) -> None:
        """An absent declaration and one that has not arrived look alike, and mean opposite things."""
        async with create_client_server_memory_streams() as (_client, server_streams):
            async with McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY) as transport:
                with pytest.raises(HandshakeNotSeenError):
                    transport.negotiate(TOOL_CAPABILITY)
                    # end with
                # end async with
            # end async with
        # end def

    async def test_negotiating_a_capability_that_was_not_declared_refuses(self) -> None:
        """A fit computed against something the host never saw is a fit only the tool believes in."""
        async with _seams(_host()) as (transport, _receiver, _seen):
            with pytest.raises(McpBindingError):
                transport.negotiate(
                    AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', witness=Witness.NONE)
                )
                # end with
            # end async with
        # end def

    # end class


class TestPerEventWire:
    """§6: the two methods, their framing, and what happens when the answer does not come."""

    async def test_an_attempt_is_sealed_and_its_decision_returned(self) -> None:
        """The round trip the whole extension rests on."""
        host = _host()
        async with _seams(host) as (transport, _receiver, _seen):
            transport.negotiate(TOOL_CAPABILITY)
            session = AmcpSession(transport, 'call-1', deps=_FixedDeps())
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pass
                # end async with
            await _settle(lambda: len(host.records()) == 2)
            # end async with
        assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success']
        assert verify_ledger(host.records()).ok
        # end def

    async def test_the_audit_frames_never_reach_the_mcp_session(self) -> None:
        """A session that saw `audit/attempt` would answer it with `method not found` (§6)."""
        host = _host()
        async with _seams(host) as (transport, _receiver, tool_side):
            transport.negotiate(TOOL_CAPABILITY)
            await transport.send_outcome({'ping': 'not an event'})
            await _settle(lambda: len(host.records()) >= 0)
            assert ATTEMPT_METHOD not in tool_side.methods()
            assert OUTCOME_METHOD not in tool_side.methods()
            # end async with
        # end def

    async def test_a_host_that_never_answers_fails_closed(self) -> None:
        """§6 leaves the bound to the transport and requires silence to abort, not to proceed."""
        async with _seams(_SilentEndpoint(), request_timeout=0.05) as (transport, _receiver, _seen):
            transport.negotiate(TOOL_CAPABILITY)
            session = AmcpSession(transport, 'call-1', deps=_FixedDeps())
            with anyio.fail_after(2.0), pytest.raises(AmcpAbortedError) as aborted:
                async with session.action(
                    'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
                ):
                    pytest.fail('the action ran although nothing recorded it')
                    # end async with
                # end with
            assert aborted.value.reason == 'host-unavailable'
            # end async with
        # end def

    async def test_an_endpoint_that_raises_answers_unavailable(self) -> None:
        """§6: every audit-layer decision travels as a result; a defect is `unavailable`, not an error."""
        async with _seams(_RaisingEndpoint()) as (transport, _receiver, _seen):
            transport.negotiate(TOOL_CAPABILITY)
            response = await transport.send_attempt({'event': 'whatever'})
            assert response.status == 'unavailable'
            # end async with
        # end def

    async def test_an_outcome_that_raises_is_not_answered_at_all(self) -> None:
        """A notification has no response channel, and inventing one would change the wire (§6)."""
        endpoint = _RaisingEndpoint()
        async with _seams(endpoint) as (transport, _receiver, _seen):
            transport.negotiate(TOOL_CAPABILITY)
            await transport.send_outcome({'event': 'whatever'})
            await _settle(lambda: endpoint.outcomes == 1)
            # end async with
        # end def

    # end class


@asynccontextmanager
async def _tool_on_a_bare_wire(
    *,
    request_timeout: float = CALL_TIMEOUT,
) -> AsyncIterator[tuple[McpAuditTransport, MemoryObjectReceiveStream, MemoryObjectSendStream, _Drain]]:
    """A tool seam whose peer is this test, reading and writing the JSON-RPC frames directly."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with McpAuditTransport(
            server_streams[0], server_streams[1], TOOL_CAPABILITY, request_timeout=request_timeout
        ) as transport:
            drain = _Drain()
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(drain.run, transport.read_stream)
                await client_streams[1].send(_initialize_request(declaring=TOOL_CAPABILITY))
                await _settle(lambda: transport.handshake_seen)
                transport.negotiate(TOOL_CAPABILITY)
                yield transport, client_streams[0], client_streams[1], drain
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


async def _attempt(transport: McpAuditTransport, event: dict[str, object], into: list[AttemptResponse]) -> None:
    """Send one attempt from a task, keeping the decision for the test to assert on."""
    into.append(await transport.send_attempt(event))
    # end def


def _respond(request_id: str | int, result: dict[str, object]) -> SessionMessage:
    """A JSON-RPC result for one audit request."""
    return SessionMessage(message=JSONRPCMessage(JSONRPCResponse(jsonrpc='2.0', id=request_id, result=result)))
    # end def


class TestWireForm:
    """§6: the literal shapes this extension puts on the connection."""

    async def test_an_outcome_is_a_notification_carrying_the_event_itself(self) -> None:
        """`params` IS the audit event object, not a wrapper, and there is nothing to respond to."""
        event: dict[str, object] = {'event_id': 'e1', 'outcome': 'success'}
        async with _tool_on_a_bare_wire() as (transport, peer_read, _peer_write, _seen):
            await transport.send_outcome(event)
            frame = (await peer_read.receive()).message.root
            # end async with
        assert isinstance(frame, JSONRPCNotification)
        assert frame.method == OUTCOME_METHOD
        assert frame.params == event
        # end def

    async def test_an_attempt_is_one_request_under_an_id_the_session_cannot_reach(self) -> None:
        """An MCP session numbers its own requests with integers; a collision would cross the two."""
        event: dict[str, object] = {'event_id': 'e1', 'outcome': 'attempted'}
        decisions: list[AttemptResponse] = []
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(_attempt, transport, event, decisions)
                frame = (await peer_read.receive()).message.root
                assert isinstance(frame, JSONRPCRequest)
                assert frame.method == ATTEMPT_METHOD
                assert frame.params == event
                assert isinstance(frame.id, str)
                assert frame.id.startswith(ID_PREFIX)
                await peer_write.send(_respond(frame.id, _ACCEPTED))
                # end async with
            # end async with
        assert decisions[0].status == 'accept'
        # end def

    async def test_a_json_rpc_error_for_an_attempt_is_read_as_a_failure_to_record(self) -> None:
        """§6 reserves errors for protocol faults and requires the tool to fail closed on one."""
        decisions: list[AttemptResponse] = []
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            with anyio.fail_after(1.0):
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(_attempt, transport, {'event_id': 'e1'}, decisions)
                    frame = (await peer_read.receive()).message.root
                    error = JSONRPCError(
                        jsonrpc='2.0', id=frame.id, error=ErrorData(code=METHOD_NOT_FOUND, message='unknown method')
                    )
                    await peer_write.send(SessionMessage(message=JSONRPCMessage(error)))
                    # end async with
                # end with
            # end async with
        assert decisions[0].status == 'unavailable'
        # end def

    async def test_an_error_beside_a_result_is_still_an_error(self) -> None:
        """A frame carrying both is not valid JSON-RPC, and reading the result would clear an operation."""
        decisions: list[AttemptResponse] = []
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            with anyio.fail_after(1.0):
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(_attempt, transport, {'event_id': 'e1'}, decisions)
                    frame = (await peer_read.receive()).message.root
                    both = JSONRPCResponse(
                        jsonrpc='2.0',
                        id=frame.id,
                        result=_ACCEPTED,
                        error={'code': -32601, 'message': 'unknown method'},
                    )
                    await peer_write.send(SessionMessage(message=JSONRPCMessage(both)))
                    # end async with
                # end with
            # end async with
        assert decisions[0].status == 'unavailable'
        # end def

    async def test_a_decision_the_tool_cannot_read_is_a_decision_it_did_not_get(self) -> None:
        """A result that does not validate leaves the tool with nothing recorded, which is `unavailable`."""
        decisions: list[AttemptResponse] = []
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            with anyio.fail_after(1.0):
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(_attempt, transport, {'event_id': 'e1'}, decisions)
                    frame = (await peer_read.receive()).message.root
                    await peer_write.send(_respond(frame.id, {'status': 'yes'}))
                    # end async with
                # end with
            # end async with
        assert decisions[0].status == 'unavailable'
        # end def

    # end class


class TestClosing:
    """What becomes of an attempt the connection can no longer answer (§7.2)."""

    async def test_an_attempt_in_flight_when_the_seam_closes_fails_closed(self) -> None:
        """A closed connection will not answer, and a tool left waiting would never record or abort."""
        decisions: list[AttemptResponse] = []
        drain = _Drain()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            transport = McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY)
            with anyio.fail_after(2.0):
                async with anyio.create_task_group() as tasks:
                    async with transport:
                        tasks.start_soon(drain.run, transport.read_stream)
                        await client_streams[1].send(_initialize_request(declaring=TOOL_CAPABILITY))
                        await _settle(lambda: transport.handshake_seen)
                        transport.negotiate(TOOL_CAPABILITY)
                        tasks.start_soon(_attempt, transport, {'event_id': 'e1'}, decisions)
                        # The attempt is on the wire and unanswered when the seam closes under it.
                        await client_streams[0].receive()
                        # end async with
                    await _settle(lambda: len(decisions) == 1)
                    # end async with
                # end with
            # end async with
        assert decisions[0].status == 'unavailable'
        # end def

    async def test_an_attempt_after_the_seam_closed_fails_closed_too(self) -> None:
        """There is no connection left to carry it, and the tool still has to be told in §7.2's terms."""
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            transport = McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY)
            async with anyio.create_task_group() as tasks:
                async with transport:
                    tasks.start_soon(_Drain().run, transport.read_stream)
                    await client_streams[1].send(_initialize_request(declaring=TOOL_CAPABILITY))
                    await _settle(lambda: transport.handshake_seen)
                    transport.negotiate(TOOL_CAPABILITY)
                    # end async with
                with anyio.fail_after(2.0):
                    assert (await transport.send_attempt({'event_id': 'e1'})).status == 'unavailable'
                    await transport.send_outcome({'event_id': 'e1'})
                    # end with
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end def

    # end class


@asynccontextmanager
async def _host_on_a_bare_wire(
    endpoint: object,
) -> AsyncIterator[tuple[MemoryObjectReceiveStream, MemoryObjectSendStream, _Drain]]:
    """A host seam whose peer is this test, so malformed audit traffic can be put on the wire."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with McpAuditReceiver(client_streams[0], client_streams[1], endpoint) as receiver:  # type: ignore[arg-type]
            drain = _Drain()
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(drain.run, receiver.read_stream)
                yield server_streams[0], server_streams[1], drain
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


class TestMalformedAuditTraffic:
    """§6: the two shapes the audit methods must not take, and what the host does with them."""

    async def test_an_outcome_sent_as_a_request_is_refused_and_not_sealed(self) -> None:
        """The outcome channel is a notification; a request is a malformed envelope, which is an error."""
        host = _host()
        async with _host_on_a_bare_wire(host) as (peer_read, peer_write, session_saw):
            request = JSONRPCRequest(jsonrpc='2.0', id=7, method=OUTCOME_METHOD, params={'event_id': 'e1'})
            await peer_write.send(SessionMessage(message=JSONRPCMessage(request)))
            with anyio.fail_after(1.0):
                frame = (await peer_read.receive()).message.root
                # end with
            # end async with
        assert isinstance(frame, JSONRPCError)
        assert frame.id == 7
        assert OUTCOME_METHOD not in session_saw.methods()
        assert not host.records()
        # end def

    async def test_an_attempt_sent_as_a_notification_is_dropped(self) -> None:
        """It has no response channel, so sealing it would record an operation never cleared (§6)."""
        host = _host()
        async with _host_on_a_bare_wire(host) as (peer_read, peer_write, session_saw):
            notification = JSONRPCNotification(jsonrpc='2.0', method=ATTEMPT_METHOD, params={'event_id': 'e1'})
            await peer_write.send(SessionMessage(message=JSONRPCMessage(notification)))
            # A well-formed attempt behind it: the first frame back proves what the notification produced.
            request = JSONRPCRequest(jsonrpc='2.0', id='amcp-1', method=ATTEMPT_METHOD, params={'event_id': 'e1'})
            await peer_write.send(SessionMessage(message=JSONRPCMessage(request)))
            with anyio.fail_after(1.0):
                frame = (await peer_read.receive()).message.root
                # end with
            # end async with
        assert isinstance(frame, JSONRPCResponse)
        assert frame.id == 'amcp-1'
        assert frame.result['status'] == 'reject'
        # An MCP session cannot parse it either: passing it on would end the connection over a frame
        # this extension put there, which is the opposite of serving an unnegotiated peer (§6.2).
        assert ATTEMPT_METHOD not in session_saw.methods()
        assert not host.records()
        # end def

    # end class


class TestSendGate:
    """§6.2: a tool sends nothing until a comparison has succeeded."""

    async def test_a_transport_that_has_not_negotiated_refuses_to_send(self) -> None:
        """The MUST NOT of §6.2 is the one rule a peer cannot enforce for the tool."""
        async with _seams(_host()) as (transport, _receiver, _seen):
            with pytest.raises(UnnegotiatedSendError):
                await transport.send_attempt({'event': 'whatever'})
                # end with
            with pytest.raises(UnnegotiatedSendError):
                await transport.send_outcome({'event': 'whatever'})
                # end with
            # end async with
        # end def

    async def test_a_mismatch_closes_the_send_path_again(self) -> None:
        """Negotiating and not fitting leaves the session unnegotiated, exactly as declaring nothing does."""
        host = AuditHost(
            'tenant-a',
            AuditCapability(spec_version='auditable-mcp/0.1', level=Level.L1, attempt='request', witness=Witness.NONE),
            clock=_Clock(),
        )
        async with _seams(host) as (transport, _receiver, _seen):
            assert not transport.negotiate(TOOL_CAPABILITY).negotiated
            with pytest.raises(UnnegotiatedSendError):
                await transport.send_attempt({'event': 'whatever'})
                # end with
            # end async with
        # end def

    # end class


class TestOverALiveMcpSession:
    """The binding against the official client and server, doing ordinary MCP at the same time."""

    async def test_a_tool_call_is_served_and_its_interior_recorded(self) -> None:
        """What the extension exists for: the call returns normally and the host holds the operations."""
        wire_host, tool_local = _host(), _host()
        async with _connection(wire_host, tool_local) as (session, _transport):
            result = await session.call_tool('read_customers', {})
            assert not result.isError
            assert [record.event['outcome'] for record in wire_host.records()] == ['attempted', 'success']
            assert not tool_local.records(), 'the session negotiated, so nothing degraded'
            # end async with
        # end def

    async def test_ordinary_mcp_still_works_around_the_audit_traffic(self) -> None:
        """§6.2: what the tool does and reports MUST NOT differ because this extension is present."""
        async with _connection(_host(), _host()) as (session, _transport):
            assert [tool.name for tool in (await session.list_tools()).tools] == ['read_customers']
            await session.call_tool('read_customers', {})
            await session.send_ping()
            # end async with
        # end def

    async def test_the_tool_declares_the_extension_the_session_never_heard_of(self) -> None:
        """The MCP session builds the `initialize` result; the binding is what puts the declaration in it."""
        async with _connection(_host(), _host()) as (session, _transport):
            result = await session.initialize()
            assert capability_of(result.capabilities) == TOOL_CAPABILITY
            # end async with
        # end def

    async def test_an_ordinary_host_gets_an_ordinary_tool_and_no_audit_frame(self) -> None:
        """The case §6.2 exists for: nearly every MCP host today, and the tool stays usable by it."""
        tool_local = _host()
        async with _connection(None, tool_local) as (session, transport):
            result = await session.call_tool('read_customers', {})
            assert not result.isError
            assert not transport.negotiate(TOOL_CAPABILITY).negotiated
            assert [record.event['outcome'] for record in tool_local.records()] == ['attempted', 'success']
            assert all(record.host_signature is None for record in tool_local.records())
            # end async with
        # end def

    # end class


def _tools_call(request_id: str | int) -> SessionMessage:
    """A `tools/call` request, the parent §4's `call_id` names."""
    return SessionMessage(
        message=JSONRPCMessage(JSONRPCRequest(jsonrpc='2.0', id=request_id, method='tools/call', params={}))
    )
    # end def


class TestAuditFramesRideTheCall:
    """§4, §6: the audit frames name the `tools/call` they belong to."""

    async def test_it_names_the_request_in_flight_in_the_form_the_transport_routes_on(self) -> None:
        """§4 carries a numeric id as its decimal string; the transport routes on the number it was."""
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            await peer_write.send(_tools_call(42))
            await _settle(lambda: 'tools/call' in session_saw.methods())
            await transport.send_outcome({'call_id': '42', 'outcome': 'success'})
            with anyio.fail_after(1.0):
                message = await peer_read.receive()
                # end with
            # end async with
        assert message.metadata is not None
        assert message.metadata.related_request_id == 42
        # end def

    async def test_it_keeps_a_string_id_a_string(self) -> None:
        """A host may use string ids, and they are a different key to the transport."""
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            await peer_write.send(_tools_call('call-abc'))
            await _settle(lambda: 'tools/call' in session_saw.methods())
            await transport.send_outcome({'call_id': 'call-abc', 'outcome': 'success'})
            with anyio.fail_after(1.0):
                message = await peer_read.receive()
                # end with
            # end async with
        assert message.metadata is not None
        assert message.metadata.related_request_id == 'call-abc'
        # end def

    async def test_it_names_nothing_when_the_call_is_no_longer_in_flight(self) -> None:
        """An outcome that arrives after the session answered the call has no stream to ride."""
        async with _tool_on_a_bare_wire() as (transport, peer_read, peer_write, session_saw):
            await peer_write.send(_tools_call(42))
            await _settle(lambda: 'tools/call' in session_saw.methods())
            # The session answers the call, so the request leaves flight.
            answer = JSONRPCResponse(jsonrpc='2.0', id=42, result={'content': []})
            await transport.write_stream.send(SessionMessage(message=JSONRPCMessage(answer)))
            with anyio.fail_after(1.0):
                await peer_read.receive()
                # end with
            await transport.send_outcome({'call_id': '42', 'outcome': 'success'})
            with anyio.fail_after(1.0):
                message = await peer_read.receive()
                # end with
            # end async with
        assert message.metadata is None
        # end def

    # end class
