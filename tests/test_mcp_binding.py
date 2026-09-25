"""The MCP bindings: the §6 exchange on a real MCP connection, under §6.5 and under §6.4."""

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import anyio
import pytest
from anyio.streams.memory import MemoryObjectReceiveStream
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import MCPError
from mcp.shared.memory import create_client_server_memory_streams
from mcp.shared.message import SessionMessage
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    CallToolRequestParams,
    CallToolResult,
    JSONRPCError,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ListToolsResult,
    PaginatedRequestParams,
    ServerCapabilities,
    TextContent,
    Tool,
    ToolsCapability,
)

from auditable_mcp.degradation import transport_for
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
    generate_tool_key,
)
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.mcp import (
    ATTEMPT_METHOD,
    MAX_ROUNDS_PER_CALL,
    OUTCOME_METHOD,
    McpAuditCall,
    McpAuditReceiver,
    McpAuditTransport,
    McpBindingError,
    UnknownCallError,
    UnnegotiatedSendError,
    audit_extension,
    capability_of,
    declare,
    declare_into,
)
from auditable_mcp.mcp import seam as seam_module
from auditable_mcp.models import (
    EXTENSION_ID,
    SPEC_VERSION,
    AuditCapability,
    Countersign,
    Level,
    TargetResource,
)
from auditable_mcp.session import AmcpAbortedError, AmcpSession, EventSigner
from auditable_mcp.transport import reject, unavailable
from auditable_mcp.verify import verify_ledger

TOOL_CAPABILITY = AuditCapability(
    spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE
)
CALL_TIMEOUT = 5.0


class _Clock:
    """A deterministic host clock."""

    def __init__(self) -> None:
        """Start the counter at the first tick."""
        self._tick = 0
        # end def

    def now(self) -> str:
        """Return the next fixed timestamp."""
        self._tick += 1
        return f'2026-07-15T00:{self._tick // 60:02d}:{self._tick % 60:02d}.000Z'
        # end def

    # end class


def _host(capability: AuditCapability = TOOL_CAPABILITY, **kwargs: Any) -> AuditHost:
    """An audit host with a deterministic clock."""
    return AuditHost('tenant-a', capability, clock=_Clock(), **kwargs)
    # end def


class _Tool:
    """How the tool under test serves `tools/call`, and what it saw."""

    def __init__(
        self,
        declares: AuditCapability = TOOL_CAPABILITY,
        *,
        operations: int = 1,
        signer: EventSigner | None = None,
        countersignature_registry: KeyRegistry | None = None,
    ) -> None:
        """Serve `operations` concurrent audited reads per call, under `declares`."""
        self.declares = declares
        self.operations = operations
        self.signer = signer
        self.countersignature_registry = countersignature_registry
        own = declares.model_copy(update={'countersign': Countersign.NONE})
        self.fallback = _host(own, verifier=None if declares.level == Level.L1 else _ANY_KEY)
        self.performed = 0
        self.negotiated: list[bool] = []
        self.sessions: list[str] = []
        # What the handler saw when it tried to send on a call that was not negotiated (§6.2).
        self.refused: list[type[Exception]] = []
        # end def

    # end class


class _AnyKey:
    """Accepts any signature: the tool's own fallback host is not what these tests are about."""

    async def verify(self, event: dict[str, object]) -> None:
        """Nothing to refuse."""
        # end def

    # end class


_ANY_KEY = _AnyKey()


def _build_server(transport: McpAuditTransport, tool: _Tool) -> Server:
    """A tool server whose one tool records the operations it performs, however the call negotiated."""
    server = Server('audited-tool')

    async def list_tools(_context: object, _params: PaginatedRequestParams) -> ListToolsResult:
        return ListToolsResult(tools=[Tool(name='read_customers', description='read', inputSchema={'type': 'object'})])
        # end def

    async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
        call = transport.call(context.request_id)
        negotiation = call.negotiate(tool.declares)
        tool.negotiated.append(negotiation.negotiated)
        tool.sessions.append(call.session_id)
        if not negotiation.negotiated:
            for send in (call.send_attempt, call.send_outcome):
                try:
                    await send({})
                except UnnegotiatedSendError as error:
                    tool.refused.append(type(error))
                    # end try
                # end for
            # end if
        verifier = (
            CountersignatureRegistryVerifier(tool.countersignature_registry)
            if tool.countersignature_registry is not None
            else None
        )
        chosen = transport_for(negotiation, negotiated=call, fallback=InProcessTransport(tool.fallback))
        if chosen is not call:
            tool.fallback.open_session(call.session_id)
            # end if
        session = AmcpSession(
            chosen,
            call.session_id,
            signer=tool.signer,
            countersignature_verifier=verifier,
            require_countersign=tool.declares.countersign == Countersign.HOST,
        )

        async def operation(n: int) -> None:
            async with session.action(
                'db.read', TargetResource(kind='table', ref=f'customers_{n}'), mutates=False, egress=False
            ):
                tool.performed += 1
                # end async with
            # end def

        aborted: list[str] = []
        try:
            async with anyio.create_task_group() as operations:
                for n in range(tool.operations):
                    operations.start_soon(operation, n)
                    # end for
                # end async with
        except* AmcpAbortedError as group:
            aborted = sorted({error.reason for error in group.exceptions if isinstance(error, AmcpAbortedError)})
        finally:
            if chosen is not call:
                await tool.fallback.close_session(call.session_id)
                # end if
            # end try
        if aborted:
            return CallToolResult(content=[TextContent(type='text', text=f'aborted: {aborted}')], isError=True)
            # end if
        return CallToolResult(content=[TextContent(type='text', text=f'read {tool.operations} rows')])
        # end def

    server.add_request_handler('tools/list', PaginatedRequestParams, list_tools)  # type: ignore[arg-type]
    server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
    return server
    # end def


@asynccontextmanager
async def _connection(
    endpoint: AuditHost | None,
    tool: _Tool,
    *,
    modern: bool,
    request_timeout: float = CALL_TIMEOUT,
) -> AsyncIterator[tuple[ClientSession, McpAuditTransport]]:
    """A live MCP session, under 2026-07-28 (`modern`) or `initialize`, audited when `endpoint` is given."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with McpAuditTransport(
            server_streams[0], server_streams[1], tool.declares, request_timeout=request_timeout
        ) as transport:
            server = _build_server(transport, tool)
            options = InitializationOptions(
                server_name='audited-tool',
                server_version='0.0.0',
                capabilities=ServerCapabilities(tools=ToolsCapability()),
            )
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                if endpoint is None:
                    async with ClientSession(client_streams[0], client_streams[1]) as session:
                        await (session.discover() if modern else session.initialize())
                        yield session, transport
                        # end async with
                else:
                    async with McpAuditReceiver(
                        client_streams[0], client_streams[1], endpoint, request_timeout=request_timeout
                    ) as receiver:
                        async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                            await (session.discover() if modern else session.initialize())
                            yield session, transport
                            # end async with
                        # end async with
                    # end if
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


async def _call(session: ClientSession) -> CallToolResult:
    """Call the tool, bounded."""
    with anyio.fail_after(CALL_TIMEOUT):
        return await session.call_tool('read_customers', {})
        # end with
    # end def


async def _settle(predicate: Callable[[], bool]) -> None:
    """Let the pumps run until `predicate` holds, failing rather than hanging if it never does."""
    with anyio.fail_after(CALL_TIMEOUT):
        while not predicate():
            await anyio.sleep(0)
            # end while
        # end with
    # end def


def _l2(countersign: Countersign = Countersign.NONE) -> AuditCapability:
    """A Level-2 capability."""
    return AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=countersign)
    # end def


BINDINGS = pytest.mark.parametrize('modern', [True, False], ids=['section-6.4-mrtr', 'section-6.5-initialize'])


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


class TestBothBindings:
    """What holds under §6.4 and §6.5 alike: the same records, from the same tool code."""

    @BINDINGS
    async def test_an_audited_call_seals_its_attempt_and_outcome_under_the_hosts_session(self, modern: bool) -> None:
        """The host issued the session; the tool carried it; the call ended with nothing unresolved (§6.3)."""
        host, tool = _host(), _Tool()
        async with _connection(host, tool, modern=modern) as (session, _transport):
            result = await _call(session)
            # end async with
        assert not result.is_error
        assert tool.negotiated == [True]
        assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success']
        assert {record.event['session_id'] for record in host.records()} == {tool.sessions[0]}
        assert host.anomalies() == []
        assert verify_ledger(host.records()).ok
        # end def

    @BINDINGS
    async def test_concurrent_operations_of_one_call_are_all_recorded(self, modern: bool) -> None:
        """Four reads in flight in one call: four attempts, four outcomes, one session."""
        host, tool = _host(), _Tool(operations=4)
        async with _connection(host, tool, modern=modern) as (session, _transport):
            result = await _call(session)
            # end async with
        assert not result.is_error
        assert tool.performed == 4
        assert len(host.records()) == 8
        assert host.anomalies() == []
        # end def

    @BINDINGS
    async def test_level_2_numbers_each_call_from_zero(self, modern: bool) -> None:
        """§7.4: the sequence is per session, so every call's events are 0, 1, ... and verify."""
        key = generate_tool_key('tool-key')
        registry = KeyRegistry()
        registry.register_tool_key(key)
        host = _host(_l2(), verifier=KeyRegistryVerifier(registry))
        tool = _Tool(_l2(), operations=3, signer=Ed25519Signer.from_tool_key(key))
        async with _connection(host, tool, modern=modern) as (session, _transport):
            await _call(session)
            await _call(session)
            # end async with
        for session_id in tool.sessions:
            numbers = sorted(r.event['signer_seq'] for r in host.records() if r.event['session_id'] == session_id)
            assert numbers == list(range(6))
            # end for
        assert host.anomalies() == []
        assert verify_ledger(host.records()).ok
        # end def

    @BINDINGS
    async def test_a_tool_that_requires_a_countersignature_acts_on_a_countersigned_accept(self, modern: bool) -> None:
        """§5.2: the host countersigns with `log_id`, and the tool verifies it before it acts."""
        host_key = generate_tool_key('host-key')
        host_registry = KeyRegistry(KeyRole.HOST)
        host_registry.register(host_key.key_id, host_key.public_key, SignatureAlgorithm.ED25519)
        host = _host(
            _l2(Countersign.HOST).model_copy(update={'level': Level.L1}),
            countersigner=Ed25519Countersigner(host_key.key_id, host_key.private_key),
        )
        tool = _Tool(
            TOOL_CAPABILITY.model_copy(update={'countersign': Countersign.HOST}),
            countersignature_registry=host_registry,
        )
        async with _connection(host, tool, modern=modern) as (session, _transport):
            result = await _call(session)
            # end async with
        assert not result.is_error
        assert tool.performed == 1
        assert all(record.log_id == 'tenant-a' for record in host.records())
        # end def

    @BINDINGS
    async def test_a_host_that_cannot_record_fails_the_operation_closed(self, modern: bool) -> None:
        """§7.2: `unavailable` means the body never runs, under either binding."""
        host, tool = _host(), _Tool()
        host.persistence_available = False
        async with _connection(host, tool, modern=modern) as (session, _transport):
            result = await _call(session)
            # end async with
        assert result.is_error
        assert tool.performed == 0
        assert host.records() == []
        # end def

    @BINDINGS
    async def test_an_ordinary_host_is_served_as_ordinary_mcp_and_the_tool_records_for_itself(
        self, modern: bool
    ) -> None:
        """§6.2: no declaration, no session - the tool degrades and its own host holds the record."""
        tool = _Tool()
        async with _connection(None, tool, modern=modern) as (session, _transport):
            result = await _call(session)
            # end async with
        assert not result.is_error
        assert tool.negotiated == [False]
        assert [record.event['outcome'] for record in tool.fallback.records()] == ['attempted', 'success']
        assert tool.fallback.anomalies() == []
        # end def

    # end class


class TestTheMrtrBinding:
    """§6.4 specifics: rounds, retries, and what the seam keeps from each session."""

    async def test_the_client_sees_one_ordinary_result(self) -> None:
        """The rounds and their retries stay between the seams; the session gets the call's result."""
        host, tool = _host(), _Tool(operations=2)
        async with _connection(host, tool, modern=True) as (session, _transport):
            result = await _call(session)
            # end async with
        assert result.content[0].text == 'read 2 rows'  # type: ignore[union-attr]
        # end def

    async def test_the_host_answers_a_round_the_tool_never_retried_by_failing_closed(self) -> None:
        """A retry that never comes releases nothing: the attempt times out and the body does not run."""
        tool = _Tool()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditTransport(
                server_streams[0], server_streams[1], tool.declares, request_timeout=0.2
            ) as transport:
                server = _build_server(transport, tool)
                options = InitializationOptions(
                    server_name='t', server_version='0', capabilities=ServerCapabilities(tools=ToolsCapability())
                )
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                    await client_streams[1].send(_tools_call(1, session_id='0198f3a2-5c1e-7000-8000-00000000abc0'))
                    with anyio.fail_after(CALL_TIMEOUT):
                        frame = (await client_streams[0].receive()).message
                        # end with
                    assert isinstance(frame, JSONRPCResponse)
                    assert frame.result['resultType'] == 'input_required'
                    await _settle(lambda: tool.negotiated == [True] and tool.performed == 0)
                    await anyio.sleep(0.4)
                    assert tool.performed == 0
                    tasks.cancel_scope.cancel()
                    # end async with
                # end async with
            # end async with
        # end def

    async def test_a_replayed_retry_is_refused_and_does_not_run_the_operation_again(self) -> None:
        """§6.4 at most once: a round token is consumed by its first retry."""
        tool = _Tool()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditTransport(server_streams[0], server_streams[1], tool.declares) as transport:
                server = _build_server(transport, tool)
                options = InitializationOptions(
                    server_name='t', server_version='0', capabilities=ServerCapabilities(tools=ToolsCapability())
                )
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                    session_id = '0198f3a2-5c1e-7000-8000-00000000abc0'
                    await client_streams[1].send(_tools_call(1, session_id=session_id))
                    round_frame = await _receive(client_streams[0])
                    assert isinstance(round_frame, JSONRPCResponse)
                    state = round_frame.result['requestState']
                    attempt = round_frame.result['_meta'][EXTENSION_ID]['events'][0]
                    accept = {
                        'status': 'accept',
                        'seq': 0,
                        'record_hash': 'a' * 64,
                        'host_ts': '2026-07-15T00:00:01.000Z',
                        'previous_hash': '0' * 64,
                    }
                    responses = {attempt['id']: accept}
                    await client_streams[1].send(
                        _tools_call(2, session_id=session_id, state=state, responses=responses)
                    )
                    final = await _receive(client_streams[0])
                    assert isinstance(final, JSONRPCResponse)
                    assert final.id == 2
                    assert tool.performed == 1
                    await client_streams[1].send(
                        _tools_call(3, session_id=session_id, state=state, responses=responses)
                    )
                    refused = await _receive(client_streams[0])
                    assert isinstance(refused, JSONRPCError)
                    assert refused.id == 3
                    assert tool.performed == 1
                    tasks.cancel_scope.cancel()
                    # end async with
                # end async with
            # end async with
        # end def

    async def test_the_final_result_carries_the_trailing_outcome(self) -> None:
        """§6.4: the outcome of the last operation goes no later than the result, in its `_meta`."""
        tool = _Tool()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditTransport(server_streams[0], server_streams[1], tool.declares) as transport:
                server = _build_server(transport, tool)
                options = InitializationOptions(
                    server_name='t', server_version='0', capabilities=ServerCapabilities(tools=ToolsCapability())
                )
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                    session_id = '0198f3a2-5c1e-7000-8000-00000000abc0'
                    await client_streams[1].send(_tools_call(1, session_id=session_id))
                    round_frame = await _receive(client_streams[0])
                    assert isinstance(round_frame, JSONRPCResponse)
                    carried = round_frame.result['_meta'][EXTENSION_ID]
                    assert carried['session_id'] == session_id
                    assert [event['outcome'] for event in carried['events']] == ['attempted']
                    attempt = carried['events'][0]
                    host = _host()
                    host.open_session(session_id)
                    answer = await host.handle_attempt(attempt, session_id=session_id)
                    await client_streams[1].send(
                        _tools_call(
                            2,
                            session_id=session_id,
                            state=round_frame.result['requestState'],
                            responses={attempt['id']: answer.to_wire()},
                        )
                    )
                    final = await _receive(client_streams[0])
                    assert isinstance(final, JSONRPCResponse)
                    assert 'resultType' not in final.result or final.result['resultType'] == 'complete'
                    trailing = final.result['_meta'][EXTENSION_ID]['events']
                    assert [event['outcome'] for event in trailing] == ['success']
                    tasks.cancel_scope.cancel()
                    # end async with
                # end async with
            # end async with
        # end def

    async def test_a_round_that_also_asks_the_client_for_input_goes_up_with_the_answers_following(self) -> None:
        """§6.4: `inputRequests` are the client's to fulfil; the host's answers ride its retry."""
        host = _host()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditReceiver(client_streams[0], client_streams[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0',
                    id=1,
                    method='tools/call',
                    params={'name': 'read_customers', 'arguments': {}, '_meta': _modern_meta()},
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                outgoing = await _receive(server_streams[0])
                assert isinstance(outgoing, JSONRPCRequest)
                session_id = outgoing.params['_meta'][EXTENSION_ID]['session_id']
                attempt = _attempt_event(session_id)
                round_result = {
                    'resultType': 'input_required',
                    'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [attempt]}},
                }
                await server_streams[1].send(
                    SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result))
                )
                surfaced = await _receive(receiver.read_stream)
                assert isinstance(surfaced, JSONRPCResponse)
                assert surfaced.result['inputRequests']
                retry = JSONRPCRequest(
                    jsonrpc='2.0',
                    id=2,
                    method='tools/call',
                    params={
                        'name': 'read_customers',
                        'arguments': {},
                        'requestState': 'tool-state',
                        'inputResponses': {'q': {'action': 'accept'}},
                        '_meta': _modern_meta(),
                    },
                )
                await receiver.write_stream.send(SessionMessage(message=retry))
                forwarded = await _receive(server_streams[0])
                assert isinstance(forwarded, JSONRPCRequest)
                carried = forwarded.params['_meta'][EXTENSION_ID]
                assert carried['session_id'] == session_id
                assert carried['responses'][attempt['id']]['status'] == 'accept'
                # end async with
            # end async with
        assert [record.event['outcome'] for record in host.records()] == ['attempted']
        # end def

    # end class


class TestTheInitializeBinding:
    """§6.5 specifics: the methods, and what an ordinary host does with them."""

    async def test_an_attempt_the_host_never_answers_fails_closed(self) -> None:
        """§6: bounding the wait is the binding's, and silence reads as a failure to record."""

        class _Silent:
            capability = TOOL_CAPABILITY

            def open_session(self, session_id: str | None = None) -> str:
                return '0198f3a2-5c1e-7000-8000-00000000abc0'

            async def close_session(self, session_id: str) -> None:
                return None

            async def handle_attempt(
                self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
            ) -> Any:
                # Answers only after the tool has stopped waiting: late is the same as never to it.
                await anyio.sleep(1.0)
                return unavailable()

            async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
                return None

            # end class

        tool = _Tool()
        async with _connection(_Silent(), tool, modern=False, request_timeout=0.2) as (session, _transport):  # type: ignore[arg-type]
            result = await _call(session)
            # end async with
        assert result.is_error
        assert tool.performed == 0
        # end def

    @BINDINGS
    async def test_a_stalled_endpoint_does_not_hold_the_result_from_the_client(self, modern: bool) -> None:
        """The host bounds its wait on its own endpoint, so a stall delays the call by that bound only."""

        class _Stalled:
            capability = TOOL_CAPABILITY

            def open_session(self, session_id: str | None = None) -> str:
                return '0198f3a2-5c1e-7000-8000-00000000abc0'

            async def close_session(self, session_id: str) -> None:
                return None

            async def handle_attempt(
                self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
            ) -> Any:
                await anyio.sleep(3.0)
                return unavailable()

            async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
                return None

            # end class

        tool = _Tool()
        started = anyio.current_time()
        async with _connection(_Stalled(), tool, modern=modern, request_timeout=0.2) as (session, _transport):  # type: ignore[arg-type]
            result = await _call(session)
            elapsed = anyio.current_time() - started
            # end async with
        assert result.is_error
        assert tool.performed == 0
        assert elapsed < 2.0, f'the result waited {elapsed:.1f}s on the stalled endpoint'
        # end def

    async def test_an_outcome_sent_as_a_request_is_refused_and_not_sealed(self) -> None:
        """The outcome is a notification; a request is a malformed envelope, which is an error."""
        host = _host()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditReceiver(client_streams[0], client_streams[1], host):
                request = JSONRPCRequest(jsonrpc='2.0', id=7, method=OUTCOME_METHOD, params={'id': 'e1'})
                await server_streams[1].send(SessionMessage(message=request))
                frame = await _receive(server_streams[0])
                # end async with
            # end async with
        assert isinstance(frame, JSONRPCError)
        assert frame.id == 7
        assert host.records() == []
        # end def

    async def test_an_attempt_sent_as_a_notification_is_dropped(self) -> None:
        """It has no response channel, so sealing it would record an operation never cleared (§6)."""
        host = _host()
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditReceiver(client_streams[0], client_streams[1], host):
                notification = JSONRPCNotification(jsonrpc='2.0', method=ATTEMPT_METHOD, params={'id': 'e1'})
                await server_streams[1].send(SessionMessage(message=notification))
                request = JSONRPCRequest(jsonrpc='2.0', id='amcp-1', method=ATTEMPT_METHOD, params={'id': 'e1'})
                await server_streams[1].send(SessionMessage(message=request))
                frame = await _receive(server_streams[0])
                # end async with
            # end async with
        assert isinstance(frame, JSONRPCResponse)
        assert frame.id == 'amcp-1'
        assert frame.result['status'] == 'reject'
        assert host.records() == []
        # end def

    # end class


class TestTheCallTransport:
    """The per-call transport the handler gets, and what it refuses."""

    @BINDINGS
    async def test_an_unnegotiated_call_refuses_to_send(self, modern: bool) -> None:
        """§6.2: the MUST NOT is the one rule a peer cannot enforce for the tool."""
        tool = _Tool()
        async with _connection(None, tool, modern=modern) as (session, _transport):
            await _call(session)
            # end async with
        assert tool.negotiated == [False]
        assert tool.refused == [UnnegotiatedSendError, UnnegotiatedSendError]
        # end def

    async def test_asking_for_a_call_that_is_not_in_flight_is_refused(self) -> None:
        """A handler that names the wrong request would audit someone else's call."""
        async with create_client_server_memory_streams() as (_client_streams, server_streams):
            async with McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY) as transport:
                with pytest.raises(UnknownCallError):
                    transport.call(99)
                    # end with
                # end async with
            # end async with
        # end def

    async def test_negotiating_with_another_capability_is_refused(self) -> None:
        """The tool negotiates with what it declared on the wire, or the peer cannot check the outcome."""
        tool = _Tool()
        seen: list[type[Exception]] = []
        async with _connection(_host(), tool, modern=True) as (session, transport):
            original = transport.call

            def spy(request_id: object) -> Any:
                call = original(request_id)  # type: ignore[arg-type]
                try:
                    call.negotiate(_l2())
                except McpBindingError as error:
                    seen.append(type(error))
                    # end try
                return call
                # end def

            transport.call = spy  # type: ignore[method-assign]
            await _call(session)
            # end async with
        assert seen == [McpBindingError]
        # end def

    # end class


class TestTheHostSeesTheToolsDeclaration:
    """A host whose requirement the tool's handshake declaration does not meet is told so, once."""

    @staticmethod
    def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
        """The binding's warnings about the tool's declaration."""
        return [
            record.getMessage()
            for record in caplog.records
            if record.name == seam_module.__name__
            and record.levelno == logging.WARNING
            and 'its calls are not audited' in record.getMessage()
        ]
        # end def

    @BINDINGS
    async def test_a_declaration_below_the_requirement_is_warned_with_its_outcome(
        self, modern: bool, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A host that requires Level 2 would otherwise get an unaudited call and hear nothing."""
        caplog.set_level(logging.WARNING, logger=seam_module.__name__)
        async with _connection(_host(_l2(), verifier=_ANY_KEY), _Tool(), modern=modern) as (session, _transport):
            await _call(session)
            await _call(session)
            # end async with
        warnings = self._warnings(caplog)
        assert len(warnings) == 1
        assert 'mismatch' in warnings[0]
        assert 'level_fit=False' in warnings[0]
        # end def

    @BINDINGS
    async def test_a_tool_that_declares_nothing_is_warned_as_undeclared(
        self, modern: bool, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A tool without this extension answers the handshake with no declaration at all."""
        caplog.set_level(logging.WARNING, logger=seam_module.__name__)
        server = Server('plain-tool')
        options = InitializationOptions(
            server_name='plain-tool', server_version='0', capabilities=ServerCapabilities(tools=ToolsCapability())
        )
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.run, server_streams[0], server_streams[1], options, True)
                async with McpAuditReceiver(client_streams[0], client_streams[1], _host()) as receiver:
                    async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                        await (session.discover() if modern else session.initialize())
                        # end async with
                    # end async with
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        warnings = self._warnings(caplog)
        assert len(warnings) == 1
        assert 'undeclared' in warnings[0]
        # end def

    @BINDINGS
    async def test_a_declaration_that_meets_the_requirement_is_not_warned(
        self, modern: bool, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Nothing to report when the tool is audited."""
        caplog.set_level(logging.WARNING, logger=seam_module.__name__)
        async with _connection(_host(), _Tool(), modern=modern) as (session, _transport):
            await _call(session)
            # end async with
        assert self._warnings(caplog) == []
        # end def

    # end class


class TestTheHighLevelServer:
    """The official SDK's high-level `MCPServer`, whose context carries the raw id beside its string form."""

    @BINDINGS
    async def test_a_high_level_tool_is_audited_by_the_id_its_context_carries(self, modern: bool) -> None:
        """The raw id, `ctx.request_context.request_id`, names the call being served."""
        host = _host()
        negotiated: list[bool] = []
        server = MCPServer('audited-tool')
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with McpAuditTransport(server_streams[0], server_streams[1], TOOL_CAPABILITY) as wire:

                @server.tool()
                async def read_customers(ctx: Context) -> str:
                    """Read the customers table, audited."""
                    call = wire.call(ctx.request_context.request_id)
                    negotiation = call.negotiate(TOOL_CAPABILITY)
                    negotiated.append(negotiation.negotiated)
                    await _act(AmcpSession(call, call.session_id))
                    return 'read'
                    # end def

                lowlevel = server._lowlevel_server
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(
                        lowlevel.run, wire.read_stream, wire.write_stream, lowlevel.create_initialization_options()
                    )
                    async with McpAuditReceiver(client_streams[0], client_streams[1], host) as receiver:
                        async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                            await (session.discover() if modern else session.initialize())
                            result = await _call(session)
                            # end async with
                        # end async with
                    tasks.cancel_scope.cancel()
                    # end async with
                # end async with
            # end async with
        assert not result.is_error
        assert negotiated == [True]
        assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success']
        # end def

    async def test_the_string_form_of_an_int_id_is_refused_with_a_pointer_to_the_raw_id(self) -> None:
        """`ctx.request_id` is `str(request_id)`: it names no call, and the error says what to pass."""
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                await client[1].send(_legacy_call(7))
                await _receive(transport.read_stream)
                with pytest.raises(UnknownCallError, match='ctx.request_context.request_id'):
                    transport.call('7')
                    # end with
                by_int = transport.call(7)
                # end async with
            # end async with
        assert by_int.session_id
        # end def

    async def test_ids_one_and_string_one_are_two_calls_each_named_by_its_raw_id(self) -> None:
        """With `1` and `"1"` in flight each raw id names its own call, so neither is audited as the other."""
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                await client[1].send(_legacy_call(1))
                await _receive(transport.read_stream)
                await client[1].send(_legacy_call('1'))
                await _receive(transport.read_stream)
                by_int = transport.call(1)
                by_string = transport.call('1')
                # end async with
            # end async with
        assert by_int.session_id != by_string.session_id
        # end def

    # end class


async def _receive(stream: MemoryObjectReceiveStream[Any]) -> Any:
    """The next JSON-RPC message on a stream, bounded."""
    with anyio.fail_after(CALL_TIMEOUT):
        message = await stream.receive()
        # end with
    return message.message
    # end def


def _modern_meta(session_id: str | None = None, responses: dict[str, object] | None = None) -> dict[str, object]:
    """The `_meta` a 2026-07-28 client puts on a request, with this extension's object when given."""
    meta: dict[str, object] = {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {'extensions': audit_extension(TOOL_CAPABILITY)},
    }
    if session_id is not None:
        carried: dict[str, object] = {'session_id': session_id}
        if responses is not None:
            carried['responses'] = responses
            # end if
        meta[EXTENSION_ID] = carried
        # end if
    return meta
    # end def


def _tools_call(
    request_id: int,
    *,
    session_id: str,
    state: str | None = None,
    responses: dict[str, object] | None = None,
) -> SessionMessage:
    """A 2026-07-28 `tools/call` from a host that audits it, or a retry of one."""
    params: dict[str, object] = {
        'name': 'read_customers',
        'arguments': {},
        '_meta': _modern_meta(session_id, responses),
    }
    if state is not None:
        params['requestState'] = state
        # end if
    return SessionMessage(message=JSONRPCRequest(jsonrpc='2.0', id=request_id, method='tools/call', params=params))
    # end def


def _attempt_event(session_id: str) -> dict[str, object]:
    """A valid Level-1 attempt in `session_id`."""
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': SPEC_VERSION,
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': session_id,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    # end def


SESSION_ID = '0198f3a2-5c1e-7000-8000-00000000abc0'
OTHER_SESSION_ID = '0198f3a2-5c1e-7000-8000-00000000abc1'
Handler = Callable[[McpAuditTransport, Any], Awaitable[CallToolResult]]


@asynccontextmanager
async def _bare(
    tool: _Tool | None = None,
    *,
    handler: Handler | None = None,
    request_timeout: float = CALL_TIMEOUT,
) -> AsyncIterator[tuple[Any, McpAuditTransport]]:
    """A tool behind its seam, driven frame by frame from the client's end of the streams."""
    declares = tool.declares if tool is not None else TOOL_CAPABILITY
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with McpAuditTransport(
            server_streams[0], server_streams[1], declares, request_timeout=request_timeout
        ) as transport:
            if tool is not None:
                server = _build_server(transport, tool)
            else:
                server = Server('raw-tool')

                async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
                    if handler is None:
                        raise AssertionError('a bare server needs a tool or a handler')
                        # end if
                    return await handler(transport, context)
                    # end def

                server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
                # end if
            options = InitializationOptions(
                server_name='t', server_version='0', capabilities=ServerCapabilities(tools=ToolsCapability())
            )
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.run, transport.read_stream, transport.write_stream, options, True)
                yield client_streams, transport
                tasks.cancel_scope.cancel()
                # end async with
            # end async with
        # end async with
    # end def


async def _act(session: AmcpSession, ref: str = 'customers') -> None:
    """One audited read."""
    async with session.action('db.read', TargetResource(kind='table', ref=ref), mutates=False, egress=False):
        pass
        # end async with
    # end def


async def _legacy_negotiated(client: Any, transport: McpAuditTransport) -> McpAuditCall:
    """Pass the handshake and a §6.5 `tools/call` carrying SESSION_ID, and negotiate it."""
    handshake = JSONRPCRequest(
        jsonrpc='2.0',
        id=0,
        method='initialize',
        params={'capabilities': {'extensions': audit_extension(TOOL_CAPABILITY)}},
    )
    await client[1].send(SessionMessage(message=handshake))
    await _receive(transport.read_stream)
    await client[1].send(_legacy_call(1, _meta={EXTENSION_ID: {'session_id': SESSION_ID}}))
    await _receive(transport.read_stream)
    call = transport.call(1)
    call.negotiate(TOOL_CAPABILITY)
    return call
    # end def


class TestTheToolSeamUnderAdversarialTraffic:
    """What the tool's seam does with retries, cancellations, and rounds that are late or never come."""

    async def test_round_tokens_carry_the_seam_prefix(self) -> None:
        """Every `requestState` the seam issues is recognizable as one of its rounds (§6.4)."""
        tool = _Tool()
        async with _bare(tool) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_frame = await _receive(client[0])
            # end async with
        assert round_frame.result['requestState'].startswith('amcp.')
        # end def

    async def test_a_token_that_names_no_open_round_is_refused_and_never_reaches_the_tool(self) -> None:
        """A forged or replayed token is a JSON-RPC error, not a new call."""
        tool = _Tool()
        async with _bare(tool) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID, state='amcp.forged'))
            frame = await _receive(client[0])
            # end async with
        assert isinstance(frame, JSONRPCError)
        assert frame.error.code == INVALID_PARAMS
        assert tool.negotiated == []
        # end def

    async def test_a_retry_long_after_the_handler_concluded_gets_the_final_frame_and_releases_nothing(self) -> None:
        """§6.4: the result waits for the round's retry however late, and the accept it carries is ignored."""
        tool = _Tool()
        host = _host()
        host.open_session(SESSION_ID)
        async with _bare(tool, request_timeout=0.2) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_frame = await _receive(client[0])
            attempt = round_frame.result['_meta'][EXTENSION_ID]['events'][0]
            answer = await host.handle_attempt(attempt, session_id=SESSION_ID)
            await _settle(lambda: bool(transport._waiting))
            # Several times the bound: no timer may drop the result while its retry can still come.
            await anyio.sleep(0.6)
            state = round_frame.result['requestState']
            responses = {attempt['id']: answer.to_wire()}
            await client[1].send(_tools_call(2, session_id=SESSION_ID, state=state, responses=responses))
            final = await _receive(client[0])
            await client[1].send(_tools_call(3, session_id=SESSION_ID, state=state, responses=responses))
            replayed = await _receive(client[0])
            waiting_left = dict(transport._waiting)
            # end async with
        assert isinstance(final, JSONRPCResponse)
        assert final.id == 2
        assert final.result['isError'] is True
        trailing = final.result['_meta'][EXTENSION_ID]['events']
        assert [(event['outcome'], event.get('reason')) for event in trailing] == [('aborted', 'host-unavailable')]
        assert isinstance(replayed, JSONRPCError)
        assert replayed.id == 3
        assert tool.negotiated == [True]
        assert tool.performed == 0
        assert waiting_left == {}
        # end def

    async def test_an_error_concluded_while_a_round_is_out_follows_its_outcomes_round_on_late_retries(self) -> None:
        """§6.4: the outcomes-only round, then the error, each on the retry of the round before it."""

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            try:
                await _act(AmcpSession(call, call.session_id))
            except AmcpAbortedError:
                pass
                # end try
            raise MCPError(-32000, 'the tool gave up')
            # end def

        async with _bare(handler=handler, request_timeout=0.2) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_one = await _receive(client[0])
            await _settle(lambda: bool(transport._waiting))
            await anyio.sleep(0.4)
            await client[1].send(
                _tools_call(2, session_id=SESSION_ID, state=round_one.result['requestState'], responses={})
            )
            outcomes_round = await _receive(client[0])
            await anyio.sleep(0.4)
            await client[1].send(
                _tools_call(3, session_id=SESSION_ID, state=outcomes_round.result['requestState'], responses={})
            )
            error = await _receive(client[0])
            # end async with
        assert outcomes_round.id == 2
        carried = outcomes_round.result['_meta'][EXTENSION_ID]['events']
        assert [(event['outcome'], event.get('reason')) for event in carried] == [('aborted', 'host-unavailable')]
        assert isinstance(error, JSONRPCError)
        assert error.id == 3
        assert error.error.code == -32000
        # end def

    async def test_concluded_calls_beyond_the_bound_evict_the_least_recently_concluded(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """What bounds a kept final frame is MAX_IDLE_SESSIONS, not time; an eviction is logged by call."""
        monkeypatch.setattr(seam_module, 'MAX_IDLE_SESSIONS', 1)
        tool = _Tool()
        sessions = [OTHER_SESSION_ID, SESSION_ID]
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'):
            async with _bare(tool, request_timeout=0.1) as (client, transport):
                states = []
                for request_id, session_id in enumerate(sessions, start=1):
                    await client[1].send(_tools_call(request_id, session_id=session_id))
                    states.append((await _receive(client[0])).result['requestState'])
                    await _settle(lambda n=request_id: len(tool.negotiated) == n and not transport._calls)
                    # end for
                kept = [call.original_id for call in transport._waiting.values()]
                await client[1].send(_tools_call(3, session_id=sessions[0], state=states[0], responses={}))
                refused = await _receive(client[0])
                await client[1].send(_tools_call(4, session_id=sessions[1], state=states[1], responses={}))
                final = await _receive(client[0])
                # end async with
            # end with
        assert kept == [2]
        assert isinstance(refused, JSONRPCError)
        assert isinstance(final, JSONRPCResponse)
        assert final.id == 4
        assert any('tools/call 1' in record.getMessage() for record in caplog.records)
        # end def

    async def test_a_result_concluded_while_a_round_is_out_goes_out_on_that_rounds_retry(self) -> None:
        """§6.4: the handler's result and its aborted outcome are not dropped while a retry can come."""
        tool = _Tool()
        async with _bare(tool, request_timeout=0.3) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_frame = await _receive(client[0])
            await _settle(lambda: not transport._calls)
            await client[1].send(
                _tools_call(2, session_id=SESSION_ID, state=round_frame.result['requestState'], responses={})
            )
            final = await _receive(client[0])
            # end async with
        assert isinstance(final, JSONRPCResponse)
        assert final.id == 2
        assert final.result['isError'] is True
        trailing = final.result['_meta'][EXTENSION_ID]['events']
        assert [(event['outcome'], event.get('reason')) for event in trailing] == [('aborted', 'host-unavailable')]
        assert tool.performed == 0
        # end def

    async def test_a_retry_under_another_session_answers_none_of_the_rounds_attempts(self) -> None:
        """§6.4: an accept delivered under the wrong `session_id` releases nothing."""
        tool = _Tool()
        async with _bare(tool) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_frame = await _receive(client[0])
            attempt = round_frame.result['_meta'][EXTENSION_ID]['events'][0]
            accept = {
                'status': 'accept',
                'seq': 0,
                'record_hash': 'a' * 64,
                'host_ts': '2026-07-15T00:00:01.000Z',
                'previous_hash': '0' * 64,
            }
            await client[1].send(
                _tools_call(
                    2,
                    session_id=OTHER_SESSION_ID,
                    state=round_frame.result['requestState'],
                    responses={attempt['id']: accept},
                )
            )
            final = await _receive(client[0])
            # end async with
        assert isinstance(final, JSONRPCResponse)
        assert final.result['isError'] is True
        assert tool.performed == 0
        # end def

    async def test_a_cancelled_call_leaves_no_state_and_its_round_is_closed(self) -> None:
        """Cancellation settles the waiting attempts, drops the call, and closes its round's token (§6.4)."""
        tool = _Tool()
        async with _bare(tool) as (client, transport):
            tokens = []
            for request_id in range(1, 11):
                session_id = f'0198f3a2-5c1e-7000-8000-{request_id:012x}'
                await client[1].send(_tools_call(request_id, session_id=session_id))
                got = await _receive(client[0])
                tokens.append(got.result['requestState'])
                cancel = JSONRPCNotification(
                    jsonrpc='2.0', method='notifications/cancelled', params={'requestId': request_id}
                )
                await client[1].send(SessionMessage(message=cancel))
                # end for
            await _settle(lambda: not transport._calls and not transport._rounds and not transport._sessions)
            await client[1].send(_tools_call(99, session_id=SESSION_ID, state=tokens[0], responses={}))
            refused = await _receive(client[0])
            # end async with
        assert isinstance(refused, JSONRPCError)
        assert tool.performed == 0
        # end def

    async def test_the_requests_of_one_call_share_one_numbering(self) -> None:
        """§6.4, §7.4: every request carrying one `session_id` continues one `signer_seq` sequence."""
        seen: list[object] = []
        both = anyio.Event()

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            seen.append(call.numbering)
            if len(seen) == 2:
                both.set()
                # end if
            await both.wait()
            return CallToolResult(content=[])
            # end def

        async with _bare(handler=handler) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            await client[1].send(_tools_call(2, session_id=SESSION_ID))
            await _receive(client[0])
            await _receive(client[0])
            await _settle(lambda: not transport._sessions)
            # end async with
        assert len(seen) == 2
        assert seen[0] is seen[1]
        # end def

    async def test_an_unnegotiated_call_never_carries_the_peers_session_id(self) -> None:
        """§6.3: a tool that degrades issues its own session, whatever the peer sent."""
        tool = _Tool()
        meta = {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
            EXTENSION_ID: {'session_id': SESSION_ID},
        }
        request = JSONRPCRequest(
            jsonrpc='2.0', id=1, method='tools/call', params={'name': 'read_customers', 'arguments': {}, '_meta': meta}
        )
        async with _bare(tool) as (client, _transport):
            await client[1].send(SessionMessage(message=request))
            await _receive(client[0])
            # end async with
        assert tool.negotiated == [False]
        assert tool.sessions[0] != SESSION_ID
        assert {record.event['session_id'] for record in tool.fallback.records()} == {tool.sessions[0]}
        # end def

    async def test_an_attempt_emitted_while_a_round_is_out_waits_for_the_next_round(self) -> None:
        """§6.4: a retry answers only the attempts its round carried; a later one is not settled early."""
        release_second = anyio.Event()
        performed: list[str] = []

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            session = AmcpSession(call, call.session_id)

            async def first() -> None:
                await _act(session, 'first')
                performed.append('first')
                # end def

            async def second() -> None:
                await release_second.wait()
                await _act(session, 'second')
                performed.append('second')
                # end def

            async with anyio.create_task_group() as operations:
                operations.start_soon(first)
                operations.start_soon(second)
                # end async with
            return CallToolResult(content=[])
            # end def

        host = _host()
        host.open_session(SESSION_ID)
        async with _bare(handler=handler) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_one = await _receive(client[0])
            events = round_one.result['_meta'][EXTENSION_ID]['events']
            assert [event['target_resource']['ref'] for event in events] == ['first']
            release_second.set()
            await anyio.sleep(0.05)
            answer = await host.handle_attempt(events[0], session_id=SESSION_ID)
            await client[1].send(
                _tools_call(
                    2,
                    session_id=SESSION_ID,
                    state=round_one.result['requestState'],
                    responses={events[0]['id']: answer.to_wire()},
                )
            )
            round_two = await _receive(client[0])
            assert round_two.id == 2
            carried = round_two.result['_meta'][EXTENSION_ID]['events']
            attempts = [event for event in carried if event['outcome'] == 'attempted']
            assert [event['target_resource']['ref'] for event in attempts] == ['second']
            for event in carried:
                if event['outcome'] != 'attempted':
                    await host.handle_outcome(event, session_id=SESSION_ID)
                    # end if
                # end for
            second_answer = await host.handle_attempt(attempts[0], session_id=SESSION_ID)
            await client[1].send(
                _tools_call(
                    3,
                    session_id=SESSION_ID,
                    state=round_two.result['requestState'],
                    responses={attempts[0]['id']: second_answer.to_wire()},
                )
            )
            final = await _receive(client[0])
            # end async with
        assert isinstance(final, JSONRPCResponse)
        assert final.id == 3
        assert sorted(performed) == ['first', 'second']
        # end def

    async def test_a_call_that_ends_in_an_error_delivers_its_outcomes_in_a_round_first(self) -> None:
        """§6.4: an error has no `_meta`, so the outcomes go in one more round and the error follows."""

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            await _act(AmcpSession(call, call.session_id))
            raise MCPError(-32000, 'the tool failed after its operation')
            # end def

        host = _host()
        host.open_session(SESSION_ID)
        async with _bare(handler=handler) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_one = await _receive(client[0])
            attempt = round_one.result['_meta'][EXTENSION_ID]['events'][0]
            answer = await host.handle_attempt(attempt, session_id=SESSION_ID)
            await client[1].send(
                _tools_call(
                    2,
                    session_id=SESSION_ID,
                    state=round_one.result['requestState'],
                    responses={attempt['id']: answer.to_wire()},
                )
            )
            outcomes_round = await _receive(client[0])
            await client[1].send(
                _tools_call(3, session_id=SESSION_ID, state=outcomes_round.result['requestState'], responses={})
            )
            error = await _receive(client[0])
            # end async with
        assert outcomes_round.id == 2
        assert [event['outcome'] for event in outcomes_round.result['_meta'][EXTENSION_ID]['events']] == ['success']
        assert isinstance(error, JSONRPCError)
        assert error.id == 3
        assert error.error.code == -32000
        # end def

    async def test_a_timed_out_attempt_leaves_no_wait_and_its_late_answer_is_dropped(self) -> None:
        """§6.5: the wait is gone once it fails closed, and a late answer never reaches the session."""
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY, request_timeout=0.2) as transport:
                call = await _legacy_negotiated(client, transport)
                answer = await call.send_attempt(_attempt_event(SESSION_ID))
                pending_after_timeout = dict(transport._pending)
                sent = await _receive(client[0])
                late = JSONRPCResponse(jsonrpc='2.0', id=sent.id, result={'status': 'accept'})
                await client[1].send(SessionMessage(message=late))
                await client[1].send(SessionMessage(message=JSONRPCRequest(jsonrpc='2.0', id=7, method='ping')))
                delivered = await _receive(transport.read_stream)
                # end async with
            # end async with
        assert answer == unavailable()
        assert pending_after_timeout == {}
        assert delivered.id == 7
        # end def

    async def test_a_cancellation_settles_the_calls_attempts_in_flight_at_once(self) -> None:
        """§6.5: a cancelled call's attempt fails closed now, not when the wait's bound expires."""
        answers: list[object] = []
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                call = await _legacy_negotiated(client, transport)

                async def attempt() -> None:
                    answers.append(await call.send_attempt(_attempt_event(SESSION_ID)))
                    # end def

                with anyio.fail_after(1.0):
                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(attempt)
                        await _receive(client[0])
                        cancel = JSONRPCNotification(
                            jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 1}
                        )
                        await client[1].send(SessionMessage(message=cancel))
                        # end async with
                    # end with
                pending_left = dict(transport._pending)
                # end async with
            # end async with
        assert answers == [unavailable()]
        assert pending_left == {}
        # end def

    async def test_a_cancellation_while_the_result_waits_on_a_round_closes_it(self) -> None:
        """§6.4: the handler concluded with its round out; a cancel refuses the retry and withholds the result."""

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            answer = await call.send_attempt(_attempt_event(SESSION_ID))
            return CallToolResult(content=[], isError=answer.status != 'accept')
            # end def

        async with _bare(handler=handler, request_timeout=0.5) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            round_frame = await _receive(client[0])
            await _settle(lambda: bool(transport._waiting))
            cancel = JSONRPCNotification(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 1})
            await client[1].send(SessionMessage(message=cancel))
            await _settle(lambda: not transport._waiting)
            await client[1].send(
                _tools_call(2, session_id=SESSION_ID, state=round_frame.result['requestState'], responses={})
            )
            refused = await _receive(client[0])
            trailing: list[object] = []
            with anyio.move_on_after(0.7):
                trailing.append(await client[0].receive())
                # end with
            # end async with
        assert isinstance(refused, JSONRPCError)
        assert refused.id == 2
        assert refused.error.code == INVALID_PARAMS
        assert trailing == []
        # end def

    async def test_a_session_whose_own_input_round_waits_past_the_timeout_is_continued(self) -> None:
        """A retry that comes after a long wait for the client still continues the session's numbering."""
        own_round = {
            'resultType': 'input_required',
            'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
            'requestState': 'tool-state',
        }
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY, request_timeout=0.1) as transport:
                await client[1].send(_tools_call(1, session_id=SESSION_ID))
                await _receive(transport.read_stream)
                first = transport.call(1)
                first.negotiate(TOOL_CAPABILITY)
                await transport.write_stream.send(
                    SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=own_round))
                )
                await _receive(client[0])
                await anyio.sleep(0.3)
                await client[1].send(_tools_call(2, session_id=SESSION_ID, state='tool-state'))
                await _receive(transport.read_stream)
                second = transport.call(2)
                second.negotiate(TOOL_CAPABILITY)
                continued = second.numbering is first.numbering
                # end async with
            # end async with
        assert continued
        # end def

    async def test_idle_sessions_beyond_the_bound_evict_the_least_recently_idle(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Only idle records are evicted, oldest first, and each eviction is logged by session."""
        monkeypatch.setattr(seam_module, 'MAX_IDLE_SESSIONS', 2)
        own_round = {'resultType': 'input_required', 'requestState': 'tool-state'}
        sessions = [f'0198f3a2-5c1e-7000-8000-{n:012x}' for n in range(1, 5)]
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'):
            async with create_client_server_memory_streams() as (client, server):
                async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                    await client[1].send(_tools_call(99, session_id=sessions[3]))
                    await _receive(transport.read_stream)
                    for request_id, session_id in enumerate(sessions[:3], start=1):
                        await client[1].send(_tools_call(request_id, session_id=session_id))
                        await _receive(transport.read_stream)
                        answer = JSONRPCResponse(jsonrpc='2.0', id=request_id, result=own_round)
                        await transport.write_stream.send(SessionMessage(message=answer))
                        await _receive(client[0])
                        # end for
                    kept = set(transport._sessions)
                    # end async with
                # end async with
            # end with
        assert kept == {sessions[1], sessions[2], sessions[3]}
        assert any(sessions[0] in record.getMessage() for record in caplog.records)
        # end def

    async def test_closing_the_connection_drops_every_sessions_record(self) -> None:
        """A session held for a retry that can no longer come goes with the connection."""
        own_round = {'resultType': 'input_required', 'requestState': 'tool-state'}
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                await client[1].send(_tools_call(1, session_id=SESSION_ID))
                await _receive(transport.read_stream)
                await transport.write_stream.send(
                    SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=own_round))
                )
                await _receive(client[0])
                held = dict(transport._sessions)
                # end async with
            # end async with
        assert list(held) == [SESSION_ID]
        assert transport._sessions == {}
        assert transport._calls == {}
        assert transport._waiting == {}
        # end def

    async def test_a_tools_own_request_state_under_the_reserved_prefix_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A tool's own `requestState` must not begin with `amcp.`; one that does is reported."""
        own_round = {'resultType': 'input_required', 'requestState': 'amcp.mine'}
        with caplog.at_level(logging.ERROR, logger='auditable_mcp.mcp.seam'):
            async with create_client_server_memory_streams() as (client, server):
                async with McpAuditTransport(server[0], server[1], TOOL_CAPABILITY) as transport:
                    await client[1].send(_tools_call(1, session_id=SESSION_ID))
                    await _receive(transport.read_stream)
                    await transport.write_stream.send(
                        SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=own_round))
                    )
                    await _receive(client[0])
                    # end async with
                # end async with
            # end with
        assert any('reserved prefix' in record.getMessage() for record in caplog.records)
        # end def

    @pytest.mark.parametrize(('task', 'augmented'), [(None, False), ({'ttl': 60000}, True)])
    async def test_only_an_object_valued_task_is_task_augmentation(self, task: object, augmented: bool) -> None:
        """§6.4: `task: null` asks for no task, so the call is audited as any other."""
        negotiated: list[bool] = []

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            negotiated.append(transport.call(context.request_id).negotiate(TOOL_CAPABILITY).negotiated)
            return CallToolResult(content=[])
            # end def

        params = {'name': 'read_customers', 'arguments': {}, 'task': task, '_meta': _modern_meta(SESSION_ID)}
        request = JSONRPCRequest(jsonrpc='2.0', id=1, method='tools/call', params=params)
        async with _bare(handler=handler) as (client, _transport):
            await client[1].send(SessionMessage(message=request))
            await _receive(client[0])
            # end async with
        assert negotiated == [not augmented]
        # end def

    async def test_an_attempt_emitted_after_the_call_returned_is_refused_at_once(self) -> None:
        """No round follows the call's end, so the attempt fails closed without waiting out the bound."""
        kept: list[Any] = []

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            call = transport.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            kept.append(call)
            return CallToolResult(content=[])
            # end def

        async with _bare(handler=handler) as (client, transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            await _receive(client[0])
            with anyio.fail_after(1.0):
                answer = await kept[0].send_attempt(_attempt_event(SESSION_ID))
                # end with
            # end async with
        assert answer == unavailable()
        assert transport._pending == {}
        # end def

    # end class


class _GatedHost:
    """An audit host whose attempts in one session wait for a gate, so its slowness can be observed."""

    def __init__(self, host: AuditHost) -> None:
        """Wrap `host`; no session is gated until `gated` is set."""
        self._host = host
        self.gate = anyio.Event()
        self.gated: str | None = None
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The wrapped host's capability."""
        return self._host.capability
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Delegate."""
        return self._host.open_session(session_id)
        # end def

    async def close_session(self, session_id: str) -> None:
        """Delegate."""
        await self._host.close_session(session_id)
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> Any:
        """Wait at the gate for the gated session, then delegate."""
        if session_id is not None and session_id == self.gated:
            await self.gate.wait()
            # end if
        return await self._host.handle_attempt(event, session_id=session_id)
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Delegate."""
        await self._host.handle_outcome(event, session_id=session_id)
        # end def

    # end class


def _legacy_call(request_id: int | str, **extra: object) -> SessionMessage:
    """A `tools/call` made under a protocol version with an initialization handshake (§6.5)."""
    params: dict[str, object] = {'name': 'read_customers', 'arguments': {}, **extra}
    return SessionMessage(message=JSONRPCRequest(jsonrpc='2.0', id=request_id, method='tools/call', params=params))
    # end def


def _attempt_request(request_id: str, event: dict[str, object]) -> SessionMessage:
    """An `audit/attempt` from the tool (§6.5)."""
    return SessionMessage(message=JSONRPCRequest(jsonrpc='2.0', id=request_id, method=ATTEMPT_METHOD, params=event))
    # end def


class TestTheHostSeamUnderAdversarialTraffic:
    """What the host's seam does with events it did not ask for, and with calls that do not end."""

    async def test_the_final_result_after_a_client_retry_goes_to_the_id_the_client_awaits(self) -> None:
        """§6.4: once the client retried a round it answered, the call answers on the client's retry id."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0',
                    id=1,
                    method='tools/call',
                    params={'name': 'x', 'arguments': {}, '_meta': _modern_meta()},
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                round_result = {
                    'resultType': 'input_required',
                    'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [_attempt_event(session_id)]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result)))
                await _receive(receiver.read_stream)
                retry = JSONRPCRequest(
                    jsonrpc='2.0',
                    id=2,
                    method='tools/call',
                    params={'name': 'x', 'arguments': {}, 'requestState': 'tool-state', '_meta': _modern_meta()},
                )
                await receiver.write_stream.send(SessionMessage(message=retry))
                assert (await _receive(server[0])).id == 2
                final = {'content': [], '_meta': {}}
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=2, result=final)))
                surfaced = await _receive(receiver.read_stream)
                # end async with
            # end async with
        assert surfaced.id == 2
        # end def

    async def test_a_client_cancellation_is_matched_on_the_id_the_client_awaits(self) -> None:
        """§6.4: after its own retry, the client cancels by the retry's id, and the session ends."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                round_result = {
                    'resultType': 'input_required',
                    'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [_attempt_event(session_id)]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result)))
                await _receive(receiver.read_stream)
                retry = JSONRPCRequest(
                    jsonrpc='2.0',
                    id=2,
                    method='tools/call',
                    params={'name': 'x', 'requestState': 'tool-state', '_meta': _modern_meta()},
                )
                await receiver.write_stream.send(SessionMessage(message=retry))
                await _receive(server[0])
                cancel = JSONRPCNotification(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 2})
                await receiver.write_stream.send(SessionMessage(message=cancel))
                forwarded = await _receive(server[0])
                await _settle(lambda: any(a.kind == 'unresolved-attempt' for a in host.anomalies()))
                # end async with
            # end async with
        assert forwarded.params['requestId'] == 2
        # end def

    async def test_an_event_from_another_connection_cannot_enter_a_session(self) -> None:
        """§6.5 on stdio: a session this host did not issue for a call on this connection is not the call's."""
        host = _host()
        async with (
            create_client_server_memory_streams() as (client_a, server_a),
            create_client_server_memory_streams() as (client_b, server_b),
        ):
            async with (
                McpAuditReceiver(client_a[0], client_a[1], host) as receiver_a,
                McpAuditReceiver(client_b[0], client_b[1], host),
            ):
                await receiver_a.write_stream.send(_legacy_call(1))
                session_a = (await _receive(server_a[0])).params['_meta'][EXTENSION_ID]['session_id']
                genuine = _attempt_event(session_a)
                await server_a[1].send(_attempt_request('amcp-1', genuine))
                assert (await _receive(server_a[0])).result['status'] == 'accept'
                forged = dict(_attempt_event(session_a), id='00000000-0000-4000-8000-0000000000ff')
                await server_b[1].send(_attempt_request('amcp-1', forged))
                refused = await _receive(server_b[0])
                outcome = dict(genuine, outcome='success', ts='2026-07-15T00:00:09.000Z')
                notification = JSONRPCNotification(jsonrpc='2.0', method=OUTCOME_METHOD, params=outcome)
                await server_b[1].send(SessionMessage(message=notification))
                await _settle(lambda: len(host.anomalies()) == 2)
                # end async with
            # end async with
        assert refused.result == {'status': 'reject', 'reason': 'replay-detected'}
        assert [record.event['outcome'] for record in host.records()] == ['attempted']
        # The connection's close ends call A with its attempt unresolved; that record is the host's own.
        assert [anomaly.kind for anomaly in host.anomalies()][:2] == ['replay-detected', 'replay-detected']
        # end def

    async def test_one_slow_session_holds_neither_another_session_nor_other_traffic(self) -> None:
        """Audit work is serialized per session, not per connection."""
        gated = _GatedHost(_host())
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], gated) as receiver:
                await receiver.write_stream.send(_legacy_call(1))
                session_one = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                await receiver.write_stream.send(_legacy_call(2))
                session_two = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                gated.gated = session_one
                await server[1].send(_attempt_request('amcp-1', _attempt_event(session_one)))
                second = dict(_attempt_event(session_two), id='00000000-0000-4000-8000-000000000002')
                await server[1].send(_attempt_request('amcp-2', second))
                answered = await _receive(server[0])
                assert answered.id == 'amcp-2'
                ping = JSONRPCRequest(jsonrpc='2.0', id=7, method='ping', params=None)
                await server[1].send(SessionMessage(message=ping))
                assert (await _receive(receiver.read_stream)).id == 7
                gated.gate.set()
                assert (await _receive(server[0])).id == 'amcp-1'
                # end async with
            # end async with
        # end def

    async def test_ids_of_different_types_name_different_calls(self) -> None:
        """JSON-RPC `1` and `"1"` are two requests with two audit sessions."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await receiver.write_stream.send(_legacy_call(1))
                session_int = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                await receiver.write_stream.send(_legacy_call('1'))
                session_str = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                done = JSONRPCResponse(jsonrpc='2.0', id='1', result={'content': []})
                await server[1].send(SessionMessage(message=done))
                surfaced = await _receive(receiver.read_stream)
                await server[1].send(_attempt_request('amcp-1', _attempt_event(session_int)))
                still_open = await _receive(server[0])
                late = dict(_attempt_event(session_str), id='00000000-0000-4000-8000-000000000002')
                await server[1].send(_attempt_request('amcp-2', late))
                closed = await _receive(server[0])
                # end async with
            # end async with
        assert session_int != session_str
        assert surfaced.id == '1'
        assert still_open.result['status'] == 'accept'
        assert closed.result == {'status': 'reject', 'reason': 'replay-detected'}
        # end def

    async def test_a_task_augmented_call_carries_no_audit_session(self) -> None:
        """§6.4: this version does not audit a task-augmented call, so the host issues nothing for it."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await receiver.write_stream.send(_legacy_call(1, task={'ttl': 60000}))
                outgoing = await _receive(server[0])
                # end async with
            # end async with
        assert EXTENSION_ID not in (outgoing.params.get('_meta') or {})
        # end def

    async def test_a_call_that_exceeds_the_round_limit_is_ended_with_an_error(self) -> None:
        """§8.3: the host stops retrying after MAX_ROUNDS_PER_CALL rounds and tells its client."""
        host = _host()
        retries = 0
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                request = await _receive(server[0])
                session_id = request.params['_meta'][EXTENSION_ID]['session_id']
                round_result = {
                    'resultType': 'input_required',
                    'requestState': 'again',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': []}},
                }
                with anyio.fail_after(CALL_TIMEOUT):
                    while True:
                        answer = JSONRPCResponse(jsonrpc='2.0', id=request.id, result=round_result)
                        await server[1].send(SessionMessage(message=answer))
                        with anyio.move_on_after(0.5):
                            request = await server[0].receive()
                            request = request.message
                            retries += 1
                            continue
                            # end with
                        break
                        # end while
                    # end with
                surfaced = await _receive(receiver.read_stream)
                # end async with
            # end async with
        assert retries == MAX_ROUNDS_PER_CALL
        assert isinstance(surfaced, JSONRPCError)
        assert surfaced.id == 1
        assert surfaced.error.code == INTERNAL_ERROR
        assert str(MAX_ROUNDS_PER_CALL) in surfaced.error.message
        # end def

    async def test_a_round_without_a_request_state_ends_the_call_with_an_error(self) -> None:
        """§6.4: a round must carry `requestState`; without one the session closes and the client is told."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                round_result = {
                    'resultType': 'input_required',
                    'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [_attempt_event(session_id)]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result)))
                surfaced = await _receive(receiver.read_stream)
                calls_left = dict(receiver._calls)
                # end async with
            # end async with
        assert isinstance(surfaced, JSONRPCError)
        assert surfaced.id == 1
        assert surfaced.error.code == INTERNAL_ERROR
        assert calls_left == {}
        assert host.records() == []
        # end def

    async def test_each_item_of_a_round_is_refused_alone(self) -> None:
        """§6.4: a non-object item and an invalid attempt are each refused, and the valid attempt is sealed."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                invalid = dict(_attempt_event(session_id), id='00000000-0000-4000-8000-000000000002')
                del invalid['action_type']
                valid = dict(_attempt_event(session_id), id='00000000-0000-4000-8000-000000000003')
                round_result = {
                    'resultType': 'input_required',
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [42, invalid, valid]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result)))
                retry = await _receive(server[0])
                # end async with
            # end async with
        responses = retry.params['_meta'][EXTENSION_ID]['responses']
        assert responses[invalid['id']] == {'status': 'reject', 'reason': 'schema-invalid'}
        assert responses[valid['id']]['status'] == 'accept'
        assert set(responses) == {invalid['id'], valid['id']}
        assert [anomaly.kind for anomaly in host.anomalies()] == [
            'schema-invalid',
            'schema-invalid',
            'unresolved-attempt',
        ]
        assert [record.event['id'] for record in host.records()] == [valid['id']]
        # end def

    async def test_the_round_over_the_limit_has_its_outcomes_sealed_and_its_attempts_left_unanswered(self) -> None:
        """§8.3: the call ends, but the outcomes the last round carried are kept."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                request = await _receive(server[0])
                session_id = request.params['_meta'][EXTENSION_ID]['session_id']
                attempt = _attempt_event(session_id)
                events: list[dict[str, object]] = [attempt]
                for _ in range(MAX_ROUNDS_PER_CALL):
                    round_result = {
                        'resultType': 'input_required',
                        'requestState': 'again',
                        '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': events}},
                    }
                    answer = JSONRPCResponse(jsonrpc='2.0', id=request.id, result=round_result)
                    await server[1].send(SessionMessage(message=answer))
                    request = await _receive(server[0])
                    events = []
                    # end for
                outcome = dict(attempt, outcome='success', ts='2026-07-15T00:00:09.000Z')
                another = dict(_attempt_event(session_id), id='00000000-0000-4000-8000-000000000002')
                last = {
                    'resultType': 'input_required',
                    'requestState': 'again',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [outcome, another]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=request.id, result=last)))
                surfaced = await _receive(receiver.read_stream)
                # end async with
            # end async with
        assert isinstance(surfaced, JSONRPCError)
        assert surfaced.error.code == INTERNAL_ERROR
        assert surfaced.error.message == 'the tool exceeded the limit of 256 audit rounds for one call'
        assert [(record.event['id'], record.event['outcome']) for record in host.records()] == [
            (attempt['id'], 'attempted'),
            (attempt['id'], 'success'),
        ]
        # end def

    async def test_task_null_is_not_task_augmentation(self) -> None:
        """§6.4: `task: null` asks for no task, so the host issues the call an audit session."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await receiver.write_stream.send(_legacy_call(1, task=None))
                outgoing = await _receive(server[0])
                # end async with
            # end async with
        assert EXTENSION_ID in outgoing.params['_meta']
        # end def

    async def test_a_client_retry_of_a_held_round_is_resolved_before_the_task_check(self) -> None:
        """§6.4: a retry that echoes a held `requestState` carries its answers whatever its `task` says."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                call = JSONRPCRequest(
                    jsonrpc='2.0', id=1, method='tools/call', params={'name': 'x', '_meta': _modern_meta()}
                )
                await receiver.write_stream.send(SessionMessage(message=call))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                attempt = _attempt_event(session_id)
                round_result = {
                    'resultType': 'input_required',
                    'inputRequests': {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}},
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [attempt]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=round_result)))
                await _receive(receiver.read_stream)
                params = {
                    'name': 'x',
                    'requestState': 'tool-state',
                    'task': {'ttl': 60000},
                    '_meta': _modern_meta(),
                }
                retry = JSONRPCRequest(jsonrpc='2.0', id=2, method='tools/call', params=params)
                await receiver.write_stream.send(SessionMessage(message=retry))
                forwarded = await _receive(server[0])
                # end async with
            # end async with
        carried = forwarded.params['_meta'][EXTENSION_ID]
        assert carried['session_id'] == session_id
        assert list(carried['responses']) == [attempt['id']]
        # end def

    async def test_a_call_whose_meta_is_not_an_object_passes_through_unaudited(self) -> None:
        """No session is issued into a `_meta` that cannot hold it, and the call is not tracked."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await receiver.write_stream.send(_legacy_call(1, _meta='opaque'))
                outgoing = await _receive(server[0])
                calls = dict(receiver._calls)
                # end async with
            # end async with
        assert outgoing.params['_meta'] == 'opaque'
        assert calls == {}
        # end def

    async def test_closing_the_connection_waits_for_queued_work_up_to_the_request_timeout(self) -> None:
        """The drain on close is bounded by the request timeout, not a bound of its own."""
        gated = _GatedHost(_host())
        with anyio.fail_after(2.0):
            async with create_client_server_memory_streams() as (client, server):
                async with McpAuditReceiver(client[0], client[1], gated, request_timeout=0.2) as receiver:
                    await receiver.write_stream.send(_legacy_call(1))
                    session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                    gated.gated = session_id
                    await server[1].send(_attempt_request('amcp-1', _attempt_event(session_id)))
                    await anyio.sleep(0.05)
                    # end async with
                # end async with
            # end with
        # end def

    # end class


class _Recording:
    """An endpoint that records what it was handed, in order, and stalls where it is told to."""

    capability = TOOL_CAPABILITY

    def __init__(self, *, attempt_stall: float = 0.0, outcome_stall: float = 0.0) -> None:
        """Stall each attempt and each outcome by the given seconds."""
        self.attempt_stall = attempt_stall
        self.outcome_stall = outcome_stall
        self.calls: list[tuple[str, object]] = []
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Issue the fixed session."""
        return SESSION_ID
        # end def

    async def close_session(self, session_id: str) -> None:
        """Record the close."""
        self.calls.append(('close', session_id))
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> Any:
        """Record the attempt, stall, and refuse it - a decision the retry can be told apart by."""
        self.calls.append(('attempt', event.get('id')))
        await anyio.sleep(self.attempt_stall)
        return reject('schema-invalid')
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Stall, then record the outcome as sealed."""
        await anyio.sleep(self.outcome_stall)
        self.calls.append(('outcome', event.get('id')))
        # end def

    # end class


def _round(events: list[object], state: str = 'tool-state', **extra: object) -> dict[str, object]:
    """An `InputRequiredResult` carrying `events` for SESSION_ID."""
    return {
        'resultType': 'input_required',
        'requestState': state,
        '_meta': {EXTENSION_ID: {'session_id': SESSION_ID, 'events': events}},
        **extra,
    }
    # end def


def _modern_call(request_id: int) -> SessionMessage:
    """A 2026-07-28 `tools/call` from the client, before the host issues its session."""
    params = {'name': 'read_customers', 'arguments': {}, '_meta': _modern_meta()}
    return SessionMessage(message=JSONRPCRequest(jsonrpc='2.0', id=request_id, method='tools/call', params=params))
    # end def


def _numbered_attempt(n: int, session_id: str = SESSION_ID) -> dict[str, object]:
    """A valid attempt with a distinct id."""
    return dict(_attempt_event(session_id), id=f'00000000-0000-4000-8000-{n:012x}')
    # end def


def _outcome_of(attempt: dict[str, object], outcome: str = 'success') -> dict[str, object]:
    """The terminal outcome of `attempt`."""
    return dict(attempt, outcome=outcome, ts='2026-07-15T00:00:09.000Z')
    # end def


INPUT_REQUEST = {'q': {'method': 'elicitation/create', 'params': {'message': 'ok?'}}}


class _LateHost:
    """A real host behind an audit subsystem that takes longer than the binding waits (field check C8)."""

    def __init__(self, host: AuditHost, delay: float) -> None:
        """Wrap `host`, delaying every decision by `delay` seconds."""
        self.host = host
        self.capability = host.capability
        self._delay = delay
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Issue a session on the real host."""
        return self.host.open_session(session_id)
        # end def

    async def close_session(self, session_id: str) -> None:
        """Close it on the real host."""
        await self.host.close_session(session_id)
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> Any:
        """Stall, then let the real host decide under the deadline it was given."""
        await anyio.sleep(self._delay)
        return await self.host.handle_attempt(event, session_id=session_id, deadline=deadline)
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Seal on the real host at once."""
        await self.host.handle_outcome(event, session_id=session_id)
        # end def

    # end class


class TestADecisionPastTheDeadline:
    """An attempt the binding answered `unavailable` before the host took it up records nothing (§6.4)."""

    @BINDINGS
    async def test_the_ledger_holds_the_refusal_alone_and_no_anomaly_blames_the_tool(self, modern: bool) -> None:
        """The tool aborts; the late decision seals nothing and is not refused against a closed session."""
        host = _host()
        late = _LateHost(host, delay=0.6)
        tool = _Tool()
        async with _connection(late, tool, modern=modern, request_timeout=0.2) as (session, _transport):  # type: ignore[arg-type]
            result = await _call(session)
            await anyio.sleep(0.8)
            # end async with
        assert result.is_error
        assert tool.performed == 0
        assert [(r.event['outcome'], r.event.get('reason')) for r in host.records()] == [
            ('aborted', 'host-unavailable')
        ]
        assert host.anomalies() == []
        # end def

    # end class


class TestOneDeadlinePerRound:
    """§6.4: a round's processing runs under one deadline, and the retry goes when it passes."""

    @pytest.mark.parametrize('operations', [2, 3])
    async def test_a_stalled_endpoint_costs_a_call_one_bound_however_many_attempts_its_round_carries(
        self, operations: int
    ) -> None:
        """The tool's result reaches the client, not a refused retry, and within about one bound."""

        class _Stalled(_Recording):
            def __init__(self) -> None:
                super().__init__(attempt_stall=30.0)
                # end def

            # end class

        tool = _Tool(operations=operations)
        started = anyio.current_time()
        async with _connection(_Stalled(), tool, modern=True, request_timeout=0.3) as (session, _transport):  # type: ignore[arg-type]
            result = await _call(session)
            elapsed = anyio.current_time() - started
            # end async with
        assert result.is_error
        assert "aborted: ['host-unavailable']" in result.content[0].text  # type: ignore[union-attr]
        assert tool.performed == 0
        assert elapsed < 0.3 * 2.5, f'the result took {elapsed:.2f}s for {operations} attempts'
        # end def

    async def test_an_attempt_reached_after_the_deadline_is_never_handed_to_the_endpoint(self) -> None:
        """The attempt in progress completes in the background; the one behind it is answered unheard."""
        endpoint = _Recording(attempt_stall=0.5)
        first, second = _numbered_attempt(1), _numbered_attempt(2)
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], endpoint, request_timeout=0.2) as receiver:  # type: ignore[arg-type]
                await receiver.write_stream.send(_modern_call(1))
                await _receive(server[0])
                started = anyio.current_time()
                answer = JSONRPCResponse(jsonrpc='2.0', id=1, result=_round([first, second]))
                await server[1].send(SessionMessage(message=answer))
                retry = await _receive(server[0])
                elapsed = anyio.current_time() - started
                await anyio.sleep(0.5)
                # end async with
            # end async with
        responses = retry.params['_meta'][EXTENSION_ID]['responses']
        assert responses == {first['id']: unavailable().to_wire(), second['id']: unavailable().to_wire()}
        assert elapsed < 0.45
        assert [call for call in endpoint.calls if call[0] == 'attempt'] == [('attempt', first['id'])]
        # end def

    async def test_a_slow_outcome_does_not_hold_the_retry_and_is_sealed_after_it(self) -> None:
        """An outcome in progress at the deadline completes; the ones behind it are queued, not dropped."""
        endpoint = _Recording(outcome_stall=0.4)
        attempt = _numbered_attempt(3)
        done_one, done_two = _outcome_of(_numbered_attempt(1)), _outcome_of(_numbered_attempt(2))
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], endpoint, request_timeout=0.2) as receiver:  # type: ignore[arg-type]
                await receiver.write_stream.send(_modern_call(1))
                await _receive(server[0])
                started = anyio.current_time()
                answer = JSONRPCResponse(jsonrpc='2.0', id=1, result=_round([done_one, done_two, attempt]))
                await server[1].send(SessionMessage(message=answer))
                retry = await _receive(server[0])
                elapsed = anyio.current_time() - started
                sealed_at_retry = list(endpoint.calls)
                await _settle(lambda: len(endpoint.calls) == 2)
                # end async with
            # end async with
        assert elapsed < 0.35
        assert sealed_at_retry == []
        assert retry.params['_meta'][EXTENSION_ID]['responses'] == {attempt['id']: unavailable().to_wire()}
        assert endpoint.calls[:2] == [('outcome', done_one['id']), ('outcome', done_two['id'])]
        assert ('attempt', attempt['id']) not in endpoint.calls
        # end def

    async def test_a_round_decided_in_time_carries_the_decisions(self) -> None:
        """The deadline is an upper bound: a round decided within it is retried with what was decided."""
        endpoint = _Recording()
        attempt = _numbered_attempt(1)
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], endpoint, request_timeout=0.5) as receiver:  # type: ignore[arg-type]
                await receiver.write_stream.send(_modern_call(1))
                await _receive(server[0])
                answer = JSONRPCResponse(jsonrpc='2.0', id=1, result=_round([attempt]))
                await server[1].send(SessionMessage(message=answer))
                retry = await _receive(server[0])
                # end async with
            # end async with
        assert retry.params['_meta'][EXTENSION_ID]['responses'] == {attempt['id']: reject('schema-invalid').to_wire()}
        # end def

    async def test_a_cancel_mid_round_seals_what_is_left_before_the_session_closes(self) -> None:
        """No retry follows a cancelled call, so its outcomes are sealed ahead of the close queued behind."""
        endpoint = _Recording(attempt_stall=0.4)
        attempt = _numbered_attempt(2)
        done = _outcome_of(_numbered_attempt(1))
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], endpoint, request_timeout=0.2) as receiver:  # type: ignore[arg-type]
                await receiver.write_stream.send(_modern_call(1))
                await _receive(server[0])
                answer = JSONRPCResponse(jsonrpc='2.0', id=1, result=_round([attempt, done]))
                await server[1].send(SessionMessage(message=answer))
                await _settle(lambda: bool(endpoint.calls))
                cancel = JSONRPCNotification(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 1})
                await receiver.write_stream.send(SessionMessage(message=cancel))
                await _settle(lambda: ('close', SESSION_ID) in endpoint.calls)
                # end async with
            # end async with
        assert endpoint.calls[:3] == [('attempt', attempt['id']), ('outcome', done['id']), ('close', SESSION_ID)]
        # end def

    async def test_an_abandoned_round_delivers_its_error_by_the_deadline(self) -> None:
        """The same deadline bounds a round the host stops following; its outcomes are sealed before the close."""
        endpoint = _Recording(outcome_stall=0.4)
        done_one, done_two = _outcome_of(_numbered_attempt(1)), _outcome_of(_numbered_attempt(2))
        result = {'resultType': 'input_required', '_meta': {EXTENSION_ID: {'session_id': SESSION_ID, 'events': []}}}
        result['_meta'][EXTENSION_ID]['events'] = [done_one, done_two]  # type: ignore[index]
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], endpoint, request_timeout=0.2) as receiver:  # type: ignore[arg-type]
                await receiver.write_stream.send(_modern_call(1))
                await _receive(server[0])
                started = anyio.current_time()
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=result)))
                surfaced = await _receive(receiver.read_stream)
                elapsed = anyio.current_time() - started
                await _settle(lambda: ('close', SESSION_ID) in endpoint.calls)
                # end async with
            # end async with
        assert isinstance(surfaced, JSONRPCError)
        assert elapsed < 0.35
        assert endpoint.calls[:3] == [('outcome', done_one['id']), ('outcome', done_two['id']), ('close', SESSION_ID)]
        # end def

    # end class


class TestWhatTheCallerSees:
    """§6.4: the events are the host's audit input, and do not reach the host's own caller."""

    async def test_the_final_result_reaches_the_caller_without_this_extensions_member(self) -> None:
        """Other `_meta` members are the caller's and stay; this extension's goes."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                surfaced: list[Any] = []
                for request_id, others in enumerate([{'org.example/x': 1}, {}], start=1):
                    await receiver.write_stream.send(_modern_call(request_id))
                    request = await _receive(server[0])
                    session_id = request.params['_meta'][EXTENSION_ID]['session_id']
                    carried = {EXTENSION_ID: {'session_id': session_id, 'events': []}, **others}
                    final = {'content': [], '_meta': carried}
                    await server[1].send(
                        SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=request_id, result=final))
                    )
                    surfaced.append(await _receive(receiver.read_stream))
                    # end for
                # end async with
            # end async with
        assert surfaced[0].result['_meta'] == {'org.example/x': 1}
        assert '_meta' not in surfaced[1].result
        # end def

    async def test_a_round_passed_up_for_the_clients_input_carries_no_events(self) -> None:
        """The attempt's `action_context` is the host's to read, not the caller's (§4.3)."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await receiver.write_stream.send(_modern_call(1))
                session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                attempt = _attempt_event(session_id)
                result = {
                    'resultType': 'input_required',
                    'inputRequests': INPUT_REQUEST,
                    'requestState': 'tool-state',
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [attempt]}},
                }
                await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=1, result=result)))
                surfaced = await _receive(receiver.read_stream)
                # end async with
            # end async with
        assert surfaced.result['inputRequests'] == INPUT_REQUEST
        assert '_meta' not in surfaced.result
        assert [record.event['outcome'] for record in host.records()] == ['attempted']
        # end def

    # end class


class TestHeldRounds:
    """§6.4: a round passed up to the client waits for a retry that may never come, within a bound."""

    async def _hold(self, receiver: McpAuditReceiver, server: Any, request_id: int, state: str) -> str:
        """Make one call whose round, carrying one attempt, is passed up; return its session."""
        await receiver.write_stream.send(_modern_call(request_id))
        session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
        result = {
            'resultType': 'input_required',
            'inputRequests': INPUT_REQUEST,
            'requestState': state,
            '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': [_numbered_attempt(request_id, session_id)]}},
        }
        await server[1].send(SessionMessage(message=JSONRPCResponse(jsonrpc='2.0', id=request_id, result=result)))
        await _receive(receiver.read_stream)
        return session_id
        # end def

    async def test_held_rounds_beyond_the_bound_evict_the_least_recently_held(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The evicted call's session closes, so the attempt it accepted is recorded unresolved (§6.3)."""
        monkeypatch.setattr(seam_module, 'MAX_IDLE_SESSIONS', 1)
        host = _host()
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'):
            async with create_client_server_memory_streams() as (client, server):
                async with McpAuditReceiver(client[0], client[1], host) as receiver:
                    evicted = await self._hold(receiver, server, 1, 'state-one')
                    await self._hold(receiver, server, 2, 'state-two')
                    await _settle(lambda: bool(host.anomalies()))
                    held = list(receiver._held)
                    unresolved = [anomaly.kind for anomaly in host.anomalies()]
                    # end async with
                # end async with
            # end with
        assert held == ['state-two']
        assert unresolved == ['unresolved-attempt']
        assert any(evicted in record.getMessage() for record in caplog.records)
        # end def

    async def test_a_second_round_under_the_same_request_state_evicts_the_first(self) -> None:
        """A client retry names its round by `requestState` alone, so one state holds one call's round."""
        host = _host()
        async with create_client_server_memory_streams() as (client, server):
            async with McpAuditReceiver(client[0], client[1], host) as receiver:
                await self._hold(receiver, server, 1, 'same')
                kept = await self._hold(receiver, server, 2, 'same')
                await _settle(lambda: bool(host.anomalies()))
                held = {state: call.session_id for state, (call, _responses) in receiver._held.items()}
                # end async with
            # end async with
        assert held == {'same': kept}
        # end def

    # end class


class _SlowSeal:
    """A real host behind an endpoint whose outcome seals are slow, as a slow store makes them."""

    def __init__(self, host: AuditHost, stall: float) -> None:
        """Wrap `host`, stalling every outcome by `stall` seconds."""
        self.host = host
        self.capability = host.capability
        self._stall = stall
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Delegate."""
        return self.host.open_session(session_id)
        # end def

    async def close_session(self, session_id: str) -> None:
        """Delegate."""
        await self.host.close_session(session_id)
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> Any:
        """Delegate."""
        return await self.host.handle_attempt(event, session_id=session_id)
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Stall, then delegate."""
        await anyio.sleep(self._stall)
        await self.host.handle_outcome(event, session_id=session_id)
        # end def

    # end class


class _HungStore:
    """A store whose append never returns, holding the host's lock for as long."""

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Wait forever."""
        await anyio.sleep_forever()
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Nothing stored."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Nothing stored."""
        return []
        # end def

    # end class


class TestClosingTheConnection:
    """§6.3: a closed connection ends every call on it, in bounded time, and says what it left undone."""

    @BINDINGS
    async def test_a_concluding_calls_session_is_closed_and_unfinished_work_is_named(
        self, modern: bool, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The outcome still queued when the bound expires is logged by session, and the session closes."""
        endpoint = _SlowSeal(_host(), stall=1.0)
        tool = _Tool()
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'):
            async with _connection(endpoint, tool, modern=modern, request_timeout=0.2) as (session, _transport):  # type: ignore[arg-type]
                result = await _call(session)
                # end async with
            # end with
        assert not result.is_error
        session_id = tool.sessions[0]
        assert [anomaly.kind for anomaly in endpoint.host.anomalies()] == ['unresolved-attempt']
        assert endpoint.host._sessions == {}
        assert any(
            session_id in record.getMessage() and 'unfinished' in record.getMessage() for record in caplog.records
        )
        # end def

    async def test_a_host_whose_store_hangs_does_not_hold_the_close(self, caplog: pytest.LogCaptureFixture) -> None:
        """Waiting on the lanes and closing each session are each bounded by the request timeout."""
        host = _host(repository=_HungStore())
        started = anyio.current_time()
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'), anyio.fail_after(2.0):
            async with create_client_server_memory_streams() as (client, server):
                async with McpAuditReceiver(client[0], client[1], host, request_timeout=0.2) as receiver:
                    await receiver.write_stream.send(_legacy_call(1))
                    session_id = (await _receive(server[0])).params['_meta'][EXTENSION_ID]['session_id']
                    await server[1].send(_attempt_request('amcp-1', _attempt_event(session_id)))
                    answered = await _receive(server[0])
                    # end async with
                # end async with
            # end with
        assert answered.result['status'] == 'unavailable'
        assert anyio.current_time() - started < 1.5
        assert any(session_id in record.getMessage() for record in caplog.records)
        # end def

    # end class


class TestACancelledRequest:
    """A cancelled request is not answered, however late its handler concludes."""

    async def test_a_handler_that_concludes_long_after_the_cancel_writes_nothing(self) -> None:
        """Neither the seam's bound nor any timer lets the late frame through."""

        async def handler(transport: McpAuditTransport, context: Any) -> CallToolResult:
            with anyio.CancelScope(shield=True):
                await anyio.sleep(0.5)
                # end with
            return CallToolResult(content=[TextContent(type='text', text='late')])
            # end def

        async with _bare(handler=handler, request_timeout=0.1) as (client, _transport):
            await client[1].send(_tools_call(1, session_id=SESSION_ID))
            await anyio.sleep(0.05)
            cancel = JSONRPCNotification(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 1})
            await client[1].send(SessionMessage(message=cancel))
            written: list[object] = []
            with anyio.move_on_after(0.8):
                written.append(await client[0].receive())
                # end with
            # end async with
        assert written == []
        # end def

    # end class
