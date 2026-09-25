"""§6.4 over Streamable HTTP, and round affinity: real HTTP, the official client transport, uvicorn.

Every case runs the tool behind `AuditedStreamableHTTP` in a uvicorn server on an ephemeral port, and
the host is the official MCP client over the official Streamable HTTP client transport with an
`McpAuditReceiver` in front of it, or plain HTTP where a case needs to send what no conforming host
sends. Two-instance cases run two servers; the retries are steered between them by the client's HTTP
transport, which is what a load balancer does.
"""

import contextvars
import hashlib
import json
import logging
import re
import socket
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
import anyio.abc
import httpx2
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.shared.message import ClientMessageMetadata, SessionMessage
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    InputRequiredResult,
    JSONRPCError,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from auditable_mcp.host import AuditHost
from auditable_mcp.mcp import (
    AFFINITY_HEADER,
    FORWARD_OUTCOME_UNKNOWN_MESSAGE,
    FORWARDED_HEADER,
    INSTANCE_PATTERN,
    NO_OPEN_ROUND_MESSAGE,
    PRINCIPAL_MISMATCH_MESSAGE,
    PROCESS_INSTANCE,
    REGISTRY_FULL_MESSAGE,
    SESSION_ALREADY_OPEN_MESSAGE,
    SESSION_BODY_PATH,
    AuditedStreamableHTTP,
    ForwardedRequest,
    ForwardedResponse,
    ForwardNotDeliveredError,
    HttpForwarder,
    McpAuditReceiver,
    McpAuditTransport,
    audit_extension,
    negotiate_unaudited,
    round_token_instance,
)
from auditable_mcp.models import EXTENSION_ID, SPEC_VERSION, AuditCapability, Countersign, Level, TargetResource
from auditable_mcp.session import AmcpAbortedError, AmcpSession
from auditable_mcp.transport import unavailable
from auditable_mcp.verify import verify_ledger

TOOL_CAPABILITY = AuditCapability(
    spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE
)
PROTOCOL_VERSION = '2026-07-28'
CALL_TIMEOUT = 10.0
HEADER_MISMATCH = -32020
INVALID_PARAMS = -32602
TOOL_NAME = 'read_customers'
# The tool's one parameter that MCP mirrors into a request header (`x-mcp-header`).
REGION_SCHEMA: dict[str, Any] = {
    'type': 'object',
    'properties': {'region': {'type': 'string', 'x-mcp-header': 'Region'}},
}
PARAM_HEADER = 'mcp-param-region'
FORGED_SECRET = 'A' * 43


@dataclass
class _ToolState:
    """What the tool of one instance did, across every call it served."""

    operations: int = 3
    # A tool that never finishes, for the cancellation case.
    block: bool = False
    performed: int = 0
    aborted: int = 0
    calls: int = 0
    cancelled: int = 0
    unaudited: int = 0
    # end class


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


def _host() -> AuditHost:
    """An audit host with a deterministic clock."""
    return AuditHost('tenant-a', TOOL_CAPABILITY, clock=_Clock())
    # end def


async def _list_tools(_context: object, _params: PaginatedRequestParams) -> ListToolsResult:
    """The tool's catalog: one tool whose `region` argument is mirrored into `Mcp-Param-Region`."""
    return ListToolsResult(tools=[Tool(name=TOOL_NAME, description='read', inputSchema=REGION_SCHEMA)])
    # end def


def _factory(state: _ToolState) -> Callable[[McpAuditTransport], Server]:
    """Build the tool's server for one audited call, behind the seam the call is served over."""

    def build(seam: McpAuditTransport) -> Server:
        server = Server('http-tool')

        async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
            call = seam.call(context.request_id)
            negotiation = call.negotiate(TOOL_CAPABILITY)
            state.calls += 1
            if not negotiation.negotiated:
                return CallToolResult(content=[TextContent(type='text', text='not negotiated')], isError=True)
                # end if
            if state.block:
                try:
                    await anyio.sleep_forever()
                finally:
                    state.cancelled += 1
                    # end try
                # end if
            session = AmcpSession(call, call.session_id)
            try:
                for n in range(state.operations):
                    async with session.action(
                        'db.read', TargetResource(kind='table', ref=f'customers_{n}'), mutates=False, egress=False
                    ):
                        state.performed += 1
                        # end async with
                    # end for
            except AmcpAbortedError as error:
                state.aborted += 1
                return CallToolResult(content=[TextContent(type='text', text=f'aborted: {error.reason}')], isError=True)
                # end try
            return CallToolResult(content=[TextContent(type='text', text=f'read {state.operations} rows')])
            # end def

        server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
        server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
        return server
        # end def

    return build
    # end def


def _official_server(state: _ToolState) -> Server:
    """The server the official handler runs: the catalog, and the calls that carry no audit session."""
    server = Server('http-tool')

    async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
        negotiation = negotiate_unaudited(context.params, TOOL_CAPABILITY)
        state.unaudited += 1
        return CallToolResult(content=[TextContent(type='text', text=f'unaudited: {negotiation.outcome}')])
        # end def

    server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
    server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
    return server
    # end def


@asynccontextmanager
async def _uvicorn(app: Starlette) -> AsyncIterator[str]:
    """Serve `app` on an ephemeral port of the loopback interface, and yield its base URL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, lifespan='on', log_level='warning', timeout_graceful_shutdown=1))
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(server.serve, [sock])
        with anyio.fail_after(CALL_TIMEOUT):
            while not server.started:
                await anyio.sleep(0.01)
                # end while
            # end with
        try:
            yield f'http://127.0.0.1:{port}'
        finally:
            server.should_exit = True
            # end try
        # end async with
    sock.close()
    # end def


@dataclass
class _Instance:
    """One tool instance on the network."""

    url: str
    entry: AuditedStreamableHTTP
    state: _ToolState
    # end class


@asynccontextmanager
async def _instance(
    state: _ToolState,
    name: str,
    *,
    json_response: bool = True,
    security: TransportSecuritySettings | None = None,
    factory: Callable[[McpAuditTransport], Server] | None = None,
    middleware: Callable[[ASGIApp], ASGIApp] | None = None,
    **options: Any,
) -> AsyncIterator[_Instance]:
    """Run one instance of the tool: the official manager, wrapped by the audited entry, under uvicorn."""
    manager = StreamableHTTPSessionManager(
        _official_server(state), json_response=json_response, security_settings=security
    )
    built = factory if factory is not None else _factory(state)
    entry = AuditedStreamableHTTP(manager, built, TOOL_CAPABILITY, instance=name, **options)
    endpoint: ASGIApp = middleware(entry) if middleware is not None else entry

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run(), entry.run():
            yield
            # end async with
        # end def

    app = Starlette(routes=[Route('/mcp', endpoint=endpoint)], lifespan=lifespan)
    async with _uvicorn(app) as base:
        yield _Instance(url=f'{base}/mcp', entry=entry, state=state)
        # end async with
    # end def


@dataclass
class _Wire:
    """Every POST the host's HTTP client sent, as it went out, and where it went."""

    posts: list[tuple[dict[str, str], dict[str, Any], str]] = field(default_factory=list)

    async def record(self, request: httpx2.Request) -> None:
        """Keep a POST's headers, body and destination."""
        if request.method == 'POST' and request.content:
            self.posts.append((dict(request.headers), json.loads(request.content), str(request.url)))
            # end if
        # end def

    def calls(self) -> list[tuple[dict[str, str], dict[str, Any], str]]:
        """The `tools/call` POSTs: the opening request and every retry."""
        return [post for post in self.posts if post[1].get('method') == 'tools/call']
        # end def

    # end class


class _Router(httpx2.AsyncBaseTransport):
    """The client's HTTP transport, sending each request to the instance `choose` picks for it."""

    def __init__(self, choose: Callable[[httpx2.Request], str]) -> None:
        """Route through `choose`, which returns the endpoint URL a request goes to."""
        self._choose = choose
        self._inner = httpx2.AsyncHTTPTransport()
        # Where each `tools/call` went, with the affinity header it carried.
        self.calls: list[tuple[str | None, str]] = []
        # end def

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        """Send the request where `choose` says."""
        target = self._choose(request)
        if request.method == 'POST' and request.content and json.loads(request.content).get('method') == 'tools/call':
            self.calls.append((request.headers.get(AFFINITY_HEADER), target))
            # end if
        request.url = httpx2.URL(target)
        return await self._inner.handle_async_request(request)
        # end def

    async def aclose(self) -> None:
        """Close the pooled connections."""
        await self._inner.aclose()
        # end def

    # end class


@asynccontextmanager
async def _host_session(
    url: str, host: AuditHost, wire: _Wire, router: _Router | None = None
) -> AsyncIterator[ClientSession]:
    """A 2026-07-28 client session to `url` over Streamable HTTP, audited by `host`."""
    http = httpx2.AsyncClient(
        transport=router, event_hooks={'request': [wire.record]}, timeout=httpx2.Timeout(CALL_TIMEOUT)
    )
    async with http, streamable_http_client(url, http_client=http) as (read_stream, write_stream):
        async with McpAuditReceiver(read_stream, write_stream, host, request_timeout=CALL_TIMEOUT) as receiver:
            async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                await session.discover()
                await session.list_tools()
                yield session
                # end async with
            # end async with
        # end async with
    # end def


def _is_retry(request: httpx2.Request) -> bool:
    """Whether a POST is a retry of one of the seam's rounds."""
    if request.method != 'POST' or not request.content:
        return False
        # end if
    params = json.loads(request.content).get('params') or {}
    state = params.get('requestState')
    return isinstance(state, str) and state.startswith('amcp.')
    # end def


async def _call(session: ClientSession, region: str = 'eu') -> CallToolResult:
    """Call the tool once, bounded."""
    with anyio.fail_after(CALL_TIMEOUT):
        return await session.call_tool(TOOL_NAME, {'region': region})
        # end with
    # end def


async def _settle(predicate: Callable[[], bool]) -> None:
    """Let the servers run until `predicate` holds, failing rather than hanging if it never does."""
    with anyio.fail_after(CALL_TIMEOUT):
        while not predicate():
            await anyio.sleep(0.01)
            # end while
        # end with
    # end def


def _body(
    request_id: int | str,
    *,
    session_id: str | None,
    state: str | None = None,
    responses: dict[str, object] | None = None,
) -> dict[str, Any]:
    """A 2026-07-28 `tools/call` body, as a host that audits it sends it."""
    meta: dict[str, Any] = {
        'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
        'io.modelcontextprotocol/clientCapabilities': {'extensions': audit_extension(TOOL_CAPABILITY)},
    }
    if session_id is not None:
        carried: dict[str, object] = {'session_id': session_id}
        if responses is not None:
            carried['responses'] = responses
            # end if
        meta[EXTENSION_ID] = carried
        # end if
    params: dict[str, Any] = {'name': TOOL_NAME, 'arguments': {'region': 'eu'}, '_meta': meta}
    if state is not None:
        params['requestState'] = state
        # end if
    return {'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call', 'params': params}
    # end def


def _headers(affinity: str | None, **extra: str) -> dict[str, str]:
    """The request metadata headers a conforming client sends with `_body`, and the affinity header."""
    headers = {
        'accept': 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-protocol-version': PROTOCOL_VERSION,
        'mcp-method': 'tools/call',
        'mcp-name': TOOL_NAME,
        PARAM_HEADER: 'eu',
    }
    if affinity is not None:
        headers[AFFINITY_HEADER] = affinity
        # end if
    headers.update(extra)
    return headers
    # end def


async def _post(url: str, body: dict[str, Any], headers: dict[str, str]) -> httpx2.Response:
    """One raw POST, bounded."""
    async with httpx2.AsyncClient(timeout=httpx2.Timeout(CALL_TIMEOUT)) as client:
        return await client.post(url, json=body, headers=headers)
        # end async with
    # end def


def _session() -> str:
    """A fresh audit session id, as a host issues one."""
    return str(uuid.uuid4())
    # end def


def _attempt_ids(result: dict[str, Any]) -> list[str]:
    """The ids of the attempts a round carries."""
    events = result['_meta'][EXTENSION_ID]['events']
    return [event['id'] for event in events if event.get('outcome') == 'attempted']
    # end def


class TestOneInstance:
    """A call served by one instance, round after round, over real HTTP."""

    async def test_a_call_of_several_rounds_is_audited_and_every_request_carries_its_headers(self) -> None:
        """H1-H3, T2: three rounds and the result, every POST with the session and the metadata headers."""
        state, host, wire = _ToolState(), _host(), _Wire()
        async with _instance(state, 'one') as tool:
            async with _host_session(tool.url, host, wire) as session:
                result = await _call(session)
                # end async with
            await _settle(lambda: not tool.entry._sessions)
            # end async with
        assert not result.is_error
        assert state.performed == 3
        assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success'] * 3
        assert host.anomalies() == []
        assert verify_ledger(host.records()).ok
        posts = wire.calls()
        assert len(posts) == 4
        session_id = host.records()[0].event['session_id']
        for headers, body, _url in posts:
            # Every request of the call: the session, mirrored, and the metadata headers MCP requires.
            assert headers[AFFINITY_HEADER.lower()] == session_id
            assert body['params']['_meta'][EXTENSION_ID]['session_id'] == session_id
            assert headers['mcp-method'] == 'tools/call'
            assert headers['mcp-name'] == TOOL_NAME
            assert headers[PARAM_HEADER] == 'eu'
            assert headers['mcp-protocol-version'] == PROTOCOL_VERSION
            # end for
        assert [body['params'].get('requestState', '').startswith('amcp.one.') for _h, body, _u in posts] == [
            False,
            True,
            True,
            True,
        ]
        # end def

    async def test_a_request_that_is_not_audited_reaches_the_official_handler(self) -> None:
        """T1: without an audit session the call is ordinary MCP, served by the official handler."""
        state, wire = _ToolState(), _Wire()
        async with _instance(state, 'one') as tool:
            http = httpx2.AsyncClient(event_hooks={'request': [wire.record]}, timeout=httpx2.Timeout(CALL_TIMEOUT))
            async with http, streamable_http_client(tool.url, http_client=http) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    discovered = await session.discover()
                    await session.list_tools()
                    result = await _call(session)
                    # end async with
                # end async with
            # end async with
        assert (
            audit_extension(TOOL_CAPABILITY)[EXTENSION_ID] == (discovered.capabilities.extensions or {})[EXTENSION_ID]
        )
        assert state.unaudited == 1
        assert state.calls == 0
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == 'unaudited: undeclared'
        assert all(AFFINITY_HEADER.lower() not in headers for headers, _b, _u in wire.calls())
        # end def

    async def test_a_call_in_sse_response_mode_is_served_the_same(self) -> None:
        """T2: with the official handler in SSE mode, the answers still reach the host."""
        state, host, wire = _ToolState(), _host(), _Wire()
        async with _instance(state, 'one', json_response=False) as tool:
            async with _host_session(tool.url, host, wire) as session:
                result = await _call(session)
                # end async with
            # end async with
        assert not result.is_error
        assert state.performed == 3
        assert host.anomalies() == []
        # end def

    async def test_a_consumed_round_token_is_refused_when_replayed(self) -> None:
        """§6.4 at most once: replaying a retry the call already consumed runs nothing again."""
        state, host, wire = _ToolState(), _host(), _Wire()
        async with _instance(state, 'one') as tool:
            async with _host_session(tool.url, host, wire) as session:
                await _call(session)
                # end async with
            headers, body, _url = wire.calls()[1]
            resent = {name: value for name, value in headers.items() if name not in ('content-length', 'host')}
            replayed = await _post(tool.url, body, resent)
            # end async with
        # A refusal is the call's answer, in-band, as a handler's error is.
        assert replayed.status_code == 200
        assert replayed.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert replayed.json()['id'] == body['id']
        assert state.performed == 3
        # end def

    @pytest.mark.parametrize(
        ('session_in_body', 'affinity'),
        [(True, None), (True, 'different'), (False, 'present')],
        ids=['header-absent', 'header-different', 'header-without-body'],
    )
    async def test_an_affinity_header_that_disagrees_with_the_body_is_a_header_mismatch(
        self, session_in_body: bool, affinity: str | None
    ) -> None:
        """§6.4: the body is the source of truth; the header must agree with it - 400 and -32020."""
        state = _ToolState()
        session_id = _session()
        header = None if affinity is None else (_session() if affinity == 'different' else session_id)
        body = _body(7, session_id=session_id if session_in_body else None)
        async with _instance(state, 'one') as tool:
            response = await _post(tool.url, body, _headers(header))
            assert tool.entry._sessions == {}
            # end async with
        assert response.status_code == 400
        error = response.json()['error']
        assert error['code'] == HEADER_MISMATCH
        assert error['message'].startswith('Bad Request: the request headers and body disagree: ')
        assert error['data'] == {'mismatch': {'header': AFFINITY_HEADER, 'body': SESSION_BODY_PATH}}
        assert response.json()['id'] == 7
        assert state.calls == 0
        assert state.unaudited == 0
        # end def

    async def test_a_duplicated_affinity_header_is_a_header_mismatch(self) -> None:
        """First-copy and last-copy readers would route one request to two instances."""
        session_id = _session()
        headers = [(name, value) for name, value in _headers(session_id).items()]
        headers.append((AFFINITY_HEADER, session_id))
        async with _instance(_ToolState(), 'one') as tool:
            async with httpx2.AsyncClient(timeout=httpx2.Timeout(CALL_TIMEOUT)) as client:
                response = await client.post(tool.url, json=_body(1, session_id=session_id), headers=headers)
                # end async with
            # end async with
        assert response.status_code == 400
        assert response.json()['error']['code'] == HEADER_MISMATCH
        # end def

    async def test_a_retry_without_mcp_method_is_rejected_as_the_official_handler_rejects_it(self) -> None:
        """T3: the request metadata headers are checked on a retry as on any request - which is why H2 exists."""
        headers = _headers(None)
        del headers['mcp-method']
        state = f'amcp.one.{FORGED_SECRET}'
        async with _instance(_ToolState(), 'one') as tool:
            response = await _post(tool.url, _body(1, session_id=None, state=state), headers)
            # end async with
        assert response.status_code == 400
        assert response.json()['error']['code'] == HEADER_MISMATCH
        assert 'mcp-method' in response.json()['error']['message']
        # end def

    async def test_an_mcp_param_header_that_disagrees_with_the_arguments_is_rejected(self) -> None:
        """T3: `Mcp-Param-*` is checked against the tool's schema, as the official handler checks it."""
        state = _ToolState()
        session_id = _session()
        async with _instance(state, 'one') as tool:
            response = await _post(
                tool.url, _body(1, session_id=session_id), _headers(session_id, **{PARAM_HEADER: 'us'})
            )
            assert tool.entry._sessions == {}
            # end async with
        assert response.status_code == 400
        assert response.json()['error']['code'] == HEADER_MISMATCH
        assert state.performed == 0
        # end def

    async def test_an_oversized_body_is_refused_before_it_is_read(self) -> None:
        """T3: the official manager's body limit holds for the requests this entry takes."""
        session_id = _session()
        body = _body(1, session_id=session_id)
        body['params']['arguments']['padding'] = 'x' * (4 * 1024 * 1024)
        async with _instance(_ToolState(), 'one') as tool:
            response = await _post(tool.url, body, _headers(session_id))
            # end async with
        assert response.status_code == 413
        # end def

    async def test_an_origin_the_settings_do_not_allow_is_refused(self) -> None:
        """T3: DNS-rebinding protection applies to the requests this entry takes, as to the official ones."""
        state = _ToolState()
        session_id = _session()
        security = TransportSecuritySettings(allowed_hosts=['127.0.0.1:*'], allowed_origins=['http://good.example'])
        async with _instance(state, 'one', security=security) as tool:
            response = await _post(
                tool.url, _body(1, session_id=session_id), _headers(session_id, origin='http://evil.example')
            )
            # end async with
        assert response.status_code == 403
        assert state.calls == 0
        # end def

    async def test_closing_the_response_stream_cancels_the_call(self) -> None:
        """T3: under 2026-07-28 HTTP a client cancels by closing the stream; the handler is cancelled."""
        state = _ToolState(block=True)
        session_id = _session()
        async with _instance(state, 'one') as tool:
            async with httpx2.AsyncClient(timeout=httpx2.Timeout(0.5)) as client:
                with pytest.raises(httpx2.ReadTimeout):
                    await client.post(tool.url, json=_body(1, session_id=session_id), headers=_headers(session_id))
                    # end with
                # end async with
            await _settle(lambda: state.cancelled == 1 and not tool.entry._sessions)
            # end async with
        assert state.performed == 0
        # end def

    async def test_an_idle_round_is_released_and_its_retry_refused(self) -> None:
        """T2: a round never retried is not held forever; the retry that comes after is refused."""
        state = _ToolState()
        session_id = _session()
        async with _instance(state, 'one', idle_timeout=0.2) as tool:
            opened = await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))
            token = opened.json()['result']['requestState']
            await _settle(lambda: not tool.entry._sessions)
            responses = {event_id: unavailable().to_wire() for event_id in _attempt_ids(opened.json()['result'])}
            retry = _body(2, session_id=session_id, state=token, responses=responses)
            refused = await _post(tool.url, retry, _headers(session_id))
            # end async with
        assert refused.status_code == 200
        assert refused.json()['error']['message'] == NO_OPEN_ROUND_MESSAGE
        assert state.performed == 0
        # end def

    async def test_a_retry_from_another_principal_is_refused_and_the_round_stays_open(self) -> None:
        """T5, MRTR requirement 5: the owner of the call's first request is the only one who can resume it."""
        state = _ToolState(operations=1)
        session_id = _session()

        def principal_of(request: Request) -> str | None:
            return request.headers.get('authorization')
            # end def

        async with _instance(state, 'one', principal_of=principal_of) as tool:
            owner = _headers(session_id, authorization='Bearer alice')
            opened = await _post(tool.url, _body(1, session_id=session_id), owner)
            token = opened.json()['result']['requestState']
            responses = {event_id: unavailable().to_wire() for event_id in _attempt_ids(opened.json()['result'])}
            retry = _body(2, session_id=session_id, state=token, responses=responses)
            stolen = await _post(tool.url, retry, _headers(session_id, authorization='Bearer mallory'))
            resumed = await _post(tool.url, retry, owner)
            # end async with
        assert stolen.status_code == 200
        assert stolen.json()['error'] == {'code': INVALID_PARAMS, 'message': PRINCIPAL_MISMATCH_MESSAGE}
        assert resumed.status_code == 200
        assert resumed.json()['result']['isError'] is True
        assert state.performed == 0
        # end def

    async def test_the_affinity_header_is_checked_on_every_request_under_the_2026_envelope(self) -> None:
        """§6.4: a `tools/list` that carries the header with no session in its body is a header mismatch."""
        body = {
            'jsonrpc': '2.0',
            'id': 3,
            'method': 'tools/list',
            'params': {'_meta': _body(3, session_id=None)['params']['_meta']},
        }
        headers = {**_headers(_session()), 'mcp-method': 'tools/list'}
        del headers['mcp-name'], headers[PARAM_HEADER]
        async with _instance(_ToolState(), 'one') as tool:
            response = await _post(tool.url, body, headers)
            # end async with
        assert response.status_code == 400
        assert response.json()['error']['code'] == HEADER_MISMATCH
        # end def

    async def test_a_new_call_is_refused_while_every_held_call_is_busy(self) -> None:
        """The registry is bounded: with no idle call to close, a new audited call is refused in-band."""
        state = _ToolState(block=True)
        first, second = _session(), _session()
        async with _instance(state, 'one', max_held_calls=1) as tool:
            async with anyio.create_task_group() as calls:
                calls.start_soon(_post, tool.url, _body(1, session_id=first), _headers(first))
                await _settle(lambda: state.calls == 1)
                refused = await _post(tool.url, _body(2, session_id=second), _headers(second))
                calls.cancel_scope.cancel()
                # end async with
            # end async with
        assert refused.status_code == 200
        assert refused.json()['error'] == {'code': -32603, 'message': REGISTRY_FULL_MESSAGE}
        # end def

    async def test_the_least_recently_used_idle_call_makes_room_for_a_new_one(self) -> None:
        """Beyond `max_held_calls` the least recently used idle call closes, and its retry is refused."""
        state = _ToolState(operations=1)
        first, second = _session(), _session()
        async with _instance(state, 'one', max_held_calls=1) as tool:
            opened = await _post(tool.url, _body(1, session_id=first), _headers(first))
            await _post(tool.url, _body(2, session_id=second), _headers(second))
            token = opened.json()['result']['requestState']
            responses = {event_id: unavailable().to_wire() for event_id in _attempt_ids(opened.json()['result'])}
            retry = await _post(tool.url, _body(3, session_id=first, state=token, responses=responses), _headers(first))
            # end async with
        assert retry.status_code == 200
        assert retry.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert state.performed == 0
        # end def

    # end class


class TestSeveralInstances:
    """Round affinity (§6.4): a deployment of two instances that share nothing."""

    async def test_a_misrouted_retry_is_forwarded_to_the_instance_that_holds_its_round(self) -> None:
        """T4: every retry lands on B; B forwards each to A, and A runs every operation once."""
        urls: dict[str, str] = {}
        resolved: list[str] = []

        def resolve(instance: str) -> str | None:
            resolved.append(instance)
            return urls.get(instance)
            # end def

        a_state, b_state, host, wire = _ToolState(), _ToolState(), _host(), _Wire()
        async with HttpForwarder(resolve) as forwarder:
            async with (
                _instance(a_state, 'a', forward=forwarder) as a,
                _instance(b_state, 'b', forward=forwarder) as b,
            ):
                urls.update({'a': a.url, 'b': b.url})
                router = _Router(lambda request: b.url if _is_retry(request) else a.url)
                async with _host_session(a.url, host, wire, router) as session:
                    result = await _call(session)
                    # end async with
                # end async with
            # end async with
        assert not result.is_error
        assert a_state.performed == 3
        assert b_state.performed == 0
        assert b_state.calls == 0
        assert resolved == ['a', 'a', 'a']
        assert [url for _session_id, url in router.calls] == [a.url, b.url, b.url, b.url]
        assert host.anomalies() == []
        assert verify_ledger(host.records()).ok
        # end def

    async def test_a_misrouted_retry_without_forwarding_is_refused_and_nothing_is_performed(self) -> None:
        """§10.11: a retry that reaches the wrong instance fails the call and runs nothing."""
        a_state, b_state, host, wire = _ToolState(), _ToolState(), _host(), _Wire()
        async with (
            _instance(a_state, 'a', request_timeout=0.5) as a,
            _instance(b_state, 'b', request_timeout=0.5) as b,
        ):
            router = _Router(lambda request: b.url if _is_retry(request) else a.url)
            async with _host_session(a.url, host, wire, router) as session:
                with pytest.raises(MCPError) as refused:
                    await _call(session)
                    # end with
                # end async with
            # The retry never reached A, so its handler fails the attempt closed once its wait expires.
            await _settle(lambda: a_state.aborted == 1)
            # end async with
        assert refused.value.error.message == NO_OPEN_ROUND_MESSAGE
        assert a_state.performed == 0
        assert b_state.calls == 0
        # The host accepted an attempt whose outcome can no longer reach it, and says so (§6.3).
        assert [anomaly.kind for anomaly in host.anomalies()] == ['unresolved-attempt']
        # end def

    async def test_a_router_that_hashes_the_affinity_header_keeps_each_call_on_one_instance(self) -> None:
        """§6.4: routing on `Auditable-Mcp-Session` alone delivers every round of a call to one instance."""
        a_state, b_state, host, wire = _ToolState(), _ToolState(), _host(), _Wire()
        async with _instance(a_state, 'a') as a, _instance(b_state, 'b') as b:

            def by_session(request: httpx2.Request) -> str:
                session = request.headers.get(AFFINITY_HEADER)
                if session is None:
                    return a.url
                    # end if
                return (a.url, b.url)[hashlib.sha256(session.encode()).digest()[0] % 2]
                # end def

            router = _Router(by_session)
            async with _host_session(a.url, host, wire, router) as session:
                results = [await _call(session) for _ in range(6)]
                # end async with
            # end async with
        assert not any(result.is_error for result in results)
        assert a_state.performed + b_state.performed == 18
        destinations: dict[str | None, set[str]] = {}
        for session_id, url in router.calls:
            destinations.setdefault(session_id, set()).add(url)
            # end for
        assert None not in destinations
        assert len(destinations) == 6
        assert all(len(urls) == 1 for urls in destinations.values())
        assert host.anomalies() == []
        # end def

    async def test_a_forwarded_retry_is_never_forwarded_again(self) -> None:
        """T4: the forward marker ends a loop; B refuses rather than forward what was forwarded to it."""
        resolved: list[str] = []

        def resolve(instance: str) -> str | None:
            resolved.append(instance)
            return None
            # end def

        session_id = _session()
        async with HttpForwarder(resolve) as forwarder:
            async with _instance(_ToolState(), 'b', forward=forwarder) as b:
                marked = _headers(session_id, **{FORWARDED_HEADER: '1'})
                response = await _post(b.url, _body(1, session_id=session_id, state=f'amcp.a.{FORGED_SECRET}'), marked)
                # end async with
            # end async with
        assert response.status_code == 200
        assert response.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert resolved == []
        # end def

    @pytest.mark.parametrize(
        'state',
        [f'amcp.zzz.{FORGED_SECRET}', f'amcp.127.0.0.1:9/.{FORGED_SECRET}', f'amcp.b.{FORGED_SECRET}', 'amcp.a.short'],
        ids=['unknown-instance', 'not-an-instance-name', 'this-instance', 'malformed-token'],
    )
    async def test_a_retry_no_known_instance_holds_is_refused(self, state: str) -> None:
        """T4: only an instance the deployment resolves is ever contacted; anything else is refused."""
        resolved: list[str] = []

        def resolve(instance: str) -> str | None:
            resolved.append(instance)
            return {'a': 'http://127.0.0.1:9/mcp'}.get(instance) if instance == 'a' else None
            # end def

        session_id = _session()
        async with HttpForwarder(resolve) as forwarder:
            async with _instance(_ToolState(), 'b', forward=forwarder) as b:
                response = await _post(b.url, _body(1, session_id=session_id, state=state), _headers(session_id))
                # end async with
            # end async with
        assert response.status_code == 200
        assert response.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert resolved == (['zzz'] if state.startswith('amcp.zzz.') else [])
        # end def

    # end class


def _leaves(error: BaseException) -> list[BaseException]:
    """The exceptions that actually failed, flattened out of any groups around them."""
    if isinstance(error, BaseExceptionGroup):
        return [leaf for inner in error.exceptions for leaf in _leaves(inner)]
        # end if
    return [error]
    # end def


class TestHostOverHttp:
    """The host seam under the official Streamable HTTP client transport."""

    async def test_a_retry_the_transport_cannot_deliver_still_closes_the_session(self) -> None:
        """§6.3: the POST fails inside the transport's task group; the session closes and says what is unresolved."""
        listener = await anyio.create_tcp_listener(local_host='127.0.0.1')
        dead = f'http://127.0.0.1:{listener.extra(anyio.abc.SocketAttribute.local_port)}/mcp'

        async def hang_up(stream: anyio.abc.SocketStream) -> None:
            async with stream:
                await stream.receive()
                # end async with
            # end def

        host, wire = _host(), _Wire()
        failure: BaseException | None = None
        async with listener, anyio.create_task_group() as tasks:
            tasks.start_soon(listener.serve, hang_up)
            async with _instance(_ToolState(), 'one') as tool:
                router = _Router(lambda request: dead if _is_retry(request) else tool.url)
                try:
                    async with _host_session(tool.url, host, wire, router) as session:
                        await _call(session)
                        # end async with
                except BaseException as error:  # noqa: BLE001 - the transport's failure is what is under test
                    failure = error
                    # end try
                # end async with
            tasks.cancel_scope.cancel()
            # end async with
        assert failure is not None
        assert any(isinstance(leaf, httpx2.RemoteProtocolError) for leaf in _leaves(failure))
        assert [record.event['outcome'] for record in host.records()] == ['attempted']
        assert [anomaly.kind for anomaly in host.anomalies()] == ['unresolved-attempt']
        # end def

    # end class


class TestRoundToken:
    """The token format both SDKs share: `amcp.<instance>.<43 base64url characters>`."""

    def test_the_process_instance_is_a_valid_random_name(self) -> None:
        """16 random bytes in base64url, so a restarted process never names an earlier one's rounds."""
        assert INSTANCE_PATTERN.fullmatch(PROCESS_INSTANCE) is not None
        assert len(PROCESS_INSTANCE) == 22
        # end def

    def test_the_instance_is_read_only_out_of_a_well_formed_token(self) -> None:
        """Anything that is not exactly the shape names no instance, and is never resolved."""
        assert round_token_instance(f'amcp.node-1.{FORGED_SECRET}') == 'node-1'
        assert round_token_instance(f'amcp.node-1.{FORGED_SECRET}x') is None
        assert round_token_instance(f'amcp.{FORGED_SECRET}') is None
        assert round_token_instance(f'amcp.a/b.{FORGED_SECRET}') is None
        assert round_token_instance(f'amcp.{"n" * 65}.{FORGED_SECRET}') is None
        assert round_token_instance('tool-state') is None
        assert round_token_instance(None) is None
        # end def

    def test_an_instance_that_could_not_be_named_in_a_token_is_refused(self) -> None:
        """A name outside the pattern would make every token the seam issues unreadable."""
        with pytest.raises(ValueError):
            McpAuditTransport(*anyio.create_memory_object_stream(1), TOOL_CAPABILITY, instance='a.b')  # type: ignore[call-arg]
            # end with
        # end def

    # end class


class TestHostHeaders:
    """H1, H2: what the host seam puts in the per-request headers of the transport under it."""

    async def test_every_request_of_an_audited_call_carries_the_session_and_repeats_its_headers(self) -> None:
        """The opening request keeps the session's headers; a seam retry repeats them; a client retry keeps its own."""
        to_host, host_reads = anyio.create_memory_object_stream[SessionMessage | Exception](8)
        host_writes, from_host = anyio.create_memory_object_stream[SessionMessage](8)
        opening_headers = {
            'mcp-protocol-version': PROTOCOL_VERSION,
            'mcp-method': 'tools/call',
            'mcp-name': TOOL_NAME,
            'Mcp-Param-Region': 'eu',
        }
        client_headers = {'mcp-protocol-version': PROTOCOL_VERSION, 'mcp-method': 'tools/call', 'x-client': 'own'}
        async with to_host, from_host, McpAuditReceiver(host_reads, host_writes, _host()) as receiver:
            opening = _body(1, session_id=None)
            await receiver.write_stream.send(
                SessionMessage(
                    JSONRPCRequest.model_validate(opening), metadata=ClientMessageMetadata(headers=opening_headers)
                )
            )
            sent = await from_host.receive()
            session_id = sent.message.params['_meta'][EXTENSION_ID]['session_id']  # type: ignore[union-attr]
            assert isinstance(sent.metadata, ClientMessageMetadata)
            assert sent.metadata.headers == {**opening_headers, AFFINITY_HEADER: session_id}

            def round_of(request_id: object, state: str, **extra: object) -> SessionMessage:
                result = {
                    'resultType': 'input_required',
                    'requestState': state,
                    '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': []}},
                    **extra,
                }
                return SessionMessage(JSONRPCResponse(jsonrpc='2.0', id=request_id, result=result))  # type: ignore[arg-type]
                # end def

            # A round that asks for nothing but the audit answers: the seam retries it on the spot.
            await to_host.send(round_of(1, 'amcp.tool.round-one'))
            retry = await from_host.receive()
            assert retry.message.params['requestState'] == 'amcp.tool.round-one'  # type: ignore[union-attr]
            assert isinstance(retry.metadata, ClientMessageMetadata)
            assert retry.metadata.headers == {**opening_headers, AFFINITY_HEADER: session_id}
            # A round that also asks the client for input goes up, and the client retries it itself.
            await to_host.send(round_of(retry.message.id, 'tool-state', inputRequests={'q': {'method': 'x'}}))  # type: ignore[union-attr]
            await receiver.read_stream.receive()
            own_retry = _body(2, session_id=None, state='tool-state')
            await receiver.write_stream.send(
                SessionMessage(
                    JSONRPCRequest.model_validate(own_retry), metadata=ClientMessageMetadata(headers=client_headers)
                )
            )
            sent = await from_host.receive()
            assert isinstance(sent.metadata, ClientMessageMetadata)
            assert sent.metadata.headers == {**client_headers, AFFINITY_HEADER: session_id}
            await to_host.send(SessionMessage(JSONRPCResponse(jsonrpc='2.0', id=2, result={'content': []})))
            await receiver.read_stream.receive()
            # end async with
        # end def

    async def test_a_call_the_host_does_not_audit_carries_no_affinity_header(self) -> None:
        """A task-augmented call carries no audit session, so it carries no header claiming one (§6.4)."""
        to_host, host_reads = anyio.create_memory_object_stream[SessionMessage | Exception](8)
        host_writes, from_host = anyio.create_memory_object_stream[SessionMessage](8)
        async with to_host, from_host, McpAuditReceiver(host_reads, host_writes, _host()) as receiver:
            body = _body(1, session_id=None)
            body['params']['task'] = {'ttl': 1000}
            headers = {'mcp-method': 'tools/call'}
            await receiver.write_stream.send(
                SessionMessage(JSONRPCRequest.model_validate(body), metadata=ClientMessageMetadata(headers=headers))
            )
            sent = await from_host.receive()
            # end async with
        assert isinstance(sent.metadata, ClientMessageMetadata)
        assert sent.metadata.headers == headers
        # end def

    # end class


# The identity a deployment's middleware puts in the request's context, as authentication does.
CALLER: contextvars.ContextVar[str | None] = contextvars.ContextVar('caller', default=None)
CALLER_HEADER = 'x-caller'
OWN_STATE = 'own-1'
OWN_TOKEN = re.compile(r'amcp\.(?P<instance>[A-Za-z0-9_-]{1,64})\.[A-Za-z0-9_-]{43}')


class _CallerMiddleware:
    """Put the request's `x-caller` header in `CALLER` for the rest of the request, as authentication does."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the app."""
        self._app = app
        # end def

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve the request with its caller in context."""
        caller = dict(scope.get('headers', [])).get(CALLER_HEADER.encode(), b'').decode() or None
        token = CALLER.set(caller)
        try:
            await self._app(scope, receive, send)
        finally:
            CALLER.reset(token)
            # end try
        # end def

    # end class


@dataclass
class _OwnRounds:
    """What a tool that runs one input round of its own saw, request by request."""

    states: list[object] = field(default_factory=list)
    callers: list[str | None] = field(default_factory=list)
    # end class


def _own_round_factory(seen: _OwnRounds) -> Callable[[McpAuditTransport], Server]:
    """A tool that asks its client for input once, with its own `requestState`, then concludes."""

    def build(seam: McpAuditTransport) -> Server:
        server = Server('own-round-tool')

        async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult | InputRequiredResult:
            seam.call(context.request_id).negotiate(TOOL_CAPABILITY)
            state = (context.params or {}).get('requestState')
            seen.states.append(state)
            seen.callers.append(CALLER.get())
            if state is None:
                return InputRequiredResult(request_state=OWN_STATE)
                # end if
            return CallToolResult(content=[TextContent(type='text', text='concluded')])
            # end def

        server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
        server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
        return server
        # end def

    return build
    # end def


def _slow_factory(state: _ToolState, delay: float) -> Callable[[McpAuditTransport], Server]:
    """A tool whose one operation takes `delay` seconds once it is accepted and performed."""

    def build(seam: McpAuditTransport) -> Server:
        server = Server('slow-tool')

        async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
            call = seam.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            state.calls += 1
            session = AmcpSession(call, call.session_id)
            async with session.action('db.write', TargetResource(kind='table', ref='x'), mutates=True, egress=False):
                state.performed += 1
                await anyio.sleep(delay)
                # end async with
            return CallToolResult(content=[TextContent(type='text', text='written')])
            # end def

        server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
        server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
        return server
        # end def

    return build
    # end def


def _two_operation_factory(record: dict[str, int], running: float) -> Callable[[McpAuditTransport], Server]:
    """A tool whose first operation runs for `running` seconds, while the second asks for its accept."""

    def build(seam: McpAuditTransport) -> Server:
        server = Server('two-operation-tool')

        async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
            call = seam.call(context.request_id)
            call.negotiate(TOOL_CAPABILITY)
            session = AmcpSession(call, call.session_id)

            async def operation(n: int, start_after: float, duration: float) -> None:
                await anyio.sleep(start_after)
                async with session.action(
                    'db.write', TargetResource(kind='table', ref=f'x{n}'), mutates=True, egress=False
                ):
                    record[f'started{n}'] = record.get(f'started{n}', 0) + 1
                    try:
                        await anyio.sleep(duration)
                    except anyio.get_cancelled_exc_class():
                        record[f'cancelled{n}'] = 1
                        raise
                        # end try
                    record[f'done{n}'] = record.get(f'done{n}', 0) + 1
                    # end async with
                # end def

            async with anyio.create_task_group() as operations:
                operations.start_soon(operation, 1, 0, running)
                operations.start_soon(operation, 2, 0.1, 0)
                # end async with
            return CallToolResult(content=[TextContent(type='text', text='both written')])
            # end def

        server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
        server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
        return server
        # end def

    return build
    # end def


async def _answered(host: AuditHost, result: dict[str, Any], session_id: str) -> dict[str, object]:
    """The host's answers to every attempt a round carries."""
    events = result['_meta'][EXTENSION_ID]['events']
    return {
        event['id']: (await host.handle_attempt(event, session_id=session_id)).to_wire()
        for event in events
        if event.get('outcome') == 'attempted'
    }
    # end def


def _retry_body(request_id: int, session_id: str, state: str) -> dict[str, Any]:
    """A retry of an input round, with no audit answers, as the client of a tool's own round sends it."""
    return _body(request_id, session_id=session_id, state=state, responses={})
    # end def


class TestBusyCalls:
    """F1: a held call at work is never closed to make room for another."""

    async def test_a_call_whose_accepted_operation_is_running_is_not_evicted(self) -> None:
        """The registry is full and the only call has an operation under way: the new call is refused."""
        record: dict[str, int] = {}
        host = _host()
        factory = _two_operation_factory(record, running=0.5)
        async with _instance(_ToolState(), 'a', max_held_calls=1, factory=factory) as tool:
            session_id = host.open_session()
            first = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()['result']
            answers = await _answered(host, first, session_id)
            retry = _body(2, session_id=session_id, state=first['requestState'], responses=answers)
            second = (await _post(tool.url, retry, _headers(session_id))).json()['result']
            other = _session()
            refused = await _post(tool.url, _body(9, session_id=other), _headers(other))
            answers = await _answered(host, second, session_id)
            last = _body(3, session_id=session_id, state=second['requestState'], responses=answers)
            concluded = await _post(tool.url, last, _headers(session_id))
            # end async with
        assert refused.json()['error'] == {'code': -32603, 'message': REGISTRY_FULL_MESSAGE}
        assert 'cancelled1' not in record
        assert record == {'started1': 1, 'done1': 1, 'started2': 1, 'done2': 1}
        assert concluded.json()['result']['content'][0]['text'] == 'both written'
        # end def

    # end class


class TestForwardFailures:
    """F2: a forward that may have reached the owner is never answered as a replay."""

    async def test_a_forward_that_times_out_after_delivery_has_an_unknown_outcome(self) -> None:
        """The owner performed the operation; the client is told the outcome is unknown, not refused."""
        urls: dict[str, str] = {}
        a_state, b_state, host, wire = _ToolState(), _ToolState(), _host(), _Wire()
        client = httpx2.AsyncClient(timeout=httpx2.Timeout(5.0, read=0.3), follow_redirects=False, trust_env=False)
        async with client, HttpForwarder(urls.get, client=client) as forwarder:
            async with (
                _instance(a_state, 'a', forward=forwarder, factory=_slow_factory(a_state, 1.0)) as a,
                _instance(b_state, 'b', forward=forwarder, factory=_slow_factory(b_state, 1.0)) as b,
            ):
                urls.update({'a': a.url, 'b': b.url})
                router = _Router(lambda request: b.url if _is_retry(request) else a.url)
                async with _host_session(a.url, host, wire, router) as session:
                    with pytest.raises(MCPError) as failed:
                        await _call(session)
                        # end with
                    # end async with
                await _settle(lambda: not a.entry._sessions)
                # end async with
            # end async with
        assert failed.value.error.code == -32603
        assert failed.value.error.message == FORWARD_OUTCOME_UNKNOWN_MESSAGE
        assert a_state.performed == 1
        assert b_state.calls == 0
        # end def

    async def test_a_deployments_forward_that_raises_is_answered_in_band(self) -> None:
        """A `forward` of the deployment's own that fails is an unknown outcome, never an HTTP 500."""

        @asynccontextmanager
        async def broken(instance: str, request: ForwardedRequest) -> AsyncIterator[ForwardedResponse | None]:
            raise RuntimeError(f'cannot reach {instance}')
            yield None
            # end def

        session_id = _session()
        async with _instance(_ToolState(), 'b', forward=broken) as b:
            body = _body(1, session_id=session_id, state=f'amcp.a.{FORGED_SECRET}')
            response = await _post(b.url, body, _headers(session_id))
            # end async with
        assert response.status_code == 200
        assert response.json()['error'] == {'code': -32603, 'message': FORWARD_OUTCOME_UNKNOWN_MESSAGE}
        # end def

    async def test_a_deployments_forward_that_says_it_never_delivered_is_refused_as_a_replay(self) -> None:
        """`ForwardNotDeliveredError` is a forward's word that nothing reached the owner."""

        @asynccontextmanager
        async def unreachable(instance: str, request: ForwardedRequest) -> AsyncIterator[ForwardedResponse | None]:
            raise ForwardNotDeliveredError(f'{instance} is not reachable')
            yield None
            # end def

        session_id = _session()
        async with _instance(_ToolState(), 'b', forward=unreachable) as b:
            body = _body(1, session_id=session_id, state=f'amcp.a.{FORGED_SECRET}')
            response = await _post(b.url, body, _headers(session_id))
            # end async with
        assert response.status_code == 200
        assert response.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        # end def

    @pytest.mark.parametrize('failure', ['resolve-raises', 'connection-refused'])
    async def test_a_forward_that_provably_never_left_is_refused_as_a_replay(self, failure: str) -> None:
        """Nothing reached the owner, so nothing was performed: the retry is refused as a replay is."""

        def resolve(instance: str) -> str | None:
            if failure == 'resolve-raises':
                raise LookupError(instance)
                # end if
            return 'http://127.0.0.1:9/mcp'
            # end def

        session_id = _session()
        async with HttpForwarder(resolve) as forwarder, _instance(_ToolState(), 'b', forward=forwarder) as b:
            body = _body(1, session_id=session_id, state=f'amcp.a.{FORGED_SECRET}')
            response = await _post(b.url, body, _headers(session_id))
            # end async with
        assert response.status_code == 200
        assert response.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        # end def

    # end class


class TestToolOwnRounds:
    """F3: a tool's own input round goes out under a token of the entry's, routed like the seam's rounds."""

    async def test_a_tools_own_round_is_resumed_with_its_own_request_state(self) -> None:
        """The client sees an instance-naming token; the tool sees the `requestState` it issued."""
        seen = _OwnRounds()
        session_id = _session()
        async with _instance(_ToolState(), 'one', factory=_own_round_factory(seen)) as tool:
            opened = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()
            token = opened['result']['requestState']
            concluded = await _post(tool.url, _retry_body(2, session_id, token), _headers(session_id))
            # end async with
        match = OWN_TOKEN.fullmatch(token)
        assert match is not None
        assert match.group('instance') == 'one'
        assert seen.states == [None, OWN_STATE]
        assert concluded.json()['result']['content'][0]['text'] == 'concluded'
        # end def

    async def test_a_tools_own_round_retried_elsewhere_is_forwarded_to_its_owner(self) -> None:
        """The retry lands on the other instance, which forwards it: the tool that asked concludes."""
        urls: dict[str, str] = {}
        seen_a, seen_b = _OwnRounds(), _OwnRounds()
        session_id = _session()
        async with HttpForwarder(urls.get) as forwarder:
            async with (
                _instance(_ToolState(), 'a', forward=forwarder, factory=_own_round_factory(seen_a)) as a,
                _instance(_ToolState(), 'b', forward=forwarder, factory=_own_round_factory(seen_b)) as b,
            ):
                urls.update({'a': a.url, 'b': b.url})
                opened = (await _post(a.url, _body(1, session_id=session_id), _headers(session_id))).json()
                token = opened['result']['requestState']
                concluded = await _post(b.url, _retry_body(2, session_id, token), _headers(session_id))
                # end async with
            # end async with
        assert concluded.json()['result']['content'][0]['text'] == 'concluded'
        assert seen_a.states == [None, OWN_STATE]
        assert seen_b.states == []
        # end def

    async def test_a_tools_own_round_misrouted_without_forwarding_is_refused(self) -> None:
        """The other instance holds nothing of the call and serves nothing of it."""
        seen_a, seen_b = _OwnRounds(), _OwnRounds()
        session_id = _session()
        async with (
            _instance(_ToolState(), 'a', factory=_own_round_factory(seen_a)) as a,
            _instance(_ToolState(), 'b', factory=_own_round_factory(seen_b)) as b,
        ):
            opened = (await _post(a.url, _body(1, session_id=session_id), _headers(session_id))).json()
            token = opened['result']['requestState']
            refused = await _post(b.url, _retry_body(2, session_id, token), _headers(session_id))
            # end async with
        assert refused.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert seen_b.states == []
        # end def

    @pytest.mark.parametrize('where', ['another-instance', 'the-holding-instance'])
    async def test_a_retry_carrying_a_state_the_entry_never_issued_is_never_a_first_request(self, where: str) -> None:
        """§6.4: a request of an audited call with a `requestState` is a retry, never a new call."""
        seen_a, seen_b = _OwnRounds(), _OwnRounds()
        session_id = _session()
        async with (
            _instance(_ToolState(), 'a', factory=_own_round_factory(seen_a)) as a,
            _instance(_ToolState(), 'b', factory=_own_round_factory(seen_b)) as b,
        ):
            await _post(a.url, _body(1, session_id=session_id), _headers(session_id))
            target = b.url if where == 'another-instance' else a.url
            refused = await _post(target, _retry_body(2, session_id, OWN_STATE), _headers(session_id))
            # end async with
        assert refused.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert seen_a.states == [None]
        assert seen_b.states == []
        # end def

    # end class


class TestSessionAlreadyOpen:
    """F4: a first request of a session the entry already holds never reaches that session's call."""

    async def test_a_second_first_request_of_a_held_session_is_refused(self) -> None:
        """The host issues a fresh session for every call (§6.3); a repeat of one is refused."""
        state = _ToolState(operations=1)
        session_id = _session()
        async with _instance(state, 'one') as tool:
            await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))
            repeated = await _post(tool.url, _body(2, session_id=session_id), _headers(session_id))
            # end async with
        assert repeated.status_code == 200
        assert repeated.json()['error'] == {'code': INVALID_PARAMS, 'message': SESSION_ALREADY_OPEN_MESSAGE}
        assert state.calls == 1
        # end def

    # end class


class TestAnswerStatus:
    """F5: an answer that rejects the request is HTTP 400 as the official handler sends it."""

    async def test_a_header_mismatch_the_tool_raises_is_http_400(self) -> None:
        """Everything else the call answers is in-band; `-32020` and `-32021` are not."""

        def build(seam: McpAuditTransport) -> Server:
            server = Server('mismatching-tool')

            async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
                seam.call(context.request_id).negotiate(TOOL_CAPABILITY)
                raise MCPError(code=HEADER_MISMATCH, message='the tool finds a header wrong')
                # end def

            server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
            server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
            return server
            # end def

        session_id = _session()
        async with _instance(_ToolState(), 'one', factory=build) as tool:
            response = await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))
            # end async with
        assert response.status_code == 400
        assert response.json()['error']['code'] == HEADER_MISMATCH
        # end def

    # end class


class TestRequestContext:
    """F7: each request is served in its own context, on both sides of the wire."""

    async def test_each_request_of_a_call_reaches_the_tool_in_its_own_context(self) -> None:
        """The retry runs the handler in the retry's context, not in the opener's."""
        seen = _OwnRounds()
        session_id = _session()
        async with _instance(
            _ToolState(), 'one', factory=_own_round_factory(seen), middleware=_CallerMiddleware
        ) as tool:
            opened = await _post(
                tool.url, _body(1, session_id=session_id), _headers(session_id, **{CALLER_HEADER: 'alice'})
            )
            token = opened.json()['result']['requestState']
            await _post(tool.url, _retry_body(2, session_id, token), _headers(session_id, **{CALLER_HEADER: 'bob'}))
            # end async with
        assert seen.callers == ['alice', 'bob']
        # end def

    async def test_every_request_of_a_call_leaves_the_host_in_the_callers_context(self) -> None:
        """The opening request and every retry the host seam builds go out in the calling task's context."""
        sent: list[tuple[str | None, bool]] = []

        async def note(request: httpx2.Request) -> None:
            if request.method == 'POST' and b'"tools/call"' in request.content:
                sent.append((CALLER.get(), _is_retry(request)))
                # end if
            # end def

        state, host = _ToolState(operations=2), _host()
        async with _instance(state, 'one') as tool:
            http = httpx2.AsyncClient(event_hooks={'request': [note]}, timeout=httpx2.Timeout(CALL_TIMEOUT))
            async with http, streamable_http_client(tool.url, http_client=http) as (read_stream, write_stream):
                async with McpAuditReceiver(read_stream, write_stream, host, request_timeout=CALL_TIMEOUT) as audit:
                    async with ClientSession(audit.read_stream, audit.write_stream) as session:
                        await session.discover()
                        await session.list_tools()
                        for caller in ('alice', 'bob'):
                            token = CALLER.set(caller)
                            try:
                                await _call(session)
                            finally:
                                CALLER.reset(token)
                                # end try
                            # end for
                        # end async with
                    # end async with
                # end async with
            # end async with
        assert sent == [
            ('alice', False),
            ('alice', True),
            ('alice', True),
            ('bob', False),
            ('bob', True),
            ('bob', True),
        ]
        # end def

    # end class


class _SlowSealer:
    """An audit endpoint whose outcome seals take a while, recording which were sealed."""

    capability = TOOL_CAPABILITY

    def __init__(self) -> None:
        """Nothing sealed or closed yet."""
        self.sealed: list[object] = []
        self.closed: list[str] = []
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Issue a session."""
        return session_id or _session()
        # end def

    async def close_session(self, session_id: str) -> None:
        """Record the close."""
        self.closed.append(session_id)
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> Any:
        """No attempt reaches this endpoint in the test."""
        raise AssertionError('no attempt is expected')
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Take a while, then record the outcome."""
        await anyio.sleep(0.05)
        self.sealed.append(event.get('n'))
        # end def

    # end class


class TestCancelledClose:
    """F8: a cancellation around the host seam does not drop the outcomes it was sealing."""

    async def test_outcomes_queued_when_the_transport_cancels_the_session_are_still_sealed(self) -> None:
        """The transport cancels the scope around the receiver; every outcome of the result is sealed."""
        endpoint = _SlowSealer()
        to_host, host_reads = anyio.create_memory_object_stream[SessionMessage | Exception](8)
        host_writes, from_host = anyio.create_memory_object_stream[SessionMessage](8)
        with anyio.CancelScope() as around:
            async with to_host, from_host, McpAuditReceiver(host_reads, host_writes, endpoint) as receiver:  # type: ignore[arg-type]
                opening = _body(1, session_id=None)
                await receiver.write_stream.send(SessionMessage(JSONRPCRequest.model_validate(opening)))
                session_id = (await from_host.receive()).message.params['_meta'][EXTENSION_ID]['session_id']  # type: ignore[union-attr]
                outcomes = [{'n': n} for n in range(3)]
                result = {'content': [], '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': outcomes}}}
                await to_host.send(SessionMessage(JSONRPCResponse(jsonrpc='2.0', id=1, result=result)))
                await receiver.read_stream.receive()
                around.cancel()
                await anyio.sleep_forever()
                # end async with
            # end with
        assert endpoint.sealed == [0, 1, 2]
        assert session_id in endpoint.closed
        # end def

    # end class


class _RequestingServer:
    """A server that sends its client a request, which the 2026-07-28 HTTP wire has no channel for."""

    def __init__(self, answers: list[object]) -> None:
        """Keep what the request is answered with."""
        self._answers = answers
        # end def

    def create_initialization_options(self) -> None:
        """No options are read."""
        return None
        # end def

    async def run(self, read_stream: Any, write_stream: Any, _options: object) -> None:
        """Send a request for roots and keep its answer; what else arrives is not served."""
        request = JSONRPCRequest(jsonrpc='2.0', id='roots', method='roots/list')
        await write_stream.send(SessionMessage(message=request))
        async for message in read_stream:
            if isinstance(message.message, JSONRPCError) and message.message.id == 'roots':
                self._answers.append(message.message)
                # end if
            # end for
        # end def

    # end class


class TestHygiene:
    """F10: what the entry answers and refuses of its own server and its own configuration."""

    async def test_a_request_the_tool_sends_its_client_is_answered_method_not_found(self) -> None:
        """There is no back-channel; the tool is told so rather than left waiting."""
        answers: list[object] = []
        session_id = _session()
        factory = lambda _seam: _RequestingServer(answers)  # noqa: E731
        body = _body(1, session_id=session_id)
        body['params']['arguments'] = {}
        headers = _headers(session_id)
        del headers[PARAM_HEADER]
        async with _instance(_ToolState(), 'one', factory=factory) as tool:  # type: ignore[arg-type]
            async with anyio.create_task_group() as posting:
                posting.start_soon(_post, tool.url, body, headers)
                await _settle(lambda: bool(answers))
                posting.cancel_scope.cancel()
                # end async with
            # end async with
        assert isinstance(answers[0], JSONRPCError)
        assert answers[0].error.code == -32601
        # end def

    def test_a_server_that_declares_another_capability_is_refused(self) -> None:
        """The entry's declaration is the one its seams negotiate with; it does not replace another's."""
        server = _official_server(_ToolState())
        server.extensions[EXTENSION_ID] = {'level': 'L2'}
        manager = StreamableHTTPSessionManager(server)
        with pytest.raises(ValueError):
            AuditedStreamableHTTP(manager, _factory(_ToolState()), TOOL_CAPABILITY)
            # end with
        # end def

    # end class


class TestHeldCallLifetime:
    """F13: one lifetime rule - running calls are neither evicted nor expired; undelivered ones only expire."""

    async def test_a_call_holding_an_undelivered_outcome_is_not_evicted(self) -> None:
        """An operation performed, its outcome waiting for the next retry: the new call is refused instead."""
        record: dict[str, int] = {}
        host = _host()
        factory = _two_operation_factory(record, running=0.2)
        async with _instance(_ToolState(), 'a', max_held_calls=1, factory=factory) as tool:
            session_id = host.open_session()
            first = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()['result']
            answers = await _answered(host, first, session_id)
            retry = _body(2, session_id=session_id, state=first['requestState'], responses=answers)
            second = (await _post(tool.url, retry, _headers(session_id))).json()['result']
            await _settle(lambda: record.get('done1') == 1)
            other = _session()
            refused = await _post(tool.url, _body(9, session_id=other), _headers(other))
            answers = await _answered(host, second, session_id)
            last = _body(3, session_id=session_id, state=second['requestState'], responses=answers)
            concluded = (await _post(tool.url, last, _headers(session_id))).json()
            for event in concluded['result']['_meta'][EXTENSION_ID]['events']:
                await host.handle_outcome(event, session_id=session_id)
                # end for
            await host.close_session(session_id)
            # end async with
        assert refused.json()['error'] == {'code': -32603, 'message': REGISTRY_FULL_MESSAGE}
        assert concluded['result']['content'][0]['text'] == 'both written'
        assert host.anomalies() == []
        # end def

    async def test_a_running_call_outlives_the_idle_bound_and_an_undelivered_one_does_not(self) -> None:
        """While an accepted operation runs the call is kept; once it only holds its outcome, it expires."""
        record: dict[str, int] = {}
        host = _host()
        factory = _two_operation_factory(record, running=0.8)
        async with _instance(_ToolState(), 'a', factory=factory, idle_timeout=0.2) as tool:
            session_id = host.open_session()
            first = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()['result']
            answers = await _answered(host, first, session_id)
            retry = _body(2, session_id=session_id, state=first['requestState'], responses=answers)
            await _post(tool.url, retry, _headers(session_id))
            await anyio.sleep(0.6)
            held_while_running = session_id in tool.entry._sessions
            await _settle(lambda: session_id not in tool.entry._sessions)
            # end async with
        assert held_while_running
        assert record.get('done1') == 1
        assert 'cancelled1' not in record
        # end def

    # end class


class TestOwnRoundSession:
    """F14: a tool's own round is resumed only within the call's audit session."""

    @pytest.mark.parametrize('presented', ['none', 'another'])
    async def test_a_retry_of_a_tools_own_round_under_another_session_is_refused(self, presented: str) -> None:
        """Refused without consuming the token; the call's own retry still concludes it."""
        seen = _OwnRounds()
        session_id = _session()
        async with _instance(_ToolState(), 'one', factory=_own_round_factory(seen)) as tool:
            opened = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()
            token = opened['result']['requestState']
            stranger = _session() if presented == 'another' else None
            body = _body(2, session_id=stranger, state=token, responses={} if stranger else None)
            refused = await _post(tool.url, body, _headers(stranger))
            concluded = await _post(tool.url, _retry_body(3, session_id, token), _headers(session_id))
            # end async with
        assert refused.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert concluded.json()['result']['content'][0]['text'] == 'concluded'
        assert seen.states == [None, OWN_STATE]
        # end def

    # end class


class _AuthenticatingMiddleware:
    """Authenticate each request as its `x-caller`, as the official bearer authentication does."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the app."""
        self._app = app
        # end def

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve the request with its caller as the authenticated user, and in `CALLER`."""
        caller = dict(scope.get('headers', [])).get(CALLER_HEADER.encode(), b'').decode()
        scope['user'] = AuthenticatedUser(AccessToken(token=f'token-{caller}', client_id=caller, scopes=[]))
        token = CALLER.set(caller)
        try:
            await self._app(scope, receive, send)
        finally:
            CALLER.reset(token)
            # end try
        # end def

    # end class


class TestResumedHandlerRequest:
    """F16: a resumed handler reads the request it is served under now from its call, not its context."""

    async def test_the_call_exposes_each_accepted_retrys_request_and_access_token(self) -> None:
        """Before the accept, the opener's request; after it, the retry's. The contextvars stay the opener's."""
        seen: list[tuple[str, str | None, str | None, str | None]] = []

        def build(seam: McpAuditTransport) -> Server:
            server = Server('request-reading-tool')

            async def call_tool(context: Any, _params: CallToolRequestParams) -> CallToolResult:
                call = seam.call(context.request_id)
                call.negotiate(TOOL_CAPABILITY)

                def note(when: str) -> None:
                    request = call.request
                    header = request.headers.get(CALLER_HEADER) if isinstance(request, Request) else None
                    token = call.access_token
                    seen.append((when, header, token.client_id if token is not None else None, CALLER.get()))
                    # end def

                note('before')
                session = AmcpSession(call, call.session_id)
                async with session.action(
                    'db.read', TargetResource(kind='table', ref='x'), mutates=False, egress=False
                ):
                    note('after-accept')
                    # end async with
                return CallToolResult(content=[TextContent(type='text', text='read')])
                # end def

            server.add_request_handler('tools/list', PaginatedRequestParams, _list_tools)  # type: ignore[arg-type]
            server.add_request_handler('tools/call', CallToolRequestParams, call_tool)  # type: ignore[arg-type]
            return server
            # end def

        host = _host()
        async with _instance(_ToolState(), 'one', factory=build, middleware=_AuthenticatingMiddleware) as tool:
            session_id = host.open_session()
            alice = _headers(session_id, **{CALLER_HEADER: 'alice'})
            first = (await _post(tool.url, _body(1, session_id=session_id), alice)).json()['result']
            answers = await _answered(host, first, session_id)
            retry = _body(2, session_id=session_id, state=first['requestState'], responses=answers)
            await _post(tool.url, retry, _headers(session_id, **{CALLER_HEADER: 'bob'}))
            # end async with
        assert seen == [('before', 'alice', 'alice', 'alice'), ('after-accept', 'bob', 'bob', 'alice')]
        # end def

    # end class


class TestForwardedStreamBreaks:
    """F17: a deployment's forward whose SSE body breaks off after the response started."""

    async def test_the_break_is_told_in_the_stream_and_the_response_starts_once(self) -> None:
        """The stream ends with the unknown-outcome error event; no second response is attempted."""

        @asynccontextmanager
        async def breaking(instance: str, request: ForwardedRequest) -> AsyncIterator[ForwardedResponse | None]:
            async def body() -> AsyncIterator[bytes]:
                yield b'event: message\r\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\r\n\r\n'
                raise RuntimeError('the deployment forward broke')
                # end def

            yield ForwardedResponse(status=200, headers=[('content-type', 'text/event-stream')], body=body())
            # end def

        session_id = _session()
        async with _instance(_ToolState(), 'b', forward=breaking) as b:
            body = _body(1, session_id=session_id, state=f'amcp.a.{FORGED_SECRET}')
            response = await _post(b.url, body, _headers(session_id))
            # end async with
        events = [line[len('data: ') :] for line in response.text.split('\r\n') if line.startswith('data: ')]
        assert response.status_code == 200
        assert json.loads(events[-1]) == {
            'jsonrpc': '2.0',
            'id': 1,
            'error': {'code': -32603, 'message': FORWARD_OUTCOME_UNKNOWN_MESSAGE},
        }
        # end def

    # end class


class _StallingSealer(_SlowSealer):
    """Seals the first outcome at once and every later one only after a second."""

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Seal the first quickly, stall on the rest."""
        await anyio.sleep(0.02 if event.get('n') == 0 else 1.0)
        self.sealed.append(event.get('n'))
        # end def

    # end class


class TestCloseBound:
    """F19: closing the host seam keeps to its bound, and says how many outcomes it could not seal."""

    async def test_the_drain_of_queued_seals_keeps_to_the_close_bound(self) -> None:
        """Jobs queued behind a cancelled worker are each held to the bound, not run to completion."""
        endpoint = _StallingSealer()
        to_host, host_reads = anyio.create_memory_object_stream[SessionMessage | Exception](8)
        host_writes, from_host = anyio.create_memory_object_stream[SessionMessage](8)
        cancelled_at = 0.0
        with anyio.CancelScope() as around:
            async with (
                to_host,
                from_host,
                McpAuditReceiver(host_reads, host_writes, endpoint, request_timeout=0.2) as receiver,  # type: ignore[arg-type]
            ):
                opening = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': TOOL_NAME}}
                await receiver.write_stream.send(SessionMessage(JSONRPCRequest.model_validate(opening)))
                session_id = (await from_host.receive()).message.params['_meta'][EXTENSION_ID]['session_id']  # type: ignore[union-attr]
                for n in range(3):
                    outcome = JSONRPCNotification(
                        jsonrpc='2.0', method='audit/outcome', params={'session_id': session_id, 'n': n}
                    )
                    await to_host.send(SessionMessage(outcome))
                    # end for
                await anyio.sleep(0.01)
                cancelled_at = anyio.current_time()
                around.cancel()
                await anyio.sleep_forever()
                # end async with
            # end with
        assert anyio.current_time() - cancelled_at < 0.8
        assert endpoint.sealed == [0]
        # end def

    async def test_the_unsealed_outcomes_of_the_job_in_progress_are_counted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A result's outcomes cut short at the bound are named in the warning, one by one."""
        endpoint = _StallingSealer()
        to_host, host_reads = anyio.create_memory_object_stream[SessionMessage | Exception](8)
        host_writes, from_host = anyio.create_memory_object_stream[SessionMessage](8)
        with caplog.at_level(logging.WARNING, logger='auditable_mcp.mcp.seam'):
            async with (
                to_host,
                from_host,
                McpAuditReceiver(host_reads, host_writes, endpoint, request_timeout=0.2) as receiver,  # type: ignore[arg-type]
            ):
                await receiver.write_stream.send(
                    SessionMessage(JSONRPCRequest.model_validate(_body(1, session_id=None)))
                )
                session_id = (await from_host.receive()).message.params['_meta'][EXTENSION_ID]['session_id']  # type: ignore[union-attr]
                outcomes = [{'n': n} for n in range(5)]
                result = {'content': [], '_meta': {EXTENSION_ID: {'session_id': session_id, 'events': outcomes}}}
                await to_host.send(SessionMessage(JSONRPCResponse(jsonrpc='2.0', id=1, result=result)))
                await receiver.read_stream.receive()
                # end async with
            # end with
        assert endpoint.sealed == [0]
        assert any('4 outcome(s) not sealed' in record.getMessage() for record in caplog.records)
        # end def

    async def test_a_retry_that_could_not_be_written_leaves_its_round_open(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A full connection refuses the retry without consuming its token, so the round can be retried."""
        seen = _OwnRounds()
        session_id = _session()
        async with _instance(_ToolState(), 'one', factory=_own_round_factory(seen)) as tool:
            opened = (await _post(tool.url, _body(1, session_id=session_id), _headers(session_id))).json()
            token = opened['result']['requestState']
            connection = tool.entry._sessions[session_id]
            original = connection.write

            def full(message: SessionMessage) -> None:
                raise anyio.WouldBlock
                # end def

            monkeypatch.setattr(connection, 'write', full)
            refused = await _post(tool.url, _retry_body(2, session_id, token), _headers(session_id))
            monkeypatch.setattr(connection, 'write', original)
            concluded = await _post(tool.url, _retry_body(3, session_id, token), _headers(session_id))
            # end async with
        assert refused.json()['error'] == {'code': INVALID_PARAMS, 'message': NO_OPEN_ROUND_MESSAGE}
        assert concluded.json()['result']['content'][0]['text'] == 'concluded'
        assert seen.states == [None, OWN_STATE]
        # end def

    # end class
