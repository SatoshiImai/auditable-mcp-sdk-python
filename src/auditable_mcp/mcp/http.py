"""Serving §6.4 over Streamable HTTP, and round affinity (§6.4).

Under MCP 2026-07-28 the official Streamable HTTP handler serves every POST on its own: it dispatches
the request straight into the server and answers it, and no stream pair outlives the request. The §6.4
seam keeps a call's handler suspended between rounds, so it needs a connection that lives as long as
the call does. `AuditedStreamableHTTP` gives each audited call one: an in-memory stream pair with the
tool's server running on it behind `McpAuditTransport`, held in this entry's registry. Each POST of the
call - the `tools/call` that opens its audit session, and every retry - is written into that connection
under an id of the connection's own, since independent HTTP requests may repeat ids, and the HTTP
response carries what the connection answers on it, in the `contextvars` of the HTTP request that
carried it. The connection closes when the call concludes, when the request that carries it is
cancelled, when it expires, or when it is evicted. A call is running while a request of it is in
flight, while its handler runs with no round out, or while an operation the host accepted has not
emitted its outcome, and undelivered while it holds outcomes or a final answer for its next retry. A
running call is neither evicted nor expired: the entry never cancels an accepted operation. An
undelivered one expires after `idle_timeout` with no request in flight - its host has had that long to
retry - but is not evicted. The registry holds at most `max_held_calls`, evicting the least recently
used call that is neither to make room, and refusing a new audited call while none may be evicted.

Every round of an audited call goes out under a token this entry can route: the seam's rounds carry
their own, and a round the tool returns with a `requestState` of its own goes out under one the entry
issues in its place, the tool's `requestState` being given back to its retry. So a request of the call
that carries a `requestState` is always a retry (§6.4): one that names no round held here is forwarded
or refused, and never served as the call's first request; and a first request for a session already
held is refused.

Every POSTed JSON-RPC request whose `_meta` names a protocol version (the 2026-07-28 envelope), of any
method, has its `Auditable-Mcp-Session` header checked against the body's `session_id`: absent while
the body carries one, present while it carries none, or different, it is refused with HTTP 400 and
`-32020` (§6.4). Of those, this entry serves only a `tools/call` that carries an audit `session_id` or
echoes a `requestState` under the reserved round-token prefix. Everything else - other methods,
unaudited calls, the handshake era - reaches the official handler untouched. Because the taken requests
bypass it, this entry applies the checks the official modern handler applies (Host/Origin and
Content-Type, `Accept`, a duplicated routing header, the request metadata headers against the body,
`Mcp-Param-*` against the tool's input schema, the body size limit), and answers a validation failure
at the status the official handler uses for it. What the call itself answers, and a refusal of a retry
or of a principal, goes in-band, with HTTP 200, as a handler's error does.

Round affinity (§6.4). A deployment that runs several instances delivers each retry to the instance
that holds its round: an intermediary that routes on `Auditable-Mcp-Session` does it without reading
the body, and otherwise the instance that receives a retry it does not hold forwards it to the one its
round token names, through `forward`. Forwarding goes only to an instance the deployment's `resolve`
knows, never to an address the request supplied, and a forwarded request is marked so that it is
never forwarded again. A retry that can be neither served nor forwarded, or whose forward provably
never reached the owner, is refused as a replay is, and nothing is performed (§10.11); one whose
forward failed after it was sent is answered as an unknown outcome, since the owner may have acted.
"""

from __future__ import annotations

import contextvars
import json
import logging
import math
import secrets
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, Self

import anyio
import anyio.abc
import httpx2
from anyio import BrokenResourceError, ClosedResourceError
from anyio.streams.memory import MemoryObjectSendStream
from mcp.server.lowlevel import Server
from mcp.server.streamable_http import check_accept_headers
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import RequestBodyLimitMiddleware, TransportSecurityMiddleware
from mcp.shared._context_streams import ContextReceiveStream
from mcp.shared.inbound import (
    ERROR_CODE_HTTP_STATUS,
    MCP_PARAM_HEADER_PREFIX,
    InboundLadderRejection,
    InboundModernRoute,
    classify_inbound_request,
    find_duplicated_routing_header,
    validate_mcp_param_headers,
)
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    ErrorData,
    JSONRPCError,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    RequestId,
)
from mcp_types import (
    CLIENT_INFO_META_KEY,
    HEADER_MISMATCH,
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    PROTOCOL_VERSION_META_KEY,
)
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Message, Receive, Scope, Send

from auditable_mcp.fields import SESSION_ID
from auditable_mcp.mcp.declaration import audit_extension
from auditable_mcp.mcp.seam import (
    AFFINITY_HEADER,
    CANCELLED_METHOD,
    DEFAULT_REQUEST_TIMEOUT,
    INPUT_REQUIRED,
    INSTANCE_PATTERN,
    MAX_IDLE_SESSIONS,
    META,
    NO_OPEN_ROUND_MESSAGE,
    REQUEST_ID,
    REQUEST_STATE,
    RESULT_TYPE,
    ROUND_TOKEN_PREFIX,
    TOOLS_CALL_METHOD,
    Frame,
    McpAuditTransport,
    _concludes,
    _meta_of,
    check_instance,
    new_instance_id,
    round_token_instance,
)
from auditable_mcp.models import EXTENSION_ID, AuditCapability

logger = logging.getLogger(__name__)

# Set by a forwarder on the request it forwards. An instance never forwards a request that carries it,
# so a request is forwarded at most once, and a client that sets it only loses forwarding (§6.4).
FORWARDED_HEADER: Final = 'Auditable-Mcp-Forwarded'
FORWARDED_VALUE: Final = '1'

# How long a call's connection is kept with no request of the call in flight. A round the host answers
# on the spot is retried within its `request_timeout`; one that also asks the client for input waits on
# a person. Both SDKs use this bound.
DEFAULT_IDLE_TIMEOUT: Final = 600.0

# What a call's request is refused with, in-band, where no round or call can serve it.
PRINCIPAL_MISMATCH_MESSAGE: Final = 'this round was opened by another principal (§6.4)'
REGISTRY_FULL_MESSAGE: Final = 'this instance holds as many audited calls as it may'
SESSION_ALREADY_OPEN_MESSAGE: Final = 'this session is already open (§6.3)'
FORWARD_OUTCOME_UNKNOWN_MESSAGE: Final = 'forwarding failed after the retry was sent; its outcome is unknown (§6.4)'
CONNECTION_CLOSED_MESSAGE: Final = 'the audited call ended before it answered this request'
# Where the affinity header's counterpart lives in the body, as a header mismatch names it.
SESSION_BODY_PATH: Final = f'params._meta["{EXTENSION_ID}"].{SESSION_ID}'

# The official modern handler's keepalive interval once a response has committed to SSE, and the
# window in which a response that has emitted nothing is still answered as JSON.
SSE_PING_INTERVAL: Final = 15.0
_SSE_HEADERS: Final = [
    (b'content-type', b'text/event-stream'),
    (b'cache-control', b'no-cache, no-transform'),
    (b'connection', b'keep-alive'),
    (b'x-accel-buffering', b'no'),
]
_SSE_PING: Final = b': ping\r\n\r\n'

# The notifications one request may have queued for its response before further ones are dropped.
MAX_QUEUED_NOTIFICATIONS: Final = 256

# The `tools/list` pages read to find a tool's input schema, as the official modern handler bounds it.
_TOOLS_LIST_PAGE_CAP: Final = 100
_TOOLS_LIST_METHOD: Final = 'tools/list'

# The buffer of each direction of a call's connection.
_CONNECTION_BUFFER: Final = 16

# Request fields a forwarder does not copy: RFC 9110 §7.6.1 connection-specific ones, and the framing and
# `Host` the forwarder's own client sets for the target.
_NOT_FORWARDED: Final = frozenset(
    {
        'connection',
        'content-length',
        'host',
        'keep-alive',
        'proxy-authorization',
        'proxy-connection',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    }
)
# Response fields that describe the forwarder's own hop; the body is relayed decoded.
_NOT_RELAYED: Final = frozenset({'connection', 'content-encoding', 'content-length', 'keep-alive', 'transfer-encoding'})
# The forwarder waits on the owner as long as the owner takes to answer the round: its read is not
# bounded here but by the client, whose closing the connection ends the forwarded request with it.
DEFAULT_FORWARD_TIMEOUT: Final = httpx2.Timeout(30.0, read=None)

_OK: Final = 200
_BAD_REQUEST: Final = 400
# The answers the official handler sends as HTTP 400 whatever produced them, which a client reads as the
# request's rejection rather than as the call's result.
_REJECTION_CODES: Final = frozenset({HEADER_MISMATCH, MISSING_REQUIRED_CLIENT_CAPABILITY})
_REDIRECTS: Final = range(300, 400)
_SSE_CONTENT_TYPE: Final = 'text/event-stream'
# The random bytes of a round token the entry issues for a tool's own round, as the seam's (§6.4).
_ROUND_TOKEN_BYTES: Final = 32
# What became of a retry this entry forwarded.
_REFUSED: Final = 'refused'
_UNKNOWN: Final = 'unknown'
_RELAYED: Final = 'relayed'
_NOT_ACCEPTABLE: Final = 406
# The failures of a forward that prove the request never reached the owner.
_NOT_SENT: Final = (httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.PoolTimeout, httpx2.ProxyError)
_JSONRPC_VERSION: Final = '2.0'

ToolServerFactory = Callable[[McpAuditTransport], Server[Any]]
PrincipalOf = Callable[[Request], str | None]


@dataclass(frozen=True)
class ForwardedRequest:
    """A retry this instance does not hold, as it is handed to `forward`.

    Attributes:
        headers: The request's header lines as received, in order, the client's credentials included.
        body: The request body as received.
    """

    headers: list[tuple[str, str]]
    body: bytes
    # end class


@dataclass(frozen=True)
class ForwardedResponse:
    """What the instance that holds the round answered, relayed to the client.

    Attributes:
        status: The HTTP status.
        headers: The response header lines, without the connection-specific ones.
        body: The response body, decoded, as it arrives.
    """

    status: int
    headers: list[tuple[str, str]]
    body: AsyncIterator[bytes]
    # end class


class ForwardNotDeliveredError(Exception):
    """A forward that provably never reached the owner: the retry is refused as a replay is (§6.4).

    A `Forward` may raise it instead of yielding None, for a failure it knows came before the request
    left - no such instance, a connection that was never made.
    """

    # end class


class ForwardOutcomeUnknownError(Exception):
    """A forward failed after the retry was sent: the owner may have acted on it (§6.4).

    A `Forward` raises it on entering, or from the response body, for a failure it cannot prove came
    before the owner received the request. The retry is then answered with
    `FORWARD_OUTCOME_UNKNOWN_MESSAGE`, never refused as a replay: a replay refusal says nothing was
    performed, which is not known.
    """

    # end class


# `forward(instance, request)` delivers a retry to the instance that holds its round and yields that
# instance's response. It yields None, or raises `ForwardNotDeliveredError`, only when the request
# provably did not reach the owner - no such instance, a connection that was never made - which refuses
# the retry as a replay; any other failure is an unknown outcome.
Forward = Callable[[str, ForwardedRequest], AbstractAsyncContextManager[ForwardedResponse | None]]


class HttpForwarder:
    """A `Forward` over HTTP: it posts the retry to the endpoint the deployment names for the instance.

    `resolve` is the only source of an address. The instance name comes from a client-controlled
    `requestState`, so it is checked against `INSTANCE_PATTERN` and then looked up; a name `resolve`
    does not know is refused, and no part of the request ever becomes part of a URL. Redirects are not
    followed - a redirect is read as not delivered - and the environment's proxy settings are not read.

    The owner answers a retry once the round's work is done, so the client's read timeout must be
    unbounded or longer than any operation: a read that times out after the request was sent is a
    forward whose outcome is unknown. The default client's read timeout is unbounded.
    """

    def __init__(
        self,
        resolve: Callable[[str], str | None],
        *,
        client: httpx2.AsyncClient | None = None,
        timeout: httpx2.Timeout = DEFAULT_FORWARD_TIMEOUT,
    ) -> None:
        """Bind the resolver, and the HTTP client the requests go out on.

        Args:
            resolve: Maps an instance of this deployment to the URL of its MCP endpoint, or returns None
                for a name the deployment does not know.
            client: The client to post with. One is created, and closed by `aclose`, when none is given.
            timeout: The timeout of a client this forwarder creates.
        """
        self._resolve = resolve
        self._owns_client = client is None
        self._client = client or httpx2.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)
        # end def

    async def aclose(self) -> None:
        """Close the HTTP client, if this forwarder created it."""
        if self._owns_client:
            await self._client.aclose()
            # end if
        # end def

    async def __aenter__(self) -> Self:
        """Use the forwarder for the lifetime of a block."""
        return self
        # end def

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the client it created."""
        await self.aclose()
        # end def

    def __call__(
        self, instance: str, request: ForwardedRequest
    ) -> AbstractAsyncContextManager[ForwardedResponse | None]:
        """Forward `request` to `instance`, yielding its response, or None when it cannot be delivered.

        Args:
            instance: The instance the retry's round token names.
            request: The retry as this instance received it.

        Returns:
            A context manager that yields the owner's response while it is relayed.
        """
        return self._forward(instance, request)
        # end def

    @asynccontextmanager
    async def _forward(self, instance: str, request: ForwardedRequest) -> AsyncIterator[ForwardedResponse | None]:
        """Post the retry, marked as forwarded, and yield the response for as long as it is relayed."""
        try:
            url = self._resolve(instance) if INSTANCE_PATTERN.fullmatch(instance) is not None else None
        except Exception:
            # `resolve` is the deployment's code; whatever it raises, nothing was sent.
            logger.exception('resolving instance %r raised; the retry is refused', instance)
            url = None
            # end try
        if url is None:
            logger.warning('a retry names instance %r, which this deployment does not know; it is refused', instance)
            yield None
            return
            # end if
        forwarded = FORWARDED_HEADER.lower()
        headers = [
            (name, value)
            for name, value in request.headers
            if name.lower() not in _NOT_FORWARDED and name.lower() != forwarded
        ]
        headers.append((FORWARDED_HEADER, FORWARDED_VALUE))
        outgoing = self._client.build_request('POST', url, headers=headers, content=request.body)
        try:
            response = await self._client.send(outgoing, stream=True, follow_redirects=False)
        except _NOT_SENT as error:
            logger.warning('a retry could not be forwarded to instance %r: %s', instance, error)
            yield None
            return
        except httpx2.HTTPError as error:
            raise ForwardOutcomeUnknownError(f'forwarding to instance {instance!r} failed: {error}') from error
            # end try
        if response.status_code in _REDIRECTS:
            await response.aclose()
            logger.warning('instance %r answered a forwarded retry with a redirect; it is refused', instance)
            yield None
            return
            # end if
        try:
            yield ForwardedResponse(
                status=response.status_code,
                headers=[
                    (name, value) for name, value in response.headers.multi_items() if name.lower() not in _NOT_RELAYED
                ],
                body=_decoded_body(response, instance),
            )
        finally:
            await response.aclose()
            # end try
        # end def

    # end class


async def _decoded_body(response: httpx2.Response, instance: str) -> AsyncIterator[bytes]:
    """The response body, decoded, ending where the owner's ended.

    Raises:
        ForwardOutcomeUnknownError: The body broke off.
    """
    try:
        async for chunk in response.aiter_bytes():
            yield chunk
            # end for
    except httpx2.HTTPError as error:
        raise ForwardOutcomeUnknownError(f'the response from instance {instance!r} broke off: {error}') from error
        # end try
    # end def


class _Waiter:
    """One request written into a call's connection, and the frames that answer it.

    The request goes into the connection under `internal_id`; its answer goes back out under the id the
    request was posted with.
    """

    def __init__(self, internal_id: int, request_id: RequestId) -> None:
        """Open the queue its answer and its notifications arrive on."""
        self.internal_id = internal_id
        self.request_id = request_id
        self.send, self.receive = anyio.create_memory_object_stream[Frame](math.inf)
        # end def

    def notify(self, frame: JSONRPCNotification) -> None:
        """Queue a notification for the response, dropping it beyond MAX_QUEUED_NOTIFICATIONS."""
        if self.send.statistics().current_buffer_used >= MAX_QUEUED_NOTIFICATIONS:
            logger.debug(
                'request %s has %s notifications queued; %s is dropped',
                self.request_id,
                MAX_QUEUED_NOTIFICATIONS,
                frame.method,
            )
            return
            # end if
        self._put(frame)
        # end def

    def answer(self, frame: JSONRPCResponse | JSONRPCError) -> None:
        """Deliver the request's answer, under the id it was posted with; nothing follows it."""
        self._put(frame.model_copy(update={'id': self.request_id}))
        self.send.close()
        # end def

    def _put(self, frame: Frame) -> None:
        """Queue a frame unless the answer has already been delivered."""
        try:
            self.send.send_nowait(frame)
        except (BrokenResourceError, ClosedResourceError):
            logger.debug('request %s is already answered; a frame for it is dropped', self.request_id)
            # end try
        # end def

    # end class


class _CallConnection:
    """The connection one audited call is served over, from its opening request to its end (§6.4)."""

    def __init__(self, session_id: str, principal: str | None) -> None:
        """Create both ends of the connection; the tool's server is started on it separately."""
        self.session_id = session_id
        self.principal = principal
        # What the entry writes, which the tool's seam reads as its transport's inbound stream. Each
        # message carries the context of the HTTP request that wrote it, which is the context the tool's
        # handler for it runs in (authentication, trace), as over the official transports.
        to_tool, raw_reads = anyio.create_memory_object_stream[tuple[contextvars.Context, SessionMessage | Exception]](
            _CONNECTION_BUFFER
        )
        self.to_tool: MemoryObjectSendStream[tuple[contextvars.Context, SessionMessage | Exception]] = to_tool
        self.tool_reads = ContextReceiveStream[SessionMessage | Exception](raw_reads)
        # What the tool's seam writes, which the entry reads and answers the POSTs with.
        self.tool_writes, self.from_tool = anyio.create_memory_object_stream[SessionMessage](_CONNECTION_BUFFER)
        # Requests in flight, by the id the connection knows them by, oldest first.
        self.waiters: dict[int, _Waiter] = {}
        # The round tokens the connection has issued and no retry has presented yet.
        self.tokens: set[str] = set()
        # The tool's own rounds (§6.4): the token the entry issued in place of each `requestState` the
        # tool returned, and that `requestState`, which its retry is given back.
        self.own_rounds: dict[str, object] = {}
        # The seam the call is served behind, once it runs.
        self.seam: McpAuditTransport | None = None
        # The called tool's input schema, once looked up; None when it could not be.
        self.schema_read = False
        self.input_schema: object | None = None
        self.in_flight = 0
        self.activity = anyio.Event()
        self.closed = False
        self.next_id = 0
        # end def

    def touch(self) -> None:
        """Wake the idle watcher: a request started or ended, or the connection closed."""
        self.activity.set()
        self.activity = anyio.Event()
        # end def

    @property
    def running(self) -> bool:
        """Whether closing the connection would cut the call short: a request in flight, or work under way.

        A running call is neither evicted nor expired: the entry never cancels an accepted operation.
        """
        return bool(self.in_flight) or (self.seam is not None and self.seam.running)
        # end def

    @property
    def evictable(self) -> bool:
        """Whether the call may be closed to make room: not running, and holding nothing undelivered.

        A call that holds outcomes or a final answer for its next retry is not evicted, but it does
        expire: its host has had `idle_timeout` to retry.
        """
        return not self.running and not (self.seam is not None and self.seam.undelivered)
        # end def

    def write(self, message: SessionMessage) -> None:
        """Write a message into the connection, carrying the context of the task that writes it.

        Raises:
            anyio.WouldBlock: The tool's side is not reading.
            BrokenResourceError: The tool's side is gone.
            ClosedResourceError: The connection is closed.
        """
        self.to_tool.send_nowait((contextvars.copy_context(), message))
        # end def

    # end class


def _request_frame(decoded: object) -> dict[str, Any] | None:
    """The body as one JSON-RPC request, or None when it is anything else."""
    if not isinstance(decoded, dict) or decoded.get('jsonrpc') != _JSONRPC_VERSION:
        return None
        # end if
    request_id, method, params = decoded.get('id'), decoded.get('method'), decoded.get('params')
    if not isinstance(method, str) or isinstance(request_id, bool) or not isinstance(request_id, str | int):
        return None
        # end if
    if params is not None and not isinstance(params, dict):
        return None
        # end if
    return decoded
    # end def


def _body_session(params: object) -> str | None:
    """The `session_id` the body's audit `_meta` member carries, or None when it carries no string one."""
    member = _meta_of(params).get(EXTENSION_ID)
    session_id = member.get(SESSION_ID) if isinstance(member, dict) else None
    return session_id if isinstance(session_id, str) else None
    # end def


def _header_value(raw: list[tuple[str, str]], name: str) -> str | None:
    """A header's value as a Fetch `Headers` reads it: every occurrence, joined by `, `, or None."""
    wanted = name.lower()
    values = [value for header, value in raw if header.lower() == wanted]
    return ', '.join(values) if values else None
    # end def


def _error(request_id: RequestId | None, code: int, message: str) -> JSONRPCError:
    """A JSON-RPC error for the request."""
    return JSONRPCError(jsonrpc='2.0', id=request_id, error=ErrorData(code=code, message=message))
    # end def


def _status_of(frame: JSONRPCResponse | JSONRPCError) -> int:
    """The HTTP status the official handler sends with this answer."""
    if isinstance(frame, JSONRPCError):
        return ERROR_CODE_HTTP_STATUS.get(frame.error.code, _OK)
        # end if
    return _OK
    # end def


def _wire(frame: Frame) -> dict[str, Any]:
    """A frame as it goes on the wire."""
    body = frame.model_dump(mode='json', by_alias=True, exclude_none=True)
    if isinstance(frame, JSONRPCError) and frame.id is None:
        body['id'] = None
        # end if
    return body
    # end def


async def _write_json(
    frame: JSONRPCResponse | JSONRPCError, scope: Scope, receive: Receive, send: Send, *, status: int = _OK
) -> None:
    """Answer the POST with one JSON-RPC message; in-band, with HTTP 200, unless `status` says otherwise."""
    body = json.dumps(_wire(frame), separators=(',', ':'))
    await Response(body, status_code=status, media_type='application/json')(scope, receive, send)
    # end def


async def _write_rejection(
    request_id: RequestId, rejection: InboundLadderRejection, scope: Scope, receive: Receive, send: Send
) -> None:
    """Answer a validation failure as the official handler does, at the status its table gives the code."""
    frame = _rejection(request_id, rejection)
    await _write_json(frame, scope, receive, send, status=_status_of(frame))
    # end def


def _answer_status(frame: JSONRPCResponse | JSONRPCError) -> int:
    """The HTTP status of the call's answer: in-band 200, except for an error that rejects the request.

    `-32020` and `-32021` say the request itself was not acceptable, and the official handler sends
    them as HTTP 400 whatever produced them; everything else the call answers is in-band.
    """
    if isinstance(frame, JSONRPCError) and frame.error.code in _REJECTION_CODES:
        return _BAD_REQUEST
        # end if
    return _OK
    # end def


def _sse_event(frame: Frame) -> bytes:
    """One SSE `message` event carrying a JSON-RPC message."""
    return f'event: message\r\ndata: {json.dumps(_wire(frame), separators=(",", ":"))}\r\n\r\n'.encode()
    # end def


def _rejection(request_id: RequestId, rejection: InboundLadderRejection) -> JSONRPCError:
    """A validation rejection as the JSON-RPC error the official handler sends for it."""
    return JSONRPCError(
        jsonrpc='2.0',
        id=request_id,
        error=ErrorData(code=rejection.code, message=rejection.message, data=rejection.data),
    )
    # end def


def _affinity_rejection(header: str | None, body: str | None) -> InboundLadderRejection | None:
    """`-32020` unless `Auditable-Mcp-Session` agrees with the body's `session_id` (§6.4).

    The header is never trusted over the body. A header sent twice is read as its values joined, which
    agrees with no `session_id`.
    """
    if header == body:
        return None
        # end if
    if header is None:
        detail = f'the body carries {SESSION_BODY_PATH} but the {AFFINITY_HEADER} header is absent'
    elif body is None:
        detail = f'the {AFFINITY_HEADER} header is present but the body carries no {SESSION_BODY_PATH}'
    else:
        detail = f'the {AFFINITY_HEADER} header does not match {SESSION_BODY_PATH}'
        # end if
    return InboundLadderRejection(
        code=HEADER_MISMATCH,
        message=f'Bad Request: the request headers and body disagree: {detail}',
        data={'mismatch': {'header': AFFINITY_HEADER, 'body': SESSION_BODY_PATH}},
    )
    # end def


def _replaying(body: bytes, receive: Receive) -> Receive:
    """A `receive` that yields the already-read body once, then what the client sends after it."""
    pending: list[Message] = [{'type': 'http.request', 'body': body, 'more_body': False}]

    async def replay() -> Message:
        if pending:
            return pending.pop()
            # end if
        return await receive()
        # end def

    return replay
    # end def


async def _read_body(receive: Receive) -> bytes:
    """The whole request body. The size limit is enforced around this entry, before it reads."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message['type'] != 'http.request':
            break
            # end if
        chunks.append(message.get('body', b''))
        if not message.get('more_body', False):
            break
            # end if
        # end while
    return b''.join(chunks)
    # end def


class AuditedStreamableHTTP:
    """An ASGI app that serves the audited calls of a Streamable HTTP endpoint behind the §6.4 seam.

    It wraps the official `StreamableHTTPSessionManager`, whose settings it follows: its security
    settings, its body size limit, and its response mode. Mount it where the manager's handler would be
    mounted, and enter `run()` beside `manager.run()` in the application's lifespan.

    The official manager serves everything but the audited calls, so the tool's `server/discover` comes
    from `manager.app`; this entry declares the tool's capability there at construction (§6.1), which is
    the declaration the per-call seams negotiate with. It writes it into `manager.app.extensions`, and
    refuses a server that already declares something else under the extension's identifier.
    """

    def __init__(
        self,
        manager: StreamableHTTPSessionManager,
        factory: ToolServerFactory,
        declares: AuditCapability,
        *,
        instance: str | None = None,
        forward: Forward | None = None,
        principal_of: PrincipalOf | None = None,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_held_calls: int = MAX_IDLE_SESSIONS,
    ) -> None:
        """Wrap the official handler and hold what each audited call's connection is built from.

        Args:
            manager: The official session manager, which serves every request this entry does not take.
            factory: Builds the tool's server for one call, given the seam the call is served behind. The
                server's `tools/call` handler finds its call with `seam.call(request_id)`, as over stdio.
            declares: The audit capability this tool declares (§6.1).
            instance: The name round tokens carry for this entry, `INSTANCE_PATTERN`. By default one is
                drawn at random for the entry, so a restarted process never claims an earlier one's round.
            forward: Delivers a retry this entry does not hold to the instance that does (§6.4). Without
                it such a retry is refused.
            principal_of: The authenticated principal of a request, or None. Each held call is bound to
                the principal of the request that opened it, and a request of the call that presents
                another is refused, performing nothing (MRTR requirement 5).
            request_timeout: In seconds, the seam's bound on each wait for the host's answer.
            idle_timeout: In seconds, how long a call that is not running is kept with no request in flight.
            max_held_calls: How many calls the entry holds. Beyond it the least recently used call that is
                neither running nor holding undelivered outcomes is closed; while none is, a new audited
                call is refused.

        Raises:
            ValueError: `instance` does not match `INSTANCE_PATTERN`, a bound is not positive, or
                `manager.app` already declares a different capability under the extension's identifier.
        """
        if not (math.isfinite(idle_timeout) and idle_timeout > 0) or max_held_calls <= 0:
            raise ValueError('idle_timeout must be a positive, finite number of seconds and max_held_calls positive')
            # end if
        self._manager = manager
        self._factory = factory
        self._declares = declares
        self.instance = check_instance(instance if instance is not None else new_instance_id())
        self._forward = forward
        self._principal_of = principal_of
        self._request_timeout = request_timeout
        self._idle_timeout = idle_timeout
        self._max_held_calls = max_held_calls
        self._security = TransportSecurityMiddleware(manager.security_settings)
        self._post = RequestBodyLimitMiddleware(self._handle_post, manager.max_request_body_size)
        # Held calls by session, least recently used first.
        self._sessions: dict[str, _CallConnection] = {}
        self._tokens: dict[str, _CallConnection] = {}
        self._task_group: anyio.abc.TaskGroup | None = None
        # The context the calls' connections run in: the lifespan's, never the context of the request
        # that happens to open a call.
        self._base_context: contextvars.Context | None = None
        declared = audit_extension(declares)
        existing = manager.app.extensions.get(EXTENSION_ID)
        if existing is not None and existing != declared[EXTENSION_ID]:
            raise ValueError(f'the server already declares {EXTENSION_ID} as {existing!r}; the entry declares it')
            # end if
        manager.app.extensions.update(declared)
        # end def

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """Hold the calls' connections for the lifetime of the block; leaving it closes every one."""
        async with anyio.create_task_group() as task_group:
            self._task_group = task_group
            self._base_context = contextvars.copy_context()
            try:
                yield
            finally:
                self._task_group = None
                for connection in list(self._sessions.values()):
                    self._close(connection)
                    # end for
                task_group.cancel_scope.cancel()
                # end try
            # end async with
        # end def

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Check and take the audited calls' POSTs, and pass everything else to the official handler."""
        if scope['type'] == 'http' and scope['method'] == 'POST':
            await self._post(scope, receive, send)
            return
            # end if
        await self._manager.handle_request(scope, receive, send)
        # end def

    async def _handle_post(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Read a POST, check its affinity header, and serve it here if it is a request of an audited call."""
        body = await _read_body(receive)
        replay = _replaying(body, receive)
        try:
            decoded = json.loads(body)
        except (ValueError, RecursionError):
            decoded = None
            # end try
        frame = _request_frame(decoded)
        if frame is None or not isinstance(_meta_of(frame.get('params')).get(PROTOCOL_VERSION_META_KEY), str):
            # Not a request under the 2026-07-28 envelope: the official handler owns every answer to it.
            await self._manager.handle_request(scope, replay, send)
            return
            # end if
        request = Request(scope, replay)
        refused = await self._security.validate_request(request, is_post=True)
        if refused is not None:
            await refused(scope, replay, send)
            return
            # end if
        raw = [(name.decode('latin-1'), value.decode('latin-1')) for name, value in scope['headers']]
        params = frame.get('params')
        affinity = _affinity_rejection(_header_value(raw, AFFINITY_HEADER), _body_session(params))
        if affinity is not None:
            await _write_rejection(frame['id'], affinity, scope, replay, send)
            return
            # end if
        if not self._claims(frame):
            await self._manager.handle_request(scope, replay, send)
            return
            # end if
        try:
            request_frame = JSONRPCRequest.model_validate(frame)
        except ValidationError:
            # Not one request: the official handler answers it as it answers any malformed body.
            await self._manager.handle_request(scope, replay, send)
            return
            # end try
        await self._serve(request_frame, frame, raw, body, request, scope, replay, send)
        # end def

    @staticmethod
    def _claims(frame: dict[str, Any]) -> bool:
        """Whether a request is one this entry serves: an audited call's `tools/call`, or a round's retry."""
        if frame.get('method') != TOOLS_CALL_METHOD:
            return False
            # end if
        params = frame.get('params')
        state = params.get(REQUEST_STATE) if isinstance(params, dict) else None
        retry = isinstance(state, str) and state.startswith(ROUND_TOKEN_PREFIX)
        return retry or _body_session(params) is not None
        # end def

    async def _serve(
        self,
        frame: JSONRPCRequest,
        decoded: dict[str, Any],
        raw: list[tuple[str, str]],
        body: bytes,
        request: Request,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Validate a request as the official handler would, then route it to its call's connection."""
        has_json, has_sse = check_accept_headers(request)
        if not has_json or (not self._manager.json_response and not has_sse):
            await Response(status_code=_NOT_ACCEPTABLE)(scope, receive, send)
            return
            # end if
        duplicated = find_duplicated_routing_header(raw)
        if duplicated is not None:
            rejection = InboundLadderRejection(
                code=HEADER_MISMATCH, message=f'{duplicated} header appears more than once'
            )
            await _write_rejection(frame.id, rejection, scope, receive, send)
            return
            # end if
        verdict = classify_inbound_request(decoded, headers=dict(request.headers))
        if isinstance(verdict, InboundLadderRejection):
            await _write_rejection(frame.id, verdict, scope, receive, send)
            return
            # end if
        params = frame.params or {}
        principal = self._principal_of(request) if self._principal_of is not None else None
        state = params.get(REQUEST_STATE)
        if isinstance(state, str) and state.startswith(ROUND_TOKEN_PREFIX):
            await self._serve_retry(frame, state, principal, verdict, raw, body, request, scope, receive, send)
            return
            # end if
        if state is not None:
            # Every round of an audited call - the tool's own included - goes out under a token this entry
            # issued, so a retry that carries anything else names no round here, and is never served as
            # the call's first request (§6.4).
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
            return
            # end if
        session_id = _body_session(params)
        if session_id is None:
            # Unreachable through `_claims`, which takes a request without a round token only when it
            # carries a session; such a request names no held call.
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
            return
            # end if
        await self._serve_opening(frame, session_id, principal, verdict, request, scope, receive, send)
        # end def

    async def _serve_retry(
        self,
        frame: JSONRPCRequest,
        state: str,
        principal: str | None,
        verdict: InboundModernRoute,
        raw: list[tuple[str, str]],
        body: bytes,
        request: Request,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Resume the round a retry names here, forward it to the instance that holds it, or refuse it."""
        connection = self._tokens.get(state)
        if connection is None:
            await self._not_held(frame, state, raw, body, scope, receive, send)
            return
            # end if
        if state in connection.own_rounds and _body_session(frame.params) != connection.session_id:
            # The tool's own round is served only within the call's audit session: under another or none,
            # the tool would take the retry for a call of its own. The token is left for the call's retry.
            logger.warning(
                'a retry of a round of session %s named another session; it is refused', connection.session_id
            )
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
            return
            # end if
        if principal != connection.principal:
            # Checked before the token is consumed, so a retry another principal presents burns nothing.
            logger.warning('a retry of session %s presented another principal; it is refused', connection.session_id)
            await _write_json(_error(frame.id, INVALID_PARAMS, PRINCIPAL_MISMATCH_MESSAGE), scope, receive, send)
            return
            # end if
        # Consumed before anything awaits, so a concurrent replay of the same token finds no round.
        del self._tokens[state]
        connection.tokens.discard(state)
        own = connection.own_rounds.pop(state, None) if state in connection.own_rounds else None

        def restore() -> None:
            # The retry never reached the seam, so its round is still out and may still be retried.
            if not connection.closed:
                self._tokens[state] = connection
                connection.tokens.add(state)
                if own is not None:
                    connection.own_rounds[state] = own
                    # end if
                # end if
            # end def

        mismatch = await self._param_rejection(connection, frame, verdict, request)
        if mismatch is not None:
            restore()
            await _write_rejection(frame.id, mismatch, scope, receive, send)
            return
            # end if
        if own is not None:
            # The tool's own round: its retry reaches the tool with the `requestState` the tool issued.
            frame = frame.model_copy(update={'params': {**(frame.params or {}), REQUEST_STATE: own}})
            # end if
        await self._exchange(connection, frame, request, scope, receive, send, on_not_written=restore)
        # end def

    async def _not_held(
        self,
        frame: JSONRPCRequest,
        state: str,
        raw: list[tuple[str, str]],
        body: bytes,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """A retry of a round this entry does not hold: forward it where it can go, else refuse it."""
        instance = round_token_instance(state)
        forwarded = _header_value(raw, FORWARDED_HEADER) is not None
        forward = self._forward
        if instance is None or instance == self.instance or forward is None or forwarded:
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
            return
            # end if
        # None while the client is gone: it closed its request, which ends the forwarded one with it.
        result: str | None = None
        async with anyio.create_task_group() as watch:
            watch.start_soon(self._cancel_on_disconnect, receive, watch.cancel_scope, None)
            result = await self._forward_and_relay(forward, instance, frame.id, raw, body, send)
            watch.cancel_scope.cancel()
            # end async with
        if result == _REFUSED:
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
        elif result == _UNKNOWN:
            error = _error(frame.id, INTERNAL_ERROR, FORWARD_OUTCOME_UNKNOWN_MESSAGE)
            await _write_json(error, scope, receive, send)
            # end if
        # end def

    @staticmethod
    async def _forward_and_relay(
        forward: Forward,
        instance: str,
        request_id: RequestId,
        raw: list[tuple[str, str]],
        body: bytes,
        send: Send,
    ) -> str:
        """Forward a retry and relay the owner's answer; say whether it was relayed, refused, or is unknown.

        Only a forward that yields None or raises `ForwardNotDeliveredError` proves the owner never
        received the retry. A forward that raises anything else - `ForwardOutcomeUnknownError`, or an
        error of a deployment's own `forward` - may have reached the owner, so the retry's outcome is
        unknown, never a replay (§6.4).
        """
        try:
            async with forward(instance, ForwardedRequest(headers=raw, body=body)) as response:
                if response is None:
                    return _REFUSED
                    # end if
                await AuditedStreamableHTTP._relay(response, request_id, send)
                return _RELAYED
                # end async with
        except ForwardNotDeliveredError as error:
            logger.warning('a retry could not be forwarded to instance %r: %s', instance, error)
            return _REFUSED
        except ForwardOutcomeUnknownError as error:
            logger.warning('a retry forwarded to instance %r has an unknown outcome: %s', instance, error)
            return _UNKNOWN
        except Exception:
            # A deployment's `forward` is its own code; whatever it raises is answered in-band, never as
            # a failure of this entry, and nothing about delivery can be concluded from it.
            logger.exception('forwarding a retry to instance %r raised', instance)
            return _UNKNOWN
            # end try
        # end def

    @staticmethod
    async def _relay(response: ForwardedResponse, request_id: RequestId, send: Send) -> None:
        """Answer the POST with the owner's response.

        A JSON answer is read whole before any of it is sent, so a body that breaks off is still
        answered with an error. An SSE answer is relayed as it arrives; one that breaks off ends with an
        error event for the request.

        Raises:
            ForwardOutcomeUnknownError: A JSON answer broke off.
        """
        headers = [(name.lower().encode('latin-1'), value.encode('latin-1')) for name, value in response.headers]
        content_type = next((value for name, value in response.headers if name.lower() == 'content-type'), '')
        if not content_type.lower().startswith(_SSE_CONTENT_TYPE):
            whole = b''.join([chunk async for chunk in response.body])
            await send({'type': 'http.response.start', 'status': response.status, 'headers': headers})
            await send({'type': 'http.response.body', 'body': whole, 'more_body': False})
            return
            # end if
        await send({'type': 'http.response.start', 'status': response.status, 'headers': headers})
        try:
            async for chunk in response.body:
                await send({'type': 'http.response.body', 'body': chunk, 'more_body': True})
                # end for
        except Exception:
            # The response has started, so whatever broke the body - the ready forwarder's
            # `ForwardOutcomeUnknownError` or anything a deployment's own `forward` raises - can only be
            # told in the stream itself.
            logger.exception('a forwarded SSE answer broke off')
            broken = _sse_event(_error(request_id, INTERNAL_ERROR, FORWARD_OUTCOME_UNKNOWN_MESSAGE))
            await send({'type': 'http.response.body', 'body': broken, 'more_body': True})
            # end try
        await send({'type': 'http.response.body', 'body': b'', 'more_body': False})
        # end def

    async def _serve_opening(
        self,
        frame: JSONRPCRequest,
        session_id: str,
        principal: str | None,
        verdict: InboundModernRoute,
        request: Request,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Serve a request that carries an audit session: on the call's connection, opened if need be."""
        if session_id in self._sessions:
            # The host issues a fresh session for every call (§6.3); a first request of a session already
            # held is not one of its call's requests, and never reaches that call.
            logger.warning('a first request named session %s, which is already open; it is refused', session_id)
            await _write_json(_error(frame.id, INVALID_PARAMS, SESSION_ALREADY_OPEN_MESSAGE), scope, receive, send)
            return
            # end if
        connection = self._open(session_id, principal)
        if connection is None:
            await _write_json(_error(frame.id, INTERNAL_ERROR, REGISTRY_FULL_MESSAGE), scope, receive, send)
            return
            # end if
        mismatch = await self._param_rejection(connection, frame, verdict, request)
        if mismatch is not None:
            self._close(connection)
            await _write_rejection(frame.id, mismatch, scope, receive, send)
            return
            # end if
        await self._exchange(connection, frame, request, scope, receive, send)
        # end def

    def _open(self, session_id: str, principal: str | None) -> _CallConnection | None:
        """Open a call's connection and start the tool's server on it; None when the registry is full."""
        task_group, base_context = self._task_group, self._base_context
        if task_group is None or base_context is None:
            raise RuntimeError('the audited HTTP entry is not running; enter `run()` in the lifespan first')
            # end if
        if len(self._sessions) >= self._max_held_calls:
            # Closing a running call would cancel an operation under way, or a request being answered, and
            # closing one that holds undelivered outcomes would drop them while its host may still retry.
            evicted = next((held for held in self._sessions.values() if held.evictable), None)
            if evicted is None:
                logger.warning(
                    '%s audited calls are held and none may be closed; a new call is refused', len(self._sessions)
                )
                return None
                # end if
            logger.warning(
                'more than %s audited calls are held; session %s is closed, and a retry of it will be refused',
                self._max_held_calls,
                evicted.session_id,
            )
            self._close(evicted)
            # end if
        connection = _CallConnection(session_id, principal)
        self._sessions[session_id] = connection
        base_context.run(task_group.start_soon, self._run_connection, connection)
        return connection
        # end def

    def _use(self, connection: _CallConnection) -> None:
        """Mark the call as the most recently used one."""
        if self._sessions.get(connection.session_id) is connection:
            del self._sessions[connection.session_id]
            self._sessions[connection.session_id] = connection
            # end if
        # end def

    async def _run_connection(self, connection: _CallConnection) -> None:
        """Serve the tool over the connection until it closes, then release it."""
        try:
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(self._read_tool, connection)
                tasks.start_soon(self._expire, connection)
                async with McpAuditTransport(
                    connection.tool_reads,
                    connection.tool_writes,
                    self._declares,
                    request_timeout=self._request_timeout,
                    instance=self.instance,
                ) as seam:
                    connection.seam = seam
                    server = self._factory(seam)
                    await server.run(seam.read_stream, seam.write_stream, server.create_initialization_options())
                    # end async with
                self._close(connection)
                # end async with
        except Exception:
            # One call's server failing must not take the entry, and with it every other call, down;
            # the requests it was answering are failed below, and the fault is logged with its trace.
            logger.exception('the connection of audit session %s failed', connection.session_id)
        finally:
            self._close(connection)
            # end try
        # end def

    async def _read_tool(self, connection: _CallConnection) -> None:
        """Answer each request written into the connection with the frames the tool writes for it."""
        async with connection.from_tool:
            async for message in connection.from_tool:
                frame = message.message
                if isinstance(frame, JSONRPCResponse | JSONRPCError):
                    frame = self._note_round(connection, frame)
                    waiter = connection.waiters.get(frame.id) if isinstance(frame.id, int) else None
                    if waiter is None:
                        logger.debug(
                            'no request of session %s awaits answer %s; it is dropped', connection.session_id, frame.id
                        )
                        continue
                        # end if
                    waiter.answer(frame)
                    continue
                    # end if
                if isinstance(frame, JSONRPCNotification):
                    related = (
                        message.metadata.related_request_id
                        if isinstance(message.metadata, ServerMessageMetadata)
                        else None
                    )
                    target = self._related_waiter(connection, related)
                    if target is None:
                        logger.debug(
                            'no request of session %s carries notification %s; it is dropped',
                            connection.session_id,
                            frame.method,
                        )
                        continue
                        # end if
                    target.notify(frame)
                    continue
                    # end if
                # A 2026-07-28 server has no back-channel, so the request is answered here, as a peer that
                # serves no such method answers it.
                logger.warning(
                    'the tool wrote a request (%s) on session %s; there is no channel for it',
                    frame.method,
                    connection.session_id,
                )
                refusal = _error(frame.id, METHOD_NOT_FOUND, f'{frame.method} is not served on this connection')
                try:
                    connection.write(SessionMessage(message=refusal))
                except (anyio.WouldBlock, BrokenResourceError, ClosedResourceError):
                    logger.debug(
                        'the refusal of %s could not be written on session %s', frame.method, connection.session_id
                    )
                    # end try
                # end for
            # end async with
        # end def

    def _note_round(
        self, connection: _CallConnection, frame: JSONRPCResponse | JSONRPCError
    ) -> JSONRPCResponse | JSONRPCError:
        """Index a round's token, so its retry finds this connection, and return the frame to answer with.

        A round the seam issued carries its own token. A round the tool issued itself (its own MRTR
        round) carries the tool's `requestState`, which names no instance; it goes out under a token of
        this entry's instead, so that its retry is routed and forwarded as the seam's rounds are (§6.4).
        """
        if not isinstance(frame, JSONRPCResponse) or frame.result.get(RESULT_TYPE) != INPUT_REQUIRED:
            return frame
            # end if
        state = frame.result.get(REQUEST_STATE)
        if state is None or connection.closed:
            return frame
            # end if
        if not (isinstance(state, str) and state.startswith(ROUND_TOKEN_PREFIX)):
            token = f'{ROUND_TOKEN_PREFIX}{self.instance}.{secrets.token_urlsafe(_ROUND_TOKEN_BYTES)}'
            connection.own_rounds[token] = state
            frame = frame.model_copy(update={'result': {**frame.result, REQUEST_STATE: token}})
            state = token
            # end if
        self._tokens[state] = connection
        connection.tokens.add(state)
        return frame
        # end def

    @staticmethod
    def _related_waiter(connection: _CallConnection, related: RequestId | None) -> _Waiter | None:
        """The request a notification goes out with: the one it names, else the latest in flight.

        The seam serves every request of the call on the handler of the first one, so a notification
        names that request's id while it is a later retry that waits; a held call has one request in
        flight between rounds, so the latest one is the call's.
        """
        waiter = connection.waiters.get(related) if isinstance(related, int) else None
        if waiter is not None:
            return waiter
            # end if
        return next(reversed(connection.waiters.values()), None)
        # end def

    async def _expire(self, connection: _CallConnection) -> None:
        """Close the connection once it has had no request in flight for `idle_timeout`."""
        while not connection.closed:
            activity = connection.activity
            if connection.in_flight:
                await activity.wait()
                continue
                # end if
            with anyio.move_on_after(self._idle_timeout) as idle:
                await activity.wait()
                # end with
            # An operation under way keeps the call: closing it would cancel the operation. What the call
            # holds undelivered does not: its host has had the whole bound to retry.
            if idle.cancelled_caught and not connection.closed and not connection.running:
                logger.info(
                    'audit session %s was idle for %ss; its connection closes',
                    connection.session_id,
                    self._idle_timeout,
                )
                self._close(connection)
                # end if
            # end while
        # end def

    def _busy(self, connection: _CallConnection) -> None:
        """A request of the call is in flight: the call is running, and is the most recently used."""
        connection.in_flight += 1
        self._use(connection)
        connection.touch()
        # end def

    @staticmethod
    def _done(connection: _CallConnection) -> None:
        """A request of the call ended; with none left in flight its idle bound starts."""
        connection.in_flight -= 1
        connection.touch()
        # end def

    def _close(self, connection: _CallConnection) -> None:
        """Close a call's connection: its rounds are no longer held, and its requests are answered."""
        if connection.closed:
            return
            # end if
        connection.closed = True
        if self._sessions.get(connection.session_id) is connection:
            del self._sessions[connection.session_id]
            # end if
        for token in connection.tokens:
            self._tokens.pop(token, None)
            # end for
        connection.tokens.clear()
        connection.to_tool.close()
        for waiter in list(connection.waiters.values()):
            waiter.answer(_error(waiter.request_id, INTERNAL_ERROR, CONNECTION_CLOSED_MESSAGE))
            # end for
        connection.touch()
        # end def

    async def _param_rejection(
        self, connection: _CallConnection, frame: JSONRPCRequest, verdict: InboundModernRoute, request: Request
    ) -> InboundLadderRejection | None:
        """Check `Mcp-Param-*` against the arguments, under the called tool's input schema."""
        params = frame.params or {}
        name = params.get('name')
        arguments = params.get('arguments')
        if not isinstance(name, str) or (arguments is not None and not isinstance(arguments, Mapping)):
            return None
            # end if
        prefix = MCP_PARAM_HEADER_PREFIX.lower()
        if not arguments and not any(header.startswith(prefix) for header in request.headers):
            return None
            # end if
        schema = await self._input_schema(connection, name, verdict, request)
        if schema is None:
            return None
            # end if
        return validate_mcp_param_headers(schema, arguments or {}, request.headers)
        # end def

    async def _input_schema(
        self, connection: _CallConnection, name: str, verdict: InboundModernRoute, request: Request
    ) -> object | None:
        """The tool's input schema, from the `tools/list` of the server that serves the call.

        Read once per connection. As in the official handler, a listing that fails or never names the
        tool leaves the headers unchecked rather than failing a working call.
        """
        if connection.schema_read:
            return connection.input_schema
            # end if
        meta: dict[str, Any] = {
            PROTOCOL_VERSION_META_KEY: verdict.protocol_version,
            CLIENT_CAPABILITIES_META_KEY: verdict.client_capabilities,
        }
        if verdict.client_info is not None:
            meta[CLIENT_INFO_META_KEY] = verdict.client_info
            # end if
        list_params: dict[str, Any] = {META: meta}
        seen: set[str] = set()
        schema: object | None = None
        for page in range(_TOOLS_LIST_PAGE_CAP):
            listing = JSONRPCRequest(jsonrpc='2.0', id=page, method=_TOOLS_LIST_METHOD, params=list_params)
            answer = await self._roundtrip(connection, listing, request)
            if not isinstance(answer, JSONRPCResponse):
                logger.debug('Mcp-Param header validation skipped: the tools/list listing failed')
                break
                # end if
            tools = answer.result.get('tools')
            found = next(
                (tool for tool in tools or [] if isinstance(tool, dict) and tool.get('name') == name),
                None,
            )
            if found is not None:
                schema = found.get('inputSchema')
                break
                # end if
            cursor = answer.result.get('nextCursor')
            if not isinstance(cursor, str) or cursor in seen:
                break
                # end if
            seen.add(cursor)
            list_params = {META: meta, 'cursor': cursor}
            # end for
        connection.schema_read = True
        connection.input_schema = schema
        return schema
        # end def

    async def _roundtrip(
        self, connection: _CallConnection, frame: JSONRPCRequest, request: Request
    ) -> JSONRPCResponse | JSONRPCError | None:
        """Write a request of this entry's own into the connection and wait, bounded, for its answer."""
        waiter = self._enter(connection, frame, request)
        if waiter is None:
            return None
            # end if
        try:
            with anyio.move_on_after(self._request_timeout):
                async for answer in waiter.receive:
                    if isinstance(answer, JSONRPCResponse | JSONRPCError):
                        return answer
                        # end if
                    # end for
                # end with
            return None
        finally:
            self._leave(connection, waiter)
            # end try
        # end def

    def _enter(self, connection: _CallConnection, frame: JSONRPCRequest, request: Request) -> _Waiter | None:
        """Register a request on the connection and write it in under an id of the connection's own.

        Returns:
            What the request's answer arrives on, or None when the connection is gone.
        """
        if connection.closed:
            return None
            # end if
        connection.next_id += 1
        waiter = _Waiter(connection.next_id, frame.id)
        connection.waiters[waiter.internal_id] = waiter
        self._busy(connection)
        # The 2026-07-28 HTTP wire has no back-channel, so the tool's server is told it has none.
        metadata = ServerMessageMetadata(request_context=request, can_send_request=False)
        renumbered = frame.model_copy(update={'id': waiter.internal_id})
        try:
            connection.write(SessionMessage(message=renumbered, metadata=metadata))
        except anyio.WouldBlock:
            self._leave(connection, waiter)
            logger.warning(
                'the connection of session %s is not reading; request %s is refused', connection.session_id, frame.id
            )
            return None
        except (BrokenResourceError, ClosedResourceError):
            self._leave(connection, waiter)
            return None
            # end try
        return waiter
        # end def

    def _leave(self, connection: _CallConnection, waiter: _Waiter) -> None:
        """The request is answered or abandoned: it no longer keeps the call running."""
        waiter.receive.close()
        if connection.waiters.pop(waiter.internal_id, None) is not None:
            self._done(connection)
            # end if
        # end def

    async def _exchange(
        self,
        connection: _CallConnection,
        frame: JSONRPCRequest,
        request: Request,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        on_not_written: Callable[[], None] | None = None,
    ) -> None:
        """Write a request of the call into its connection and answer the POST with the tool's answer.

        `on_not_written` runs when the request could not be written, before it is refused.
        """
        waiter = self._enter(connection, frame, request)
        if waiter is None:
            if on_not_written is not None:
                on_not_written()
                # end if
            await _write_json(_error(frame.id, INVALID_PARAMS, NO_OPEN_ROUND_MESSAGE), scope, receive, send)
            return
            # end if
        answer: JSONRPCResponse | JSONRPCError | None = None
        disconnected = anyio.Event()
        try:
            async with anyio.create_task_group() as watch:
                watch.start_soon(self._cancel_on_disconnect, receive, watch.cancel_scope, disconnected)
                answer = await self._respond(waiter, scope, receive, send)
                watch.cancel_scope.cancel()
                # end async with
            if disconnected.is_set() and answer is None:
                # Closing the response stream is the 2026-07-28 HTTP spelling of cancellation.
                self._cancel(connection, waiter)
                # end if
        finally:
            self._leave(connection, waiter)
            if answer is not None and _concludes(answer):
                self._close(connection)
                # end if
            # end try
        # end def

    def _cancel(self, connection: _CallConnection, waiter: _Waiter) -> None:
        """Cancel the request on the connection through the seam's cancellation path, then close it."""
        logger.info(
            'the client closed request %s of session %s; the call is cancelled',
            waiter.request_id,
            connection.session_id,
        )
        cancellation = JSONRPCNotification(
            jsonrpc='2.0',
            method=CANCELLED_METHOD,
            params={REQUEST_ID: waiter.internal_id, 'reason': 'response stream closed'},
        )
        try:
            connection.write(SessionMessage(message=cancellation))
        except (anyio.WouldBlock, BrokenResourceError, ClosedResourceError):
            logger.debug(
                'the connection of session %s took no cancellation; closing it ends the call', connection.session_id
            )
            # end try
        self._close(connection)
        # end def

    @staticmethod
    async def _cancel_on_disconnect(
        receive: Receive, scope: anyio.CancelScope, disconnected: anyio.Event | None
    ) -> None:
        """Cancel `scope` when the client closes the request."""
        while (await receive())['type'] != 'http.disconnect':
            continue
            # end while
        if disconnected is not None:
            disconnected.set()
            # end if
        scope.cancel()
        # end def

    async def _respond(
        self, waiter: _Waiter, scope: Scope, receive: Receive, send: Send
    ) -> JSONRPCResponse | JSONRPCError | None:
        """Answer the POST as the official handler would, and return the answer it carried.

        JSON when the manager is in JSON-response mode. Otherwise, as the official modern handler does,
        an answer that comes before any notification and within `SSE_PING_INTERVAL` is sent as JSON,
        and anything else commits the response to SSE: notifications as they come, a keepalive comment
        every interval, and the answer last. In JSON mode a notification has no place in the response
        and is dropped with a debug log. The answer is in-band: HTTP 200, whatever it says.
        """
        if self._manager.json_response:
            async for frame in waiter.receive:
                if isinstance(frame, JSONRPCResponse | JSONRPCError):
                    await _write_json(frame, scope, receive, send, status=_answer_status(frame))
                    return frame
                    # end if
                logger.debug(
                    'JSON response mode carries no notification; %s is dropped', getattr(frame, 'method', None)
                )
                # end for
            return None
            # end if
        pending: Frame | None = None
        with anyio.move_on_after(SSE_PING_INTERVAL):
            pending = await waiter.receive.receive()
            # end with
        if isinstance(pending, JSONRPCResponse | JSONRPCError):
            await _write_json(pending, scope, receive, send, status=_answer_status(pending))
            return pending
            # end if
        await send({'type': 'http.response.start', 'status': _OK, 'headers': _SSE_HEADERS})
        while True:
            if isinstance(pending, JSONRPCResponse | JSONRPCError):
                await send({'type': 'http.response.body', 'body': _sse_event(pending), 'more_body': False})
                return pending
                # end if
            chunk = _SSE_PING if pending is None else _sse_event(pending)
            await send({'type': 'http.response.body', 'body': chunk, 'more_body': True})
            pending = None
            with anyio.move_on_after(SSE_PING_INTERVAL):
                pending = await waiter.receive.receive()
                # end with
            # end while
        # end def

    # end class


__all__ = [
    'CONNECTION_CLOSED_MESSAGE',
    'DEFAULT_FORWARD_TIMEOUT',
    'DEFAULT_IDLE_TIMEOUT',
    'FORWARD_OUTCOME_UNKNOWN_MESSAGE',
    'FORWARDED_HEADER',
    'FORWARDED_VALUE',
    'MAX_QUEUED_NOTIFICATIONS',
    'PRINCIPAL_MISMATCH_MESSAGE',
    'REGISTRY_FULL_MESSAGE',
    'SESSION_ALREADY_OPEN_MESSAGE',
    'SESSION_BODY_PATH',
    'SSE_PING_INTERVAL',
    'AuditedStreamableHTTP',
    'Forward',
    'ForwardedRequest',
    'ForwardedResponse',
    'ForwardNotDeliveredError',
    'ForwardOutcomeUnknownError',
    'HttpForwarder',
    'PrincipalOf',
    'ToolServerFactory',
]
