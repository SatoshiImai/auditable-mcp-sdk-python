"""Carrying the §6 exchange on an MCP connection, in both bindings (§6.4, §6.5).

Neither official MCP SDK can deliver this extension through its own dispatch, and neither needs to:
everything it adds is ordinary JSON-RPC on the connection MCP already holds. So this binding sits one
layer lower, between the session and the transport streams. Each side wraps the stream pair its
transport yields and hands its session a pair of its own; the audit traffic is handled here, and
every other message passes through untouched and in order, so the session sees exactly the MCP it
would have seen without this extension.

Which binding a call uses is read from the call itself. A `tools/call` that carries the protocol
version in its `_meta` is made under MCP `2026-07-28`, and §6.4 applies: the host's declaration comes
with the request, and the exchange rides the call as Multi Round-Trip Requests. Any other call is
made under a version with an initialization handshake, and §6.5 applies: the declaration came with
`initialize`, and the exchange is `audit/attempt` and `audit/outcome`.

Under §6.4 the tool's handler is not rewritten into rounds. It awaits its attempts as it would under
§6.5; this seam ends the round for it with an `InputRequiredResult`, keeps the handler suspended until
the host's retry arrives, hands it the answers, and puts the handler's final result on the retry's id.
The retry never reaches the tool's session. That works where the retry reaches the process that holds
the suspended handler, and this SDK does not serialize a handler into `requestState`; the
specification does not constrain the mechanism. Over Streamable HTTP, `auditable_mcp.mcp.http` gives
each audited call a connection of its own behind this seam, and round affinity (§6.4) brings every
retry to the instance that holds it: each request of the call carries `Auditable-Mcp-Session`, which
an intermediary can route on, and every round token names the instance that issued it, so an instance
that receives a retry it does not hold can forward it there or refuse it.

The host's side is symmetric: it issues the audit session in each outgoing `tools/call`, seals what
comes back, answers a round that asks for nothing else by retrying on the spot, and closes the session
when the call ends (§6.3).
"""

from __future__ import annotations

import contextvars
import logging
import math
import re
import secrets
from collections.abc import Callable, Coroutine, Mapping
from copy import deepcopy
from dataclasses import dataclass, field, replace
from functools import partial
from types import TracebackType
from typing import Any, Final, Self, TypeGuard

import anyio
import anyio.abc
import anyio.lowlevel
from anyio import BrokenResourceError, ClosedResourceError
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.shared._context_streams import ContextSendStream, create_context_streams
from mcp.shared._stream_protocols import ReadStream as StreamReader
from mcp.shared._stream_protocols import WriteStream as StreamWriter
from mcp.shared.message import ClientMessageMetadata, MessageMetadata, ServerMessageMetadata, SessionMessage
from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)
from mcp_types import PROTOCOL_VERSION_META_KEY
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import TypeAdapter, ValidationError

from auditable_mcp import fields
from auditable_mcp.capability import NegotiationOutcome, NegotiationResult, negotiate
from auditable_mcp.mcp.declaration import capability_of, declare_into
from auditable_mcp.models import (
    EXTENSION_ID,
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    AuditRequestMeta,
    Outcome,
)
from auditable_mcp.session import SessionNumbering, new_session_id
from auditable_mcp.transport import AmcpUsageError, AuditEndpoint, unavailable

logger = logging.getLogger(__name__)

# §6.5's methods. `params` IS the audit event object, never a wrapper.
ATTEMPT_METHOD: Final = 'audit/attempt'
OUTCOME_METHOD: Final = 'audit/outcome'
TOOLS_CALL_METHOD: Final = 'tools/call'
CANCELLED_METHOD: Final = 'notifications/cancelled'
INITIALIZE_METHOD: Final = 'initialize'
DISCOVER_METHOD: Final = 'server/discover'
HANDSHAKE_METHODS: Final = (INITIALIZE_METHOD, DISCOVER_METHOD)

# The MRTR members of a result and of a retry (MCP 2026-07-28), as they appear on the wire.
RESULT_TYPE: Final = 'resultType'
INPUT_REQUIRED: Final = 'input_required'
INPUT_REQUESTS: Final = 'inputRequests'
REQUEST_STATE: Final = 'requestState'
META: Final = '_meta'
REQUEST_ID: Final = 'requestId'
TASK: Final = 'task'

# Request ids this seam mints are strings under this prefix. An MCP session numbers its own requests
# with integers, so the two id spaces cannot collide however long either side runs.
ID_PREFIX: Final = 'amcp-'

# Every `requestState` this seam issues for an audit round is `amcp.<instance>.<secret>`: this prefix,
# the instance that holds the round, and 32 random bytes in base64url. A `tools/call` whose
# `requestState` carries the prefix is a retry of one of this seam's rounds or nothing: one that names no
# open round - consumed, finished, cancelled, or never issued - is refused and never reaches the tool's
# session (§6.4 at most once). The prefix is what lets the seam refuse a replayed token without
# remembering every token it ever consumed. It is therefore reserved: a tool's own `requestState` (its
# own MRTR round) must not begin with it, or the retry that echoes it is taken for one of this seam's
# rounds and refused. The secret is what finds the round, so altering a token can at most name no round;
# the instance only says where the round is held (§6.4 round affinity).
ROUND_TOKEN_PREFIX: Final = 'amcp.'
_ROUND_TOKEN_BYTES: Final = 32
_ROUND_SECRET_PATTERN: Final = re.compile(r'[A-Za-z0-9_-]{43}')

# What an instance name may be. It travels inside a client-controlled `requestState`, so it is held to a
# shape that cannot carry a separator, a scheme or a host.
INSTANCE_PATTERN: Final = re.compile(r'[A-Za-z0-9_-]{1,64}')
_INSTANCE_BYTES: Final = 16


def new_instance_id() -> str:
    """A fresh instance name: 16 random bytes in base64url, so a restarted instance never claims an old round.

    Returns:
        A name that matches `INSTANCE_PATTERN`.
    """
    return secrets.token_urlsafe(_INSTANCE_BYTES)
    # end def


# The instance a seam names in its tokens unless told otherwise: fresh for every process, so a restarted
# process never claims a round its predecessor issued.
PROCESS_INSTANCE: Final = new_instance_id()

# The HTTP header that mirrors a request's audit `session_id` under Streamable HTTP (§6.4 round
# affinity). The body is the source of truth; the header exists so an intermediary can route a call's
# requests to one instance without parsing the body.
AFFINITY_HEADER: Final = 'Auditable-Mcp-Session'

# What a retry that names no open round is answered with, as a JSON-RPC `INVALID_PARAMS` error: a
# replay, a round that ended, or a round held by an instance the retry cannot reach (§6.4, §10.11).
NO_OPEN_ROUND_MESSAGE: Final = 'this requestState names no open round (§6.4)'

# §6 leaves the bound on the wait to the binding, requiring only that it fail closed.
DEFAULT_REQUEST_TIMEOUT: Final = 30.0

# §8.3 leaves bounding the rounds a host follows in one call to the host. A call that asks for more is
# ended: the host stops retrying, closes the session, and answers its client with an error.
MAX_ROUNDS_PER_CALL: Final = 256

# The idle audit sessions a tool keeps on one connection: those whose call asked the client for input
# with the tool's own round and has not been retried yet. They are kept until the connection closes,
# because a retry can come after a human answers and must continue the session's `signer_seq`. Beyond
# the bound the least recently idle one is evicted; its retry restarts the numbering, which the host
# refuses, so the eviction fails closed.
MAX_IDLE_SESSIONS: Final = 1024

# The session a host passes for an event that arrived on no call in flight. No session has it, so the
# endpoint refuses the event as not the call's once it has checked its structure (§6.3, §6.5).
_NO_CALL: Final = ''

# The official SDK's stream protocols, which its memory streams and its context-carrying streams both
# satisfy. They live in a private module of the `mcp` package; the official transports and server
# import them from there too.
ReadStream = StreamReader[SessionMessage | Exception]
WriteStream = StreamWriter[SessionMessage]
# One JSON-RPC message, which is what `SessionMessage.message` carries. Spelled as the MCP package's
# own union rather than restated, so a member added upstream reaches this seam.
Frame = JSONRPCMessage
RequestId = str | int
# A JSON-RPC id keyed by its type as well as its value: `1` and `"1"` are different requests.
IdKey = tuple[str, RequestId]
Job = Callable[[], Coroutine[Any, Any, None]]

_RESPONSE_ADAPTER: TypeAdapter[AttemptResponse] = TypeAdapter(AttemptResponse)

# What the client is answered with when the retry of a round cannot be sent, which ends the call (§6.3).
RETRY_NOT_SENT_MESSAGE: Final = 'the retry of an audit round could not be sent (§6.4)'


def with_affinity_header(headers: Mapping[str, str] | None, session_id: str) -> dict[str, str]:
    """Per-request headers with `Auditable-Mcp-Session` set to `session_id`, and no other spelling of it.

    Args:
        headers: The headers a request already carries, or None.
        session_id: The audit session the request belongs to.

    Returns:
        A new mapping; `headers` is left untouched.
    """
    affinity = AFFINITY_HEADER.lower()
    merged = {name: value for name, value in (headers or {}).items() if name.lower() != affinity}
    merged[AFFINITY_HEADER] = session_id
    return merged
    # end def


def check_instance(instance: str) -> str:
    """Return `instance` if it can name an instance in a round token, and raise otherwise.

    Args:
        instance: The instance name.

    Returns:
        The same name.

    Raises:
        ValueError: It does not match `INSTANCE_PATTERN`.
    """
    if INSTANCE_PATTERN.fullmatch(instance) is None:
        raise ValueError(f'an instance name must match {INSTANCE_PATTERN.pattern}')
        # end if
    return instance
    # end def


def round_token_instance(request_state: object) -> str | None:
    """The instance a round token names, or None when `request_state` is not a well-formed round token.

    Args:
        request_state: A `requestState` as a retry carried it.

    Returns:
        The instance part of `amcp.<instance>.<secret>`, or None.
    """
    if not isinstance(request_state, str) or not request_state.startswith(ROUND_TOKEN_PREFIX):
        return None
        # end if
    instance, separator, secret = request_state[len(ROUND_TOKEN_PREFIX) :].partition('.')
    if not separator or INSTANCE_PATTERN.fullmatch(instance) is None:
        return None
        # end if
    if _ROUND_SECRET_PATTERN.fullmatch(secret) is None:
        return None
        # end if
    return instance
    # end def


class McpBindingError(AmcpUsageError):
    """The binding was driven into a state §6 does not define."""

    # end class


class HandshakeNotSeenError(McpBindingError):
    """Negotiation was asked for, under §6.5, before the peer's `initialize` reached this seam (§6.1)."""

    # end class


class UnnegotiatedSendError(McpBindingError):
    """A send was attempted for a call that is not audit-negotiated (§6.2)."""

    # end class


class UnknownCallError(McpBindingError):
    """A call was asked for that is not a `tools/call` in flight on this connection."""

    # end class


def access_token_of(request: object | None) -> AccessToken | None:
    """The access token the official bearer authentication put on a transport request, or None.

    Args:
        request: A transport request, as `McpAuditCall.request` gives it.

    Returns:
        The token, or None when the request carries no authenticated user.
    """
    scope = getattr(request, 'scope', None)
    user = scope.get('user') if isinstance(scope, dict) else None
    return user.access_token if isinstance(user, AuthenticatedUser) else None
    # end def


def _request_of(metadata: MessageMetadata) -> object | None:
    """The transport's request a message arrived with, or None."""
    return metadata.request_context if isinstance(metadata, ServerMessageMetadata) else None
    # end def


def _without_session(result: NegotiationResult) -> NegotiationResult:
    """A fit the host did not ask to use: the call carries no audit session (§6.2, §6.3)."""
    if not result.negotiated:
        return result
        # end if
    return replace(result, outcome=NegotiationOutcome.NO_SESSION)
    # end def


def negotiate_unaudited(params: object, offered: AuditCapability) -> NegotiationResult:
    """The §6.1 result for a `tools/call` served outside this seam, which carries no audit session.

    Under Streamable HTTP, `auditable_mcp.mcp.http` serves only the calls that carry an audit session
    behind this seam; every other `tools/call` reaches the official handler, and a tool that takes the
    degraded posture there needs the same answer `McpAuditCall.negotiate` gives for such a call. It is
    never negotiated: the host did not ask to audit the call (§6.2, §6.3).

    Args:
        params: The request's `params` as the handler received them.
        offered: The audit capability this tool declares.

    Returns:
        `UNDECLARED` or `MISMATCH` where the declarations do not fit, otherwise `NO_SESSION`.
    """
    declared = capability_of(_meta_of(params).get(CLIENT_CAPABILITIES_META_KEY))
    return _without_session(negotiate(declared, offered))
    # end def


class _Pending:
    """One attempt in flight, waiting for the host's answer."""

    def __init__(self) -> None:
        """Arm the wait with no answer yet."""
        self.arrived = anyio.Event()
        self.response: AttemptResponse | None = None
        # end def

    def settle(self, response: AttemptResponse) -> None:
        """Record the answer and release the waiter. The first answer stands."""
        if self.response is None:
            self.response = response
            self.arrived.set()
            # end if
        # end def

    # end class


def _key(request_id: object) -> IdKey:
    """Key a JSON-RPC id by type and value, so `1` and `"1"` never name one call."""
    value = request_id if isinstance(request_id, str | int) else str(request_id)
    return (type(request_id).__name__, value)
    # end def


def _meta_of(params: object) -> dict[str, Any]:
    """The `_meta` member of a request's params, or an empty dict."""
    meta = params.get(META) if isinstance(params, dict) else None
    return meta if isinstance(meta, dict) else {}
    # end def


def _is_modern(params: object) -> bool:
    """True when a request is made under MCP 2026-07-28, which puts its version in `_meta` (§6.4)."""
    return _meta_of(params).get(PROTOCOL_VERSION_META_KEY) in MODERN_PROTOCOL_VERSIONS
    # end def


def _concludes(frame: JSONRPCResponse | JSONRPCError) -> bool:
    """Whether a tool's answer ends its call: an error, or a result that is not an input round (§6.4)."""
    if isinstance(frame, JSONRPCError):
        return True
        # end if
    result = frame.result if isinstance(frame.result, dict) else {}
    return result.get(RESULT_TYPE) != INPUT_REQUIRED
    # end def


def _is_attempt(event: object) -> TypeGuard[dict[str, object]]:
    """True for an event that carries an attempt rather than an outcome."""
    return isinstance(event, dict) and event.get(fields.OUTCOME) == Outcome.ATTEMPTED
    # end def


def _decision(frame: JSONRPCResponse | JSONRPCError, what: str) -> AttemptResponse:
    """Read an Attempt Response, treating anything unreadable as a failure to record (§6, §7.2)."""
    # §6 requires a protocol error in place of an Attempt Response to be read as a failure to record,
    # exactly as for `unavailable`. A frame carrying both `result` and `error` is not valid JSON-RPC;
    # `mcp>=2.2` parses one into a `JSONRPCResponse` and drops the `error` member before it reaches
    # this seam, so the rule cannot be applied here and no guard pretends to.
    if isinstance(frame, JSONRPCError):
        logger.warning('%s %s answered with a JSON-RPC error', what, frame.id)
        return unavailable()
        # end if
    return _read_response(frame.result, what)
    # end def


def _read_response(value: object, what: str) -> AttemptResponse:
    """Validate one Attempt Response, or read it as a failure to record."""
    try:
        return _RESPONSE_ADAPTER.validate_python(value)
    except ValidationError as error:
        logger.warning('%s answered with an unreadable Attempt Response: %s', what, error)
        return unavailable()
        # end try
    # end def


async def _send_in[ItemT](context: contextvars.Context | None, stream: StreamWriter[ItemT], item: ItemT) -> None:
    """Send `item` from a task that runs in `context`, so a context-carrying stream records that context.

    A context-carrying stream snapshots the context of the task that calls `send`, so the send runs in
    a task started in `context`. Without one it is sent from the current task.

    Raises:
        BrokenResourceError: The receiving end is gone.
        ClosedResourceError: The stream is closed.
    """
    if context is None:
        await stream.send(item)
        return
        # end if
    failure: list[BrokenResourceError | ClosedResourceError] = []

    async def deliver() -> None:
        try:
            await stream.send(item)
        except (BrokenResourceError, ClosedResourceError) as error:
            failure.append(error)
            # end try
        # end def

    async with anyio.create_task_group() as sender:
        context.run(sender.start_soon, deliver)
        # end async with
    if failure:
        raise failure[0]
        # end if
    # end def


class _FrameSeam:
    """Stream plumbing shared by both roles: pass MCP through, handle the audit traffic here.

    The session is handed the inner ends of two memory streams and drives them as it would drive the
    transport's own. Two pump tasks move messages across, so the session's receive loop is never the
    thing that has to be running for an audit frame to be answered, and an audit exchange in flight
    never stalls ordinary MCP traffic.
    """

    def __init__(self, read_stream: ReadStream, write_stream: WriteStream) -> None:
        """Wrap the transport's stream pair and build the pair the session will be given."""
        self._outer_read = read_stream
        self._outer_write = write_stream
        # Both pairs carry the sender's `contextvars` with each message, as the official transports'
        # streams do: the server runs each request's handler in the context of the task that delivered
        # it (the HTTP request's, with its authentication and trace), and a client transport sends each
        # request from the context of the caller that made it.
        self._to_session, self._session_read = create_context_streams[SessionMessage | Exception](1)
        self._session_write, self._from_session = create_context_streams[SessionMessage](1)
        # Frames this seam writes join the queue the session writes to, so one task owns the outbound
        # stream and the order messages leave in is the order they were produced in.
        self._frames_out: ContextSendStream[SessionMessage] = self._session_write.clone()
        # The context of the message the outbound pump is handling, for work that message starts.
        self._sending_context: contextvars.Context | None = None
        # The frames this seam wrote itself, which the outbound hook must not read as the session's.
        self._own_frames: set[int] = set()
        self._task_group: anyio.abc.TaskGroup | None = None
        self._next_id = 0
        # end def

    @property
    def read_stream(self) -> ReadStream:
        """The read stream to give the MCP session in place of the transport's."""
        return self._session_read
        # end def

    @property
    def write_stream(self) -> WriteStream:
        """The write stream to give the MCP session in place of the transport's."""
        return self._session_write
        # end def

    async def __aenter__(self) -> Self:
        """Start the two pumps."""
        self._task_group = anyio.create_task_group()
        await self._task_group.__aenter__()
        self._task_group.start_soon(self._pump_inbound)
        self._task_group.start_soon(self._pump_outbound)
        return self
        # end def

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        """Settle whatever is in flight, stop the pumps without waiting on the peer, then close the wire.

        The transport's write stream is closed last. Nothing else holds it - the session was given this
        seam's streams - so a transport that ends when its writer closes (stdio, whose process exits on
        it) would otherwise outlive the session.

        The pumps' task group is exited even when settling is interrupted: a transport that fails a
        request inside its own task group cancels the session around this seam, and a task group left
        entered would leave its cancel scope on the task's stack.
        """
        try:
            await self._on_close()
            await self._frames_out.aclose()
        finally:
            suppress = await self._stop(exc_type, exc_val, exc_tb)
            # end try
        return suppress
        # end def

    async def _stop(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        """Cancel and exit the pumps' task group, then close the transport's write stream."""
        task_group = self._task_group
        try:
            if task_group is None:
                return None
                # end if
            task_group.cancel_scope.cancel()
            return await task_group.__aexit__(exc_type, exc_val, exc_tb)
        finally:
            await self._outer_write.aclose()
            # end try
        # end def

    def _start(
        self,
        task: Callable[..., Coroutine[Any, Any, None]],
        *args: object,
        context: contextvars.Context | None = None,
    ) -> None:
        """Run `task` beside the pumps, so a wait on the peer never holds either of them.

        With `context`, the task runs in it rather than in the context of the task that starts it.
        """
        task_group = self._task_group
        if task_group is None:
            raise McpBindingError('the seam is not running; enter it with `async with` first')
            # end if
        if context is None:
            task_group.start_soon(task, *args)
            return
            # end if
        context.run(task_group.start_soon, task, *args)
        # end def

    async def _pump_inbound(self) -> None:
        """Deliver everything the peer sends to the session, except what this side handles."""
        try:
            async for message in self._outer_read:
                context = getattr(self._outer_read, 'last_context', None)
                if isinstance(message, Exception):
                    await _send_in(context, self._to_session, message)
                    continue
                    # end if
                forward = await self._inbound(message.message, message.metadata)
                if forward is not None:
                    delivered = SessionMessage(message=forward, metadata=message.metadata)
                    await _send_in(context, self._to_session, delivered)
                    # end if
                # end for
        except (BrokenResourceError, ClosedResourceError):
            logger.debug('the session stopped reading; the inbound pump ends with it')
        finally:
            await self._to_session.aclose()
            # end try
        # end def

    async def _pump_outbound(self) -> None:
        """Forward what the session and this seam write, in order, after this side's own additions."""
        try:
            async for message in self._from_session:
                context = self._from_session.last_context
                if id(message) in self._own_frames:
                    self._own_frames.discard(id(message))
                    await _send_in(context, self._outer_write, message)
                    continue
                    # end if
                self._sending_context = context
                try:
                    forward = await self._outbound(message.message)
                finally:
                    self._sending_context = None
                    # end try
                if forward is not None:
                    metadata = self._outbound_metadata(forward, message.metadata)
                    await _send_in(context, self._outer_write, SessionMessage(message=forward, metadata=metadata))
                    # end if
                # end for
        except (BrokenResourceError, ClosedResourceError):
            logger.debug('the connection went away; the outbound pump ends with it')
            # end try
        # end def

    async def _send_frame(
        self,
        frame: Frame,
        related_request_id: RequestId | None = None,
        *,
        metadata: MessageMetadata = None,
    ) -> None:
        """Queue one JSON-RPC message for the peer. One message per frame, never an array (§6.5)."""
        if metadata is None and related_request_id is not None:
            metadata = ServerMessageMetadata(related_request_id=related_request_id)
            # end if
        message = SessionMessage(message=frame, metadata=metadata)
        self._own_frames.add(id(message))
        await self._frames_out.send(message)
        # end def

    async def _deliver_up(self, frame: Frame) -> None:
        """Hand the session a frame this seam produced, from any task."""
        try:
            await self._to_session.send(SessionMessage(message=frame))
        except (BrokenResourceError, ClosedResourceError):
            logger.warning('the session stopped reading; a frame for request %s is dropped', getattr(frame, 'id', None))
            # end try
        # end def

    def _new_id(self) -> str:
        """Return the next request id in the string space the session never uses."""
        self._next_id += 1
        return f'{ID_PREFIX}{self._next_id}'
        # end def

    async def _inbound(self, frame: Frame, metadata: MessageMetadata) -> Frame | None:
        """Handle an inbound frame; return what the session should see, or None."""
        del metadata
        return frame
        # end def

    async def _outbound(self, frame: Frame) -> Frame | None:
        """Handle an outbound frame; return what the peer should see, or None."""
        return frame
        # end def

    def _outbound_metadata(self, frame: Frame, metadata: MessageMetadata) -> MessageMetadata:
        """The transport metadata an outbound frame of the session's leaves with. Its own by default."""
        del frame
        return metadata
        # end def

    async def _on_close(self) -> None:
        """Release anything the role is holding. Nothing by default."""
        # end def

    # end class


@dataclass
class _Round:
    """One round of a §6.4 call that is out: its token, and the attempts it carried."""

    token: str
    awaiting: dict[str, _Pending]
    answered: anyio.Event = field(default_factory=anyio.Event)
    # end class


@dataclass
class _AuditSession:
    """An audit session the host issued, as the tool sees it across the requests of one call (§6.3, §6.4).

    Under §6.4 one call can reach the tool as several requests - its own `inputRequests` rounds are
    retried as new requests that the tool's session serves - and every one of them carries the same
    `session_id`. What must hold for the whole call is kept here: the §6.1 comparison is made against
    the declaration the call's first request carried, and the `signer_seq` sequence continues rather
    than restarting at 0 with each request.
    """

    session_id: str
    host_capability: AuditCapability | None
    numbering: SessionNumbering = field(default_factory=SessionNumbering)
    # Requests of the call in flight on this connection.
    live: int = 0
    # end class


@dataclass
class _ToolCall:
    """One `tools/call` request this tool is serving, and the state of its audit exchange."""

    original_id: RequestId
    modern: bool
    host_capability: AuditCapability | None
    # The audit session the host issued for the call, or None when it issued none.
    audit: _AuditSession | None
    # The session a tool that degrades records under: minted here, never the peer's (§6.2, §6.3).
    own_session_id: str
    task_augmented: bool
    # The id the final result goes out on: the original, or under §6.4 the latest retry's. None while
    # a round is out and its retry has not come - there is nothing to answer on.
    current_id: RequestId | None
    # Every id the call has been served under, which a cancellation may name.
    ids: set[IdKey] = field(default_factory=set)
    own_numbering: SessionNumbering = field(default_factory=SessionNumbering)
    negotiated: bool = False
    # §6.4: the events emitted since the last round and the attempts among them, then the round out.
    buffered: list[dict[str, object]] = field(default_factory=list)
    buffered_awaiting: dict[str, _Pending] = field(default_factory=dict)
    round: _Round | None = None
    round_scheduled: bool = False
    # §6.4: the handler's final frame, kept while a round is out, until that round's retry answers it.
    final: JSONRPCResponse | JSONRPCError | None = None
    # The handler has concluded; `ended` once nothing more goes out for the call; `released` once the
    # request no longer counts toward its audit session.
    finished: bool = False
    ended: bool = False
    released: bool = False
    # The attempts the host accepted whose outcome the tool has not emitted yet: operations under way.
    accepted_open: set[str] = field(default_factory=set)
    # The transport's context of the request of the call being served: the latest retry's once one is
    # accepted (Streamable HTTP: the Starlette request). None on a transport that has none.
    request: object | None = None

    @property
    def session_id(self) -> str:
        """The host's session when the call is audit-negotiated, otherwise the tool's own (§6.2, §6.3)."""
        if self.negotiated and self.audit is not None:
            return self.audit.session_id
            # end if
        return self.own_session_id
        # end def

    # end class


class McpAuditCall:
    """The tool's audit transport for one `tools/call` (§6.3): an `AuditTransport` for that call alone.

    Obtain it from `McpAuditTransport.call` with the request id the MCP handler is serving. Its
    `session_id` is the audit session the host issued for the call once the call is audit-negotiated,
    and otherwise one minted here for a tool that takes the degraded posture (§6.2) - never the peer's.
    """

    def __init__(self, seam: McpAuditTransport, call: _ToolCall) -> None:
        """Bind the call's state to the seam that carries it."""
        self._seam = seam
        self._call = call
        # end def

    @property
    def session_id(self) -> str:
        """The audit session every event of this call carries (§6.3)."""
        return self._call.session_id
        # end def

    @property
    def numbering(self) -> SessionNumbering:
        """The `signer_seq` state of this call's audit session, shared by every request of the call (§7.4).

        `AmcpSession` reads it, so a handler invoked again for a later request of the same call
        continues the sequence instead of restarting it.
        """
        if self._call.negotiated and self._call.audit is not None:
            return self._call.audit.numbering
            # end if
        return self._call.own_numbering
        # end def

    @property
    def host_capability(self) -> AuditCapability | None:
        """What the host declared for this call, or None if it declared nothing readable (§6.1).

        Returns:
            The declaration, or None.
        """
        return self._call.host_capability
        # end def

    @property
    def request(self) -> object | None:
        """The transport's request the call is being served under now, or None where there is none.

        Under Streamable HTTP it is the Starlette request of the latest request of the call: the one that
        opened it, then each retry as it is accepted. A handler is resumed on each retry rather than
        invoked again, so its `contextvars` - `get_access_token()` included - stay those of the request
        that invoked it; what is per request is read here.

        Returns:
            The request, or None (stdio).
        """
        return self._call.request
        # end def

    @property
    def access_token(self) -> AccessToken | None:
        """The access token the request the call is being served under now was authenticated with.

        Returns:
            The token the official bearer authentication put on the request, or None.
        """
        return access_token_of(self._call.request)
        # end def

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Compare the host's declaration for this call against the tool's, and open the send path (§6.1).

        Args:
            offered: The audit capability this tool declares.

        Returns:
            The fit. A call the host sent without an audit session is not negotiated however the
            declarations compare: the host did not ask to audit it (§6.2, §6.3).

        Raises:
            HandshakeNotSeenError: Under §6.5, called before the peer's `initialize` reached the seam.
            McpBindingError: `offered` is not what this transport declared on the wire.
        """
        if offered != self._seam.declares:
            raise McpBindingError('this transport declared a different capability (§6.1)')
            # end if
        if not self._call.modern and not self._seam.handshake_seen:
            raise HandshakeNotSeenError('the peer has not sent `initialize` yet; negotiate after the handshake (§6.1)')
            # end if
        result = negotiate(self._call.host_capability, offered)
        if self._call.audit is None or self._call.task_augmented:
            result = _without_session(result)
            # end if
        self._call.negotiated = result.negotiated
        return result
        # end def

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Send an attempt and resolve with the host's answer, failing closed on silence (§6, §7.2)."""
        self._require_negotiated()
        return await self._seam._send_attempt(self._call, event)
        # end def

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Send an outcome, which has no answer (§6)."""
        self._require_negotiated()
        await self._seam._send_outcome(self._call, event)
        # end def

    def _require_negotiated(self) -> None:
        """Refuse to send an audit message for an unnegotiated call (§6.2)."""
        if not self._call.negotiated:
            raise UnnegotiatedSendError(
                'this call is not audit-negotiated, so no audit message may be sent; '
                'choose the transport with `transport_for` after `negotiate` (§6.2)'
            )
            # end if
        # end def

    # end class


class McpAuditTransport(_FrameSeam):
    """The tool side of the wire: it hands out one `McpAuditCall` per `tools/call` (§6.3).

    A tool is an MCP server, so every declaration passes through this seam. The host's arrives with
    `initialize` (§6.5) or with each request (§6.4); the tool's goes out in the handshake result. The
    seam reads the first and writes the second, so what the tool declared on the wire is what it
    negotiates with - there is no second copy to drift.
    """

    def __init__(
        self,
        read_stream: ReadStream,
        write_stream: WriteStream,
        declares: AuditCapability,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        instance: str = PROCESS_INSTANCE,
    ) -> None:
        """Wrap the transport's streams, hold the declaration, and arm the bound §6 leaves to the binding.

        Args:
            read_stream: The transport's inbound stream.
            write_stream: The transport's outbound stream.
            declares: The audit capability this tool declares (§6.1).
            request_timeout: In seconds, the bound on each wait for the host's answer to an attempt.
            instance: The instance every round token this seam issues names (§6.4 round affinity).

        Raises:
            ValueError: `instance` does not match `INSTANCE_PATTERN`.
        """
        super().__init__(read_stream, write_stream)
        self.declares = declares
        self.instance = check_instance(instance)
        self._request_timeout = request_timeout
        self._handshake_id: RequestId | None = None
        self._handshake_seen = False
        self._handshake_capability: AuditCapability | None = None
        # Requests in flight by their original id, and the rounds out, by token.
        self._calls: dict[IdKey, _ToolCall] = {}
        self._rounds: dict[str, tuple[_ToolCall, _Round]] = {}
        # The host-issued audit sessions of the calls in flight on this connection, by session id.
        self._sessions: dict[str, _AuditSession] = {}
        # The sessions among them with no request in flight, least recently idle first.
        self._idle: dict[str, _AuditSession] = {}
        # §6.5 attempts in flight, by the request id this seam gave them, with the call that owns each.
        self._pending: dict[str, tuple[_Pending, _ToolCall]] = {}
        # Calls whose handler has concluded while a §6.4 round is still out, by original id, least
        # recently concluded first. Each keeps its final frame until that round's retry arrives, however
        # late (§6.4); only the connection's end or eviction beyond MAX_IDLE_SESSIONS drops it. They are
        # not served any more, but a cancellation can still name them.
        self._waiting: dict[IdKey, _ToolCall] = {}
        # Cancelled requests whose handler may still conclude. Their final frame is not written: the id
        # was answered by a round already, or the client abandoned it. Each is forgotten after the bound.
        self._cancelled: dict[IdKey, _ToolCall] = {}
        # end def

    @property
    def running(self) -> bool:
        """Whether a call on this connection is at work, which closing the connection would cut short.

        A call runs while its handler runs with no round out - it is not waiting for a retry - and while
        an operation the host accepted has not emitted its outcome: closing the connection then would
        cancel an operation under way, whose outcome could never be known (§6.3).
        """
        return any(
            not call.ended and not call.finished and (call.round is None or bool(call.accepted_open))
            for call in self._calls.values()
        )
        # end def

    @property
    def undelivered(self) -> bool:
        """Whether a call on this connection holds outcomes or a final answer its host has not received.

        They go out on the call's next retry. Closing the connection before it comes drops them, and
        the host's session end then records the attempts they would have resolved (§6.3).
        """
        held = any(not call.ended and bool(call.buffered) for call in self._calls.values())
        return held or any(not call.ended for call in self._waiting.values())
        # end def

    @property
    def handshake_seen(self) -> bool:
        """True once the peer's `initialize` or `server/discover` has passed through this seam."""
        return self._handshake_seen
        # end def

    def call(self, request_id: RequestId | None) -> McpAuditCall:
        """The audit transport for the `tools/call` the MCP handler is serving.

        The id is matched by JSON type and value, so `1` and `"1"` are two calls. Pass the raw id the
        request carried: with the high-level `MCPServer` that is `ctx.request_context.request_id`, not
        `ctx.request_id`, which is its string form. A string form cannot name one of two calls whose ids
        stringify alike, so it is not accepted in place of the raw id.

        Args:
            request_id: The JSON-RPC id of that request, as the request carried it.

        Raises:
            UnknownCallError: No `tools/call` with that id is in flight on this connection. When a call
                whose id has the same string form is, the message says to pass the raw id.
        """
        call = self._calls.get(_key(request_id))
        if call is None:
            alike = [found.original_id for found in self._calls.values() if str(found.original_id) == str(request_id)]
            hint = (
                f'; a call with id {alike[0]!r} is - pass the raw JSON-RPC id '
                '(with MCPServer, `ctx.request_context.request_id`), not its string form'
                if alike
                else ''
            )
            raise UnknownCallError(f'no tools/call {request_id!r} is in flight on this connection{hint}')
            # end if
        return McpAuditCall(self, call)
        # end def

    async def _send_attempt(self, call: _ToolCall, event: dict[str, object]) -> AttemptResponse:
        """Carry an attempt in the binding the call uses, and wait, bounded, for the answer."""
        if call.finished or call.ended:
            # No round follows the call's end and no answer is awaited for it, so nothing can answer.
            logger.warning('an attempt was emitted after the call returned or ended; failing closed')
            return unavailable()
            # end if
        pending = _Pending()
        request_id: str | None = None
        if call.modern:
            call.buffered.append(event)
            call.buffered_awaiting[str(event.get(fields.ID))] = pending
            self._schedule_round(call)
        else:
            request_id = self._new_id()
            self._pending[request_id] = (pending, call)
            try:
                await self._send_frame(
                    JSONRPCRequest(jsonrpc='2.0', id=request_id, method=ATTEMPT_METHOD, params=dict(event)),
                    call.original_id,
                )
            except (BrokenResourceError, ClosedResourceError):
                logger.warning('the connection is gone; %s could not be sent', ATTEMPT_METHOD)
                self._pending.pop(request_id, None)
                return unavailable()
                # end try
            # end if
        with anyio.move_on_after(self._request_timeout):
            await pending.arrived.wait()
            # end with
        if pending.response is None:
            logger.warning('no answer to an attempt within %ss; failing closed', self._request_timeout)
            pending.settle(unavailable())
            if request_id is not None:
                self._pending.pop(request_id, None)
                # end if
            # end if
        response = pending.response if pending.response is not None else unavailable()
        if isinstance(response, AcceptResponse) and not call.ended:
            call.accepted_open.add(str(event.get(fields.ID)))
            # end if
        return response
        # end def

    async def _send_outcome(self, call: _ToolCall, event: dict[str, object]) -> None:
        """Carry an outcome: in the next round or the final result (§6.4), or as a notification (§6.5)."""
        call.accepted_open.discard(str(event.get(fields.ID)))
        if call.finished or call.ended:
            # §6 requires an outcome to go no later than the result; one emitted after it has nowhere
            # to go, and the host records the attempt unresolved (§6.3).
            logger.warning('an outcome was emitted after the call returned; it is lost (§6.3)')
            return
            # end if
        if call.modern:
            call.buffered.append(event)
            return
            # end if
        try:
            await self._send_frame(
                JSONRPCNotification(jsonrpc='2.0', method=OUTCOME_METHOD, params=dict(event)),
                call.original_id,
            )
        except (BrokenResourceError, ClosedResourceError):
            logger.warning('the connection is gone; %s could not be sent', OUTCOME_METHOD)
            # end try
        # end def

    def _schedule_round(self, call: _ToolCall) -> None:
        """End the current round once, after every sibling that is about to emit has emitted (§6.4)."""
        if not call.round_scheduled:
            call.round_scheduled = True
            self._start(self._end_round, call)
            # end if
        # end def

    async def _end_round(self, call: _ToolCall) -> None:
        """Answer the call's current request with an `InputRequiredResult` carrying the round's events."""
        # Concurrent operations of one call reach their attempts in the same pass of the event loop;
        # yielding once lets them join this round rather than each costing one of its own.
        await anyio.lowlevel.checkpoint()
        call.round_scheduled = False
        request_id = call.current_id
        if call.ended or call.round is not None or request_id is None or not call.buffered:
            # A round is out and its retry has not come; what is buffered goes out with the next one.
            return
            # end if
        token = f'{ROUND_TOKEN_PREFIX}{self.instance}.{secrets.token_urlsafe(_ROUND_TOKEN_BYTES)}'
        events, call.buffered = call.buffered, []
        awaiting, call.buffered_awaiting = call.buffered_awaiting, {}
        out = _Round(token=token, awaiting=awaiting)
        call.round = out
        call.current_id = None
        self._rounds[token] = (call, out)
        result = {
            RESULT_TYPE: INPUT_REQUIRED,
            REQUEST_STATE: token,
            META: {EXTENSION_ID: {fields.SESSION_ID: call.session_id, fields.EVENTS: events}},
        }
        try:
            await self._send_frame(JSONRPCResponse(jsonrpc='2.0', id=request_id, result=result))
        except (BrokenResourceError, ClosedResourceError):
            logger.warning('the connection is gone; a round of tools/call %s could not be sent', call.original_id)
            # end try
        # end def

    def _accept_retry(self, call: _ToolCall, answered: _Round, frame: JSONRPCRequest, request: object | None) -> None:
        """Take a retry's answers to the round it closes, and only to that round (§6.4).

        An answer to an attempt the tool already treated as unanswered changes nothing: the first
        answer an attempt receives stands (§6.4 at most once).
        """
        meta = _meta_of(frame.params).get(EXTENSION_ID)
        try:
            request_meta = AuditRequestMeta.model_validate(meta)
        except ValidationError:
            request_meta = None
            # end try
        if request_meta is None or call.audit is None or request_meta.session_id != call.audit.session_id:
            # A retry that does not name this call's session answers none of the round's attempts, and
            # each is read as unanswered, which fails it closed (§6.4).
            logger.warning('a retry of tools/call %s did not carry its audit session', call.original_id)
            responses: dict[str, AttemptResponse] = {}
        else:
            responses = dict(request_meta.responses or {})
            # end if
        for event_id, pending in answered.awaiting.items():
            pending.settle(responses.get(event_id, unavailable()))
            # end for
        call.round = None
        call.current_id = frame.id
        call.ids.add(_key(frame.id))
        call.request = request
        answered.answered.set()
        # Events emitted while the round was out go with the next one; an outcome among them can wait
        # for the final result, and an attempt needs a round of its own.
        if not call.finished and not call.ended and any(_is_attempt(event) for event in call.buffered):
            self._schedule_round(call)
            # end if
        # end def

    async def _inbound(self, frame: Frame, metadata: MessageMetadata) -> Frame | None:
        """Read the declarations, take the calls in, and keep §6.4 retries from the session."""
        if isinstance(frame, JSONRPCRequest) and frame.method in HANDSHAKE_METHODS:
            self._handshake_id = frame.id
            self._read_handshake(frame.method, frame.params)
            return frame
            # end if
        if isinstance(frame, JSONRPCRequest) and frame.method == TOOLS_CALL_METHOD:
            return await self._take_call(frame, _request_of(metadata))
            # end if
        if isinstance(frame, JSONRPCResponse | JSONRPCError) and isinstance(frame.id, str):
            if frame.id.startswith(ID_PREFIX):
                entry = self._pending.pop(frame.id, None)
                if entry is None:
                    # The wait already ended, failed closed; the session never issued this id.
                    logger.debug(
                        'an answer to %s %s came after its wait ended; it is dropped', ATTEMPT_METHOD, frame.id
                    )
                else:
                    entry[0].settle(_decision(frame, ATTEMPT_METHOD))
                    # end if
                return None
                # end if
            # end if
        if isinstance(frame, JSONRPCNotification) and frame.method == CANCELLED_METHOD:
            return self._cancel(frame)
            # end if
        return frame
        # end def

    async def _take_call(self, frame: JSONRPCRequest, request: object | None) -> Frame | None:
        """A new request is tracked and passed on; a retry of a round is taken here and never passed on."""
        params = frame.params or {}
        state = params.get(REQUEST_STATE)
        if isinstance(state, str) and state.startswith(ROUND_TOKEN_PREFIX):
            entry = self._rounds.pop(state, None)
            if entry is None:
                # Consumed, finished, cancelled, or never issued: a replay the tool must not act on
                # again (§6.4 at most once), and never a new call.
                await self._send_frame(
                    JSONRPCError(
                        jsonrpc='2.0',
                        id=frame.id,
                        error=ErrorData(code=INVALID_PARAMS, message=NO_OPEN_ROUND_MESSAGE),
                    )
                )
                return None
                # end if
            call = entry[0]
            self._accept_retry(call, entry[1], frame, request)
            if call.final is not None:
                await self._deliver_final(call, call.final)
                # end if
            return None
            # end if
        modern = _is_modern(params)
        meta = _meta_of(params)
        try:
            issued: str | None = AuditRequestMeta.model_validate(meta.get(EXTENSION_ID)).session_id
        except ValidationError:
            issued = None
            # end try
        declared = capability_of(meta.get(CLIENT_CAPABILITIES_META_KEY)) if modern else self._handshake_capability
        audit: _AuditSession | None = None
        if issued is not None:
            audit = self._sessions.get(issued)
            if audit is None:
                # §6.1, §6.4: the comparison is made against the declaration of the call's first request.
                audit = _AuditSession(session_id=issued, host_capability=declared)
                self._sessions[issued] = audit
                # end if
            self._idle.pop(issued, None)
            audit.live += 1
            # end if
        call = _ToolCall(
            original_id=frame.id,
            modern=modern,
            host_capability=audit.host_capability if audit is not None else declared,
            audit=audit,
            own_session_id=new_session_id(),
            task_augmented=isinstance(params.get(TASK), dict),
            current_id=frame.id,
            ids={_key(frame.id)},
            request=request,
        )
        self._calls[_key(frame.id)] = call
        return frame
        # end def

    def _cancel(self, frame: JSONRPCNotification) -> Frame | None:
        """End the cancelled call here, and point the cancellation at the id the session knows (§6.4)."""
        params = frame.params or {}
        request_id = params.get(REQUEST_ID)
        target = _key(request_id)
        candidates = (*self._calls.values(), *self._waiting.values())
        call = next((call for call in candidates if target in call.ids), None)
        if call is None:
            return frame
            # end if
        handler_concluded = call.finished
        self._end_call(call, final=True)
        if handler_concluded:
            # The handler's frame has already passed and the session holds nothing for the call; closing
            # the round withholds the frame that waited on its retry, and refuses that retry.
            logger.debug('tools/call %s was cancelled while its round was out; its final frame is withheld', request_id)
            return None
            # end if
        original = _key(call.original_id)
        self._cancelled[original] = call
        self._start(self._forget_cancelled, original)
        if target == original:
            return frame
            # end if
        return JSONRPCNotification(
            jsonrpc='2.0', method=CANCELLED_METHOD, params={**params, REQUEST_ID: call.original_id}
        )
        # end def

    async def _forget_cancelled(self, original: IdKey) -> None:
        """Stop waiting for a cancelled request's final frame once the bound has passed."""
        await anyio.sleep(self._request_timeout)
        self._cancelled.pop(original, None)
        # end def

    def _end_call(self, call: _ToolCall, *, final: bool) -> None:
        """Drop the call: every attempt still waiting is unanswered, and its round closes (§6, §6.4)."""
        call.finished = True
        call.ended = True
        call.final = None
        self._calls.pop(_key(call.original_id), None)
        self._waiting.pop(_key(call.original_id), None)
        for request_id, (pending, owner) in list(self._pending.items()):
            if owner is call:
                del self._pending[request_id]
                pending.settle(unavailable())
                # end if
            # end for
        if call.round is not None:
            self._rounds.pop(call.round.token, None)
            for pending in call.round.awaiting.values():
                pending.settle(unavailable())
                # end for
            call.round.answered.set()
            # end if
        for pending in call.buffered_awaiting.values():
            pending.settle(unavailable())
            # end for
        call.buffered_awaiting = {}
        self._release(call, final=final)
        # end def

    def _release(self, call: _ToolCall, *, final: bool) -> None:
        """A request of the call is done; the audit session's state goes when the call ends (§6.3)."""
        audit = call.audit
        if audit is None or call.released:
            return
            # end if
        call.released = True
        audit.live -= 1
        if audit.live > 0:
            return
            # end if
        if final:
            self._sessions.pop(audit.session_id, None)
            self._idle.pop(audit.session_id, None)
            return
            # end if
        self._keep_idle(audit)
        # end def

    def _keep_idle(self, audit: _AuditSession) -> None:
        """Keep a session for the retry of the tool's own input round, evicting beyond MAX_IDLE_SESSIONS."""
        self._idle.pop(audit.session_id, None)
        self._idle[audit.session_id] = audit
        while len(self._idle) > MAX_IDLE_SESSIONS:
            evicted = next(iter(self._idle))
            del self._idle[evicted]
            self._sessions.pop(evicted, None)
            logger.warning(
                'more than %s idle audit sessions on this connection; session %s is evicted, and a retry of it '
                'restarts its numbering',
                MAX_IDLE_SESSIONS,
                evicted,
            )
            # end while
        # end def

    async def _outbound(self, frame: Frame) -> Frame | None:
        """Declare on the handshake result, and put a call's final result on the id that is still open."""
        if isinstance(frame, JSONRPCResponse) and frame.id == self._handshake_id:
            capabilities = frame.result.setdefault('capabilities', {})
            if isinstance(capabilities, dict):
                declare_into(capabilities, self.declares)
                # end if
            return frame
            # end if
        if isinstance(frame, JSONRPCResponse | JSONRPCError):
            if self._cancelled.pop(_key(frame.id), None) is not None:
                logger.debug('tools/call %s was cancelled; its final frame is not written', frame.id)
                return None
                # end if
            call = self._calls.pop(_key(frame.id), None)
            if call is not None:
                call.finished = True
                return await self._finish(call, frame)
                # end if
            # end if
        return frame
        # end def

    async def _finish(self, call: _ToolCall, frame: JSONRPCResponse | JSONRPCError) -> Frame | None:
        """Deliver the call's remaining outcomes no later than its result, on the id still open (§6, §6.4)."""
        # A result that itself asks the client for input (the tool's own MRTR round) leaves the call
        # going: its retry is a new request of the same audit session.
        continues = isinstance(frame, JSONRPCResponse) and frame.result.get(RESULT_TYPE) == INPUT_REQUIRED
        if isinstance(frame, JSONRPCResponse) and continues:
            own_state = frame.result.get(REQUEST_STATE)
            if isinstance(own_state, str) and own_state.startswith(ROUND_TOKEN_PREFIX):
                logger.error(
                    'tools/call %s asked for input with a requestState under the reserved prefix %r; '
                    'its retry will be refused as a round this seam never issued',
                    call.original_id,
                    ROUND_TOKEN_PREFIX,
                )
                # end if
            # end if
        self._release(call, final=not continues)
        if not call.modern:
            call.ended = True
            return frame
            # end if
        if call.round is not None:
            # The handler concluded while a round is out - an attempt in it went unanswered and failed
            # closed, and whatever the retry says of it now is ignored. The retry is the one request
            # left to answer on, so the final frame waits for it (§6.4).
            for pending in call.round.awaiting.values():
                pending.settle(unavailable())
                # end for
            self._keep_waiting(call, frame)
            return None
            # end if
        return await self._final_frame(call, frame)
        # end def

    def _keep_waiting(self, call: _ToolCall, frame: JSONRPCResponse | JSONRPCError) -> None:
        """Keep a concluded call's final frame for its round's retry, evicting beyond MAX_IDLE_SESSIONS."""
        call.final = frame
        key = _key(call.original_id)
        self._waiting.pop(key, None)
        self._waiting[key] = call
        while len(self._waiting) > MAX_IDLE_SESSIONS:
            evicted = next(iter(self._waiting.values()))
            logger.warning(
                'more than %s concluded calls wait on a retry on this connection; tools/call %s (session %s) '
                'is evicted, and its final frame is dropped',
                MAX_IDLE_SESSIONS,
                evicted.original_id,
                evicted.session_id,
            )
            self._end_call(evicted, final=True)
            # end while
        # end def

    async def _deliver_final(self, call: _ToolCall, frame: JSONRPCResponse | JSONRPCError) -> None:
        """Answer the retry that just arrived with the call's final frame, or the round that precedes it."""
        final = await self._final_frame(call, frame)
        if final is not None:
            await self._send_frame(final)
            # end if
        # end def

    async def _final_frame(self, call: _ToolCall, frame: JSONRPCResponse | JSONRPCError) -> Frame | None:
        """The frame that concludes the call on its open id, with the outcomes still buffered (§6.4)."""
        request_id = call.current_id
        if request_id is None:
            return None
            # end if
        outcomes = [event for event in call.buffered if not _is_attempt(event)]
        if len(outcomes) != len(call.buffered):
            # An attempt never sent was already failed closed; a final result carries no attempt (§6.4).
            logger.warning('tools/call %s concluded with an attempt never sent; it is dropped', call.original_id)
            # end if
        call.buffered = []
        for pending in call.buffered_awaiting.values():
            pending.settle(unavailable())
            # end for
        call.buffered_awaiting = {}
        if isinstance(frame, JSONRPCError):
            if outcomes:
                # An error carries no `_meta` to put them in, so they go in a round of their own first,
                # and the error follows on that round's retry (§6.4).
                call.buffered = outcomes
                self._keep_waiting(call, frame)
                self._schedule_round(call)
                return None
                # end if
            self._conclude_waiting(call)
            return JSONRPCError(jsonrpc='2.0', id=request_id, error=frame.error)
            # end if
        result = dict(frame.result)
        if outcomes:
            meta = dict(result.get(META) or {})
            meta[EXTENSION_ID] = {fields.SESSION_ID: call.session_id, fields.EVENTS: outcomes}
            result[META] = meta
            # end if
        self._conclude_waiting(call)
        return JSONRPCResponse(jsonrpc='2.0', id=request_id, result=result)
        # end def

    def _conclude_waiting(self, call: _ToolCall) -> None:
        """The call's final frame goes out now: nothing more is sent for it or kept of it."""
        call.ended = True
        call.final = None
        self._waiting.pop(_key(call.original_id), None)
        # end def

    def _read_handshake(self, method: str, params: dict[str, Any] | None) -> None:
        """Take the host's declaration out of the handshake request as it passes (§6.1, §6.5)."""
        fields_in = params or {}
        if method == DISCOVER_METHOD:
            capabilities = _meta_of(fields_in).get(CLIENT_CAPABILITIES_META_KEY)
        else:
            capabilities = fields_in.get('capabilities')
            # end if
        self._handshake_capability = capability_of(capabilities)
        self._handshake_seen = True
        # end def

    async def _on_close(self) -> None:
        """Settle every attempt in flight and drop every call's state: a closed connection answers nothing (§7.2)."""
        for pending, _owner in self._pending.values():
            pending.settle(unavailable())
            # end for
        self._pending = {}
        for call in [*self._calls.values(), *self._waiting.values()]:
            self._end_call(call, final=True)
            # end for
        for owner, out in list(self._rounds.values()):
            for pending in out.awaiting.values():
                pending.settle(unavailable())
                # end for
            out.answered.set()
            owner.ended = True
            # end for
        self._rounds = {}
        self._sessions = {}
        self._idle = {}
        self._cancelled = {}
        # end def

    # end class


class _Lane:
    """The audit work of one session, done in arrival order by one task (§6)."""

    def __init__(self) -> None:
        """Open the queue; the worker marks `done` when it stops, drained or cancelled."""
        self.send, self.receive = anyio.create_memory_object_stream[Job](math.inf)
        self.done = anyio.Event()
        # The scope of the job in progress, which only closing the connection cancels.
        self.job_scope: anyio.CancelScope | None = None
        # end def

    def take_queued(self) -> list[Job]:
        """Take every job still queued, once the worker has stopped; the queue is closed afterwards."""
        queued: list[Job] = []
        while True:
            try:
                queued.append(self.receive.receive_nowait())
            except (anyio.WouldBlock, anyio.EndOfStream, ClosedResourceError):
                break
                # end try
            # end while
        self.receive.close()
        return queued
        # end def

    # end class


@dataclass
class _HostCall:
    """A `tools/call` this host sent, and the audit session it issued for it (§6.3)."""

    original_id: RequestId
    params: dict[str, Any]
    session_id: str
    # The id the tool answers on: the original, or the latest retry this seam sent.
    current_id: RequestId
    # The id the client awaits: the original, or the latest retry the client sent itself (§6.4).
    client_id: RequestId
    lane: _Lane
    rounds: int = 0
    # The `requestState` of each of the call's rounds that went up to the client and awaits its retry.
    held: set[str] = field(default_factory=set)
    ended: bool = False
    # The per-request transport headers of the latest request the client sent for the call (`Mcp-Method`,
    # `Mcp-Name`, every `Mcp-Param-*`), which each retry this seam builds repeats (§6.4).
    headers: dict[str, str] | None = None
    # end class


@dataclass
class _RoundWork:
    """One round's events as they are worked through, and what was decided by the round's deadline."""

    events: list[object]
    # False when no retry follows the round, so no attempt of it can be answered and none is decided.
    decide: bool = True
    # The index of the next item not yet taken up.
    next: int = 0
    responses: dict[str, AttemptResponse] = field(default_factory=dict)
    # Set at the deadline: no further item is taken up, and a decision reached afterwards is not the
    # one the retry carries.
    cutoff: bool = False
    done: anyio.Event = field(default_factory=anyio.Event)

    def leftover_outcomes(self) -> list[object]:
        """The items not taken up by the deadline that are not attempts: they are sealed later, not dropped."""
        return [event for event in self.events[self.next :] if not _is_attempt(event)]
        # end def

    # end class


def _without_audit(result: dict[str, Any]) -> dict[str, Any]:
    """A copy of a result without this extension's `_meta` member, for the host's caller (§6.4).

    The events are the host's audit input. Passed on, they would show the caller the audit of the call
    it asked for - cleartext `action_context` included (§4.3) - as if they were the tool's result.
    """
    meta = result.get(META)
    if not isinstance(meta, dict) or EXTENSION_ID not in meta:
        return result
        # end if
    stripped = dict(result)
    rest = {key: value for key, value in meta.items() if key != EXTENSION_ID}
    if rest:
        stripped[META] = rest
    else:
        del stripped[META]
        # end if
    return stripped
    # end def


class McpAuditReceiver(_FrameSeam):
    """The host side of the wire: issues sessions, answers attempts, seals outcomes (§6, §7).

    A host is an MCP client. Its declaration goes out on the handshake (§6.5) and on every request that
    carries the client's capabilities (§6.4), and it is `endpoint.capability` - the requirement the
    endpoint enforces at runtime (§7) and the one it declares are the same object.

    Audit work is done per audit session, in arrival order, by a task of the session's own: one
    session's slow decision holds neither ordinary MCP traffic nor another session's events.
    """

    def __init__(
        self,
        read_stream: ReadStream,
        write_stream: WriteStream,
        endpoint: AuditEndpoint,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        """Wrap the transport's streams and bind them to the audit subsystem that decides.

        Args:
            read_stream: The transport's inbound stream.
            write_stream: The transport's outbound stream.
            endpoint: The audit subsystem that decides and seals.
            request_timeout: In seconds, the one deadline a §6.4 round's processing runs under, and the
                bound on the wait for the endpoint's decision on a §6.5 attempt. What is not decided by
                then is answered `unavailable`. Closing the connection waits as long for the work still
                queued, and as long again for each session's close.
        """
        super().__init__(read_stream, write_stream)
        self._endpoint = endpoint
        self._request_timeout = request_timeout
        # Calls that left the calls in flight - the client has their answer, or they were cancelled,
        # abandoned or evicted - while their outcomes are sealed and their session closes; closing the
        # connection waits for them.
        self._concluding: dict[int, _HostCall] = {}
        # Rounds that went up to the client and await its retry, by `requestState`, least recently held
        # first, with the Attempt Responses the retry is to carry.
        self._held: dict[str, tuple[_HostCall, dict[str, dict[str, object]]]] = {}
        # Calls in flight by the id the tool currently answers on.
        self._calls: dict[IdKey, _HostCall] = {}
        # The handshake request whose result carries the tool's declaration, until that result is read.
        self._handshake_id: IdKey | None = None
        # Outcomes received per session and not yet handed to the endpoint, for what closing reports.
        self._owed: dict[str, int] = {}
        self._handshake_read = False
        # end def

    def _open_lane(self) -> _Lane:
        """Start a session's worker, in the context of the client request that opened the session."""
        lane = _Lane()
        self._start(self._run_lane, lane, context=self._sending_context)
        return lane
        # end def

    async def _run_lane(self, lane: _Lane) -> None:
        """Do a session's audit work, one job at a time, until its queue closes.

        A job, once taken up, is shielded from a cancellation around the seam: a transport that fails a
        request inside its own task group cancels the session, and a seal cut short there would drop the
        outcome it holds (§6). Only closing the connection, at its bound, cancels a job. A cancellation
        between jobs stops the worker and leaves the queue open, so that closing the connection still
        does the work it holds (`_on_close`).
        """
        try:
            async for job in lane.receive:
                await self._run_job(lane, job)
                # end for
        finally:
            lane.done.set()
            # end try
        # end def

    @staticmethod
    async def _run_job(lane: _Lane, job: Job, deadline: float = math.inf) -> None:
        """Do one job of a lane, shielded, under the scope closing the connection cancels, by `deadline`."""
        with anyio.CancelScope(shield=True, deadline=deadline) as scope:
            lane.job_scope = scope
            try:
                await job()
            except (BrokenResourceError, ClosedResourceError):
                logger.warning('the connection went away while audit work was in progress')
            finally:
                lane.job_scope = None
                # end try
            # end with
        # end def

    def _dispatch(self, lane: _Lane | None, job: Job) -> None:
        """Queue `job` behind its session's earlier work; work for no open session runs on its own."""
        if lane is not None:
            try:
                lane.send.send_nowait(job)
                return
            except (BrokenResourceError, ClosedResourceError):
                logger.debug('the session ended; its late audit work runs on its own')
                # end try
            # end if
        self._start(job)
        # end def

    def _route(self, params: object, metadata: MessageMetadata) -> tuple[str, _Lane | None]:
        """The session an §6.5 event arrived on, and the lane its work goes to (§6.3, §6.5).

        Where the transport relates the request to a call, the event arrived on that call. Where it does
        not (stdio), it arrived on whichever call in flight on this connection its `session_id` names -
        and on none if it names a session this host did not issue for a call in flight here.
        """
        related = metadata.related_request_id if isinstance(metadata, ServerMessageMetadata) else None
        if related is not None:
            call = self._calls.get(_key(related))
            if call is not None:
                return call.session_id, call.lane
                # end if
            # end if
        claimed = params.get(fields.SESSION_ID) if isinstance(params, dict) else None
        for call in self._calls.values():
            if call.session_id == claimed:
                return call.session_id, call.lane
                # end if
            # end for
        return _NO_CALL, None
        # end def

    async def _outbound(self, frame: Frame) -> Frame | None:
        """Declare this host on the way out, and issue an audit session for each `tools/call` (§6.3)."""
        if not isinstance(frame, JSONRPCRequest):
            if isinstance(frame, JSONRPCNotification) and frame.method == CANCELLED_METHOD:
                return self._cancel(frame)
                # end if
            return frame
            # end if
        if frame.method in HANDSHAKE_METHODS and not self._handshake_read:
            self._handshake_id = _key(frame.id)
            # end if
        params = frame.params
        if params is not None:
            self._declare(frame.method, params)
            # end if
        if frame.method != TOOLS_CALL_METHOD or params is None:
            return frame
            # end if
        if not isinstance(params.get(META, {}), dict):
            # A `_meta` that is not an object has no room for the audit session, and rewriting it would
            # change the client's request; the call goes out as ordinary MCP, unaudited and untracked.
            logger.warning('tools/call %s carries a `_meta` that is not an object; it is not audited', frame.id)
            return frame
            # end if
        state = params.get(REQUEST_STATE)
        entry = self._held.pop(state, None) if isinstance(state, str) else None
        if entry is not None and isinstance(state, str):
            # The client's own retry of a round that asked it for input: the answers ride along, and
            # the call now answers on the id the client sent (§6.4).
            held, responses = entry
            held.held.discard(state)
            self._calls.pop(_key(held.current_id), None)
            held.current_id = frame.id
            held.client_id = frame.id
            self._calls[_key(frame.id)] = held
            meta = params.setdefault(META, {})
            meta[EXTENSION_ID] = {fields.SESSION_ID: held.session_id, fields.RESPONSES: responses}
            return frame
            # end if
        if isinstance(params.get(TASK), dict):
            # §6.4: this version does not audit a task-augmented call, so it carries no audit session.
            return frame
            # end if
        session_id = self._endpoint.open_session()
        params.setdefault(META, {})[EXTENSION_ID] = {fields.SESSION_ID: session_id}
        self._calls[_key(frame.id)] = _HostCall(
            original_id=frame.id,
            params=deepcopy(params),
            session_id=session_id,
            current_id=frame.id,
            client_id=frame.id,
            lane=self._open_lane(),
        )
        return frame
        # end def

    def _outbound_metadata(self, frame: Frame, metadata: MessageMetadata) -> MessageMetadata:
        """Carry the call's session in the affinity header of every request of an audited call (§6.4).

        The headers the session already set are kept: a client's own retry keeps its headers and gains
        the affinity header. The headers of the latest request the client sent for the call are
        remembered for the retries this seam builds. A transport without per-request headers ignores them.
        """
        if not isinstance(frame, JSONRPCRequest) or frame.method != TOOLS_CALL_METHOD:
            return metadata
            # end if
        call = self._calls.get(_key(frame.id))
        if call is None or call.ended:
            return metadata
            # end if
        own = metadata.headers if isinstance(metadata, ClientMessageMetadata) else None
        # The request the tool now answers is this one, so its headers are the ones a retry repeats.
        call.headers = dict(own or {})
        headers = with_affinity_header(own, call.session_id)
        if isinstance(metadata, ClientMessageMetadata):
            return replace(metadata, headers=headers)
            # end if
        return ClientMessageMetadata(headers=headers)
        # end def

    def _hold(self, call: _HostCall, state: str, responses: dict[str, dict[str, object]]) -> None:
        """Keep a round's answers for the client's retry, evicting beyond MAX_IDLE_SESSIONS (§6.4).

        A held round costs nothing until its retry comes, and a client may never retry. Beyond the bound
        the least recently held one is evicted: its call ends and its session closes, so the endpoint
        records every attempt it accepted and never saw resolved (§6.3).
        """
        previous = self._held.pop(state, None)
        if previous is not None and previous[0] is not call:
            logger.warning(
                'tools/call %s held a round under the requestState of tools/call %s (session %s), which is evicted',
                call.original_id,
                previous[0].original_id,
                previous[0].session_id,
            )
            self._evict(previous[0])
            # end if
        self._held[state] = (call, responses)
        call.held.add(state)
        while len(self._held) > MAX_IDLE_SESSIONS:
            evicted, _responses = next(iter(self._held.values()))
            logger.warning(
                'more than %s rounds await a client retry on this connection; tools/call %s (session %s) is '
                'evicted, and its session closes',
                MAX_IDLE_SESSIONS,
                evicted.original_id,
                evicted.session_id,
            )
            self._evict(evicted)
            # end while
        # end def

    def _evict(self, call: _HostCall) -> None:
        """End a call whose round waits on its client, closing its session in its lane (§6.3)."""
        self._detach(call)
        self._dispatch(call.lane, partial(self._close, call))
        # end def

    def _detach(self, call: _HostCall) -> None:
        """Take the call out of the calls in flight; what its lane still holds finishes before its close."""
        call.ended = True
        self._calls.pop(_key(call.current_id), None)
        for state in call.held:
            self._held.pop(state, None)
            # end for
        call.held.clear()
        self._concluding[id(call)] = call
        # end def

    def _declare(self, method: str, params: dict[str, Any]) -> None:
        """Write the host's declaration wherever this request carries the client's capabilities (§6.1)."""
        if method == INITIALIZE_METHOD:
            capabilities = params.setdefault('capabilities', {})
        else:
            meta = params.get(META)
            capabilities = meta.get(CLIENT_CAPABILITIES_META_KEY) if isinstance(meta, dict) else None
            # end if
        if isinstance(capabilities, dict):
            declare_into(capabilities, self._endpoint.capability)
            # end if
        # end def

    def _cancel(self, frame: JSONRPCNotification) -> Frame:
        """A cancelled call ends its session; the cancellation goes to the id the tool answers on (§6.3)."""
        params = frame.params or {}
        target = _key(params.get(REQUEST_ID))
        call = next((call for call in self._calls.values() if _key(call.client_id) == target), None)
        if call is None:
            return frame
            # end if
        self._evict(call)
        if _key(call.current_id) == target:
            return frame
            # end if
        return JSONRPCNotification(
            jsonrpc='2.0', method=CANCELLED_METHOD, params={**params, REQUEST_ID: call.current_id}
        )
        # end def

    async def _inbound(self, frame: Frame, metadata: MessageMetadata) -> Frame | None:
        """Answer §6.5's methods, and follow each call's rounds to its end (§6.4)."""
        if isinstance(frame, JSONRPCRequest) and frame.method == ATTEMPT_METHOD:
            session_id, lane = self._route(frame.params, metadata)
            self._dispatch(lane, partial(self._answer_attempt, frame, session_id))
            return None
            # end if
        if isinstance(frame, JSONRPCNotification) and frame.method == OUTCOME_METHOD:
            session_id, lane = self._route(frame.params, metadata)
            self._owe(session_id, 1)
            self._dispatch(lane, partial(self._seal_outcome, frame.params, session_id))
            return None
            # end if
        if isinstance(frame, JSONRPCRequest) and frame.method == OUTCOME_METHOD:
            # §6.5 defines the outcome as a notification. One sent as a request is a malformed envelope,
            # which is what a JSON-RPC error is for, and it is not sealed either way.
            await self._send_frame(
                JSONRPCError(
                    jsonrpc='2.0',
                    id=frame.id,
                    error=ErrorData(code=INVALID_REQUEST, message=f'{OUTCOME_METHOD} is a notification (§6.5)'),
                )
            )
            return None
            # end if
        if isinstance(frame, JSONRPCNotification) and frame.method == ATTEMPT_METHOD:
            # An attempt without an id has no response channel, so it cannot be accepted and the tool
            # cannot be told. Sealing it would record an operation the tool never learned was cleared.
            logger.warning('%s arrived as a notification; it cannot be answered, so it is dropped', ATTEMPT_METHOD)
            return None
            # end if
        if (
            isinstance(frame, JSONRPCResponse)
            and self._handshake_id is not None
            and _key(frame.id) == self._handshake_id
        ):
            self._handshake_id = None
            self._handshake_read = True
            self._check_declaration(frame.result.get('capabilities'))
            return frame
            # end if
        if isinstance(frame, JSONRPCResponse | JSONRPCError):
            call = self._calls.get(_key(frame.id))
            if call is not None and isinstance(frame, JSONRPCResponse) and isinstance(frame.result, dict):
                carried = self._events_of(frame.result, call)
                self._owe(call.session_id, sum(1 for event in carried if not _is_attempt(event)))
                # end if
            if call is not None and not call.ended and _concludes(frame):
                # The call's answer reaches the client at once. Sealing what it carries and closing the
                # session follow in the session's lane, behind the audit work already queued there: the
                # session ends when that is done (§6.3), but the client does not wait on the host's audit.
                self._detach(call)
                self._dispatch(call.lane, partial(self._conclude, call, frame))
                if isinstance(frame, JSONRPCError):
                    return JSONRPCError(jsonrpc='2.0', id=call.client_id, error=frame.error)
                    # end if
                return JSONRPCResponse(jsonrpc='2.0', id=call.client_id, result=_without_audit(frame.result))
                # end if
            if call is not None:
                self._dispatch(call.lane, partial(self._follow, call, frame))
                return None
                # end if
            # end if
        return frame
        # end def

    def _check_declaration(self, capabilities: object) -> None:
        """Warn when the tool's handshake declaration does not meet this host's requirement (§6.1, §6.2).

        The binding cannot refuse the connection for the host: whether an unaudited tool may be called
        is the host's decision, made on `capability_of(result.capabilities)`. What the binding owes it
        is that the fact is not silent, since every call the tool makes is otherwise unaudited.
        """
        declared = capability_of(capabilities)
        if declared is None:
            logger.warning(
                'the tool declared no auditable-mcp capability in the handshake (outcome %s); '
                'its calls are not audited',
                NegotiationOutcome.UNDECLARED,
            )
            return
            # end if
        fit = negotiate(self._endpoint.capability, declared)
        if not fit.negotiated:
            logger.warning(
                "the tool declared %s, which does not meet this host's requirement %s (outcome %s: "
                'version_match=%s level_fit=%s countersign_fit=%s); its calls are not audited',
                declared.to_wire(),
                self._endpoint.capability.to_wire(),
                fit.outcome,
                fit.version_match,
                fit.level_fit,
                fit.countersign_fit,
            )
            # end if
        # end def

    async def _conclude(self, call: _HostCall, frame: JSONRPCResponse | JSONRPCError) -> None:
        """Seal what the call's answer carries, then end the call (§6.3, §6.4); the client already has it."""
        if isinstance(frame, JSONRPCResponse) and isinstance(frame.result, dict):
            for event in self._events_of(frame.result, call):
                # A final result carries outcomes only; an attempt in it is refused as one (§6.4).
                await self._seal_outcome(event, call.session_id)
                # end for
            # end if
        await self._close(call)
        # end def

    async def _follow(self, call: _HostCall, frame: JSONRPCResponse | JSONRPCError) -> None:
        """Answer a round: decide and seal its events, then retry it or pass it up (§6.4).

        A job of the session's lane, and the round's one deadline runs from the moment the lane takes it
        up. The events are worked through in array order; the retry does not wait past the deadline for
        them. An attempt not decided by then is answered `unavailable` - one not yet reached is never
        handed to the endpoint, and one in progress completes in the background - and the outcomes not
        yet sealed are queued in the lane before the retry is sent, so the next round's events stay
        behind them.
        """
        deadline = anyio.current_time() + self._request_timeout
        if call.ended or not isinstance(frame, JSONRPCResponse):
            return
            # end if
        result = frame.result if isinstance(frame.result, dict) else {}
        events = self._events_of(result, call)
        call.rounds += 1
        state = result.get(REQUEST_STATE)
        if call.rounds > MAX_ROUNDS_PER_CALL:
            logger.warning(
                'tools/call %s exceeded %s rounds; the host stops retrying', call.original_id, MAX_ROUNDS_PER_CALL
            )
            message = f'the tool exceeded the limit of {MAX_ROUNDS_PER_CALL} audit rounds for one call'
            await self._abandon(call, events, message, deadline)
            return
            # end if
        if not isinstance(state, str):
            # §6.4 requires the round to carry a `requestState`; without one there is no retry to make and
            # nothing a client retry could be matched to.
            logger.warning('tools/call %s asked for input without a requestState; the host ends it', call.original_id)
            await self._abandon(call, events, 'the tool asked for input without a requestState (§6.4)', deadline)
            return
            # end if
        work = _RoundWork(events)
        await self._work_until(call, work, deadline)
        leftover = work.leftover_outcomes()
        if call.ended:
            # Cancelled mid-round: no retry follows, and the session's close is queued behind this job,
            # so what is left is sealed here, ahead of it.
            await self._seal_all(leftover, call.session_id)
            return
            # end if
        if leftover:
            self._dispatch(call.lane, partial(self._seal_all, leftover, call.session_id))
            # end if
        responses: dict[str, dict[str, object]] = {}
        for event in events:
            # An attempt is answered under its `id` where that is a string; any other refusal is the
            # endpoint's anomaly to record (§6.4).
            event_id = event.get(fields.ID) if _is_attempt(event) else None
            if isinstance(event_id, str):
                responses[event_id] = work.responses.get(event_id, unavailable()).to_wire()
                # end if
            # end for
        if result.get(INPUT_REQUESTS):
            # The round also asks the client for input, which only the client can give. It goes up; the
            # answers ride on the client's retry.
            self._hold(call, state, responses)
            await self._deliver_up(JSONRPCResponse(jsonrpc='2.0', id=call.client_id, result=_without_audit(result)))
            return
            # end if
        # A round that asks for nothing but the audit answers is retried here (§6.4).
        self._calls.pop(_key(call.current_id), None)
        retry_id = self._new_id()
        call.current_id = retry_id
        self._calls[_key(retry_id)] = call
        params = deepcopy(call.params)
        params[REQUEST_STATE] = state
        params.setdefault(META, {})[EXTENSION_ID] = {fields.SESSION_ID: call.session_id, fields.RESPONSES: responses}
        # A retry is the same request, so it repeats the request metadata headers of the one it repeats,
        # and carries the call's session in the affinity header like every request of the call (§6.4).
        headers = with_affinity_header(call.headers, call.session_id)
        try:
            await self._send_frame(
                JSONRPCRequest(jsonrpc='2.0', id=retry_id, method=TOOLS_CALL_METHOD, params=params),
                metadata=ClientMessageMetadata(headers=headers),
            )
        except (BrokenResourceError, ClosedResourceError):
            if call.ended:
                return
                # end if
            # A call whose retry cannot leave would otherwise wait on an answer that never comes.
            logger.warning('the retry of tools/call %s could not be sent; the call ends', call.original_id)
            self._detach(call)
            self._dispatch(call.lane, partial(self._close, call))
            error = ErrorData(code=INTERNAL_ERROR, message=RETRY_NOT_SENT_MESSAGE)
            await self._deliver_up(JSONRPCError(jsonrpc='2.0', id=call.client_id, error=error))
            # end try
        # end def

    async def _work_until(self, call: _HostCall, work: _RoundWork, deadline: float) -> None:
        """Work through a round's events until they are done or `deadline` passes, then cut it off (§6.4).

        The items are taken up by a task of their own, so the item in progress at the deadline
        completes - the endpoint is not cancelled mid-seal - while the round goes on without it.
        """
        self._start(self._work_through, call, work, deadline)
        with anyio.CancelScope(deadline=deadline):
            await work.done.wait()
            # end with
        work.cutoff = True
        if not work.done.is_set():
            logger.warning(
                'the round of tools/call %s (session %s) was not processed within %ss; what is undecided is '
                'answered unavailable, and its outcomes are sealed after the retry',
                call.original_id,
                call.session_id,
                self._request_timeout,
            )
            # end if
        # end def

    async def _work_through(self, call: _HostCall, work: _RoundWork, deadline: float) -> None:
        """Take up a round's events in array order, one at a time, until they are done or cut off (§6.4)."""
        try:
            while work.next < len(work.events) and not work.cutoff:
                event = work.events[work.next]
                work.next += 1
                # One item at a time (§6.4): an invalid one is refused alone.
                if not _is_attempt(event):
                    await self._seal_outcome(event, call.session_id)
                    continue
                    # end if
                if not work.decide:
                    continue
                    # end if
                answer = await self._hand_over(event, call.session_id, deadline)
                event_id = event.get(fields.ID)
                if isinstance(event_id, str) and not work.cutoff:
                    work.responses[event_id] = answer
                    # end if
                # end while
        finally:
            work.done.set()
            # end try
        # end def

    async def _seal_all(self, events: list[object], session_id: str) -> None:
        """Seal outcomes, in order."""
        for event in events:
            await self._seal_outcome(event, session_id)
            # end for
        # end def

    async def _abandon(self, call: _HostCall, events: list[object], message: str, deadline: float) -> None:
        """Stop following a round: seal its outcomes, leave its attempts unanswered, end the call (§6.4)."""
        # No retry follows, so no attempt of the round could be answered, and deciding one would seal an
        # operation the tool never learns was cleared. Its outcomes are already final and are kept.
        self._detach(call)
        work = _RoundWork(events, decide=False)
        await self._work_until(call, work, deadline)
        leftover = work.leftover_outcomes()
        if leftover:
            self._dispatch(call.lane, partial(self._seal_all, leftover, call.session_id))
            # end if
        self._dispatch(call.lane, partial(self._close, call))
        error = ErrorData(code=INTERNAL_ERROR, message=message)
        await self._deliver_up(JSONRPCError(jsonrpc='2.0', id=call.client_id, error=error))
        # end def

    def _events_of(self, result: dict[str, Any], call: _HostCall) -> list[object]:
        """The items a result carries as events for this call's session, in the order the tool emitted them.

        Every item is returned, an invalid one included: each is refused on its own (§6.4), and one left
        out here would be dropped with no anomaly recorded for it.
        """
        meta = result.get(META)
        carried = meta.get(EXTENSION_ID) if isinstance(meta, dict) else None
        if not isinstance(carried, dict):
            return []
            # end if
        events = carried.get(fields.EVENTS)
        if not isinstance(events, list):
            logger.warning('tools/call %s carried an audit `_meta` without events', call.original_id)
            return []
            # end if
        return list(events)
        # end def

    async def _close(self, call: _HostCall) -> None:
        """Close the call's session, recording any unresolved attempt, and stop its lane (§6.3)."""
        try:
            await self._endpoint.close_session(call.session_id)
        finally:
            call.lane.send.close()
            self._concluding.pop(id(call), None)
            # end try
        # end def

    async def _hand_over(self, event: dict[str, object], session_id: str, deadline: float) -> AttemptResponse:
        """Hand an attempt to the endpoint with the deadline it is answered by, turning a raise into `unavailable`."""
        try:
            return await self._endpoint.handle_attempt(event, session_id=session_id, deadline=deadline)
        except Exception:
            # §6 requires every audit-layer decision to travel as an Attempt Response, never as an
            # error, so an endpoint that raised has to be turned into one. It recorded nothing, which
            # is what `unavailable` says, and the tool already fails closed on it (§7.2).
            logger.exception('the audit endpoint raised while deciding an attempt')
            return unavailable()
            # end try
        # end def

    async def _decide(self, event: dict[str, object], session_id: str) -> AttemptResponse:
        """Hand a §6.5 attempt to the endpoint, bounded, turning a late decision into `unavailable`.

        The wait is bounded because the tool's answer to its caller waits on it, and past the tool's own
        bound the attempt has failed closed anyway. A decision that arrives late still completes - the
        endpoint is not cancelled mid-seal - and the tool, told `unavailable`, does not act (§7.2); the
        record it leaves is concluded by the tool's abort. One the endpoint had not yet taken up by the
        deadline records nothing (`AuditEndpoint.handle_attempt`).
        """
        decided: list[AttemptResponse] = []
        done = anyio.Event()
        deadline = anyio.current_time() + self._request_timeout

        async def decide() -> None:
            try:
                decided.append(await self._hand_over(event, session_id, deadline))
            finally:
                done.set()
                # end try
            # end def

        self._start(decide)
        with anyio.CancelScope(deadline=deadline):
            await done.wait()
            # end with
        if decided:
            return decided[0]
            # end if
        logger.warning(
            'the audit endpoint did not decide an attempt within %ss; answering unavailable', self._request_timeout
        )
        return unavailable()
        # end def

    async def _answer_attempt(self, frame: JSONRPCRequest, session_id: str) -> None:
        """Answer a §6.5 `audit/attempt` with the endpoint's decision as a JSON-RPC result."""
        response = await self._decide(dict(frame.params or {}), session_id)
        await self._send_frame(JSONRPCResponse(jsonrpc='2.0', id=frame.id, result=response.to_wire()))
        # end def

    async def _on_close(self) -> None:
        """The connection ended, so every call still open on it has ended too (§6.3).

        The work already queued in each session's lane - outcomes to seal, sessions to close - gets one
        bound, `request_timeout`, to finish. Then every session, in flight or concluding, is closed, each
        close bounded as long again. What a lane still holds when the bound expires is not done, and
        each such session is logged by id rather than dropped in silence.

        Both waits are shielded from a cancellation around the seam: a transport that fails a request
        inside its own task group (Streamable HTTP, when the tool goes away) cancels the session, and the
        sessions still have to close, so that the attempts the tool never resolved are recorded (§6.3).
        """
        calls = list({id(call): call for call in self._calls.values()}.values())
        self._calls = {}
        self._held = {}
        for call in calls:
            call.ended = True
            call.lane.send.close()
            # end for
        waited = list({id(call): call for call in [*calls, *self._concluding.values()]}.values())
        undone: dict[int, list[Job]] = {}
        closing_by = anyio.current_time() + self._request_timeout
        with anyio.move_on_after(self._request_timeout, shield=True):
            for call in waited:
                await call.lane.done.wait()
                # A worker cancelled around the seam leaves its queue behind; the work in it - outcomes
                # to seal above all (§6) - is done here, in order, under the same bound, which each job
                # is held to as well: a job is shielded, so the bound around it does not reach it.
                undone[id(call)] = call.lane.take_queued()
                while undone[id(call)]:
                    await self._run_job(call.lane, undone[id(call)].pop(0), closing_by)
                    # end while
                # end for
            # end with
        for call in waited:
            if call.lane.job_scope is not None:
                # The bound has passed: the job in progress is abandoned so that the connection closes.
                call.lane.job_scope.cancel()
                # end if
            # end for
        for call in waited:
            left = len(undone.get(id(call), [])) if call.lane.done.is_set() else None
            unsealed = self._owed.pop(call.session_id, 0)
            if left is None or left or unsealed:
                # The session's close below records each attempt these outcomes would have resolved as
                # `unresolved-attempt` (§6.3).
                logger.warning(
                    'the connection closed with audit work of session %s unfinished (%s job(s) not done, %s '
                    'outcome(s) not sealed); their attempts are recorded unresolved',
                    call.session_id,
                    call.lane.send.statistics().current_buffer_used if left is None else left,
                    unsealed,
                )
                # end if
            # Idempotent: a session its lane already closed is not closed twice.
            with anyio.move_on_after(self._request_timeout, shield=True) as scope:
                await self._endpoint.close_session(call.session_id)
                # end with
            if scope.cancelled_caught:
                logger.warning(
                    'audit session %s could not be closed within %ss as the connection closed',
                    call.session_id,
                    self._request_timeout,
                )
                # end if
            # end for
        self._concluding = {}
        # end def

    def _owe(self, session_id: str, outcomes: int) -> None:
        """Count outcomes of a session received and not yet handed to the endpoint."""
        if outcomes:
            self._owed[session_id] = self._owed.get(session_id, 0) + outcomes
            # end if
        # end def

    async def _seal_outcome(self, params: object, session_id: str) -> None:
        """Hand an outcome to the endpoint. It has no response (§6).

        An item that is not an object reaches the endpoint as an empty event, which fails structural
        validation and is recorded `schema-invalid` in its anomaly set (§6).
        """
        event = dict(params) if isinstance(params, dict) else {}
        try:
            await self._endpoint.handle_outcome(event, session_id=session_id)
        except Exception:
            # There is no channel to answer on, so the endpoint's own anomaly set is where this belongs
            # (§7.6); the log is here because a raise instead of an anomaly is a host-side defect.
            logger.exception('the audit endpoint raised while sealing an outcome')
            # end try
        # Handed over, whatever the endpoint made of it; one cut short above is still owed.
        owed = self._owed.get(session_id, 0)
        if owed > 1:
            self._owed[session_id] = owed - 1
        elif owed:
            del self._owed[session_id]
            # end if
        # end def

    # end class
