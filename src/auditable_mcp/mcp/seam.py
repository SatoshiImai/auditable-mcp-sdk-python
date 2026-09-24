"""Carrying `audit/attempt` and `audit/outcome` on an MCP connection (§6).

Neither official MCP SDK can deliver these methods through its own dispatch: a session parses each
incoming message into a fixed request union and answers anything outside it before a handler is
consulted, and the Python client registers no request handlers at all. Nothing about the audit wire
needs that dispatch, though — it is ordinary JSON-RPC on the connection MCP already holds — so this
binding sits one layer lower, between the session and the transport streams.

Each side wraps the stream pair its transport yields and hands its session a pair of its own. Audit
frames are taken out of the inbound flow and answered here; every other message passes through
untouched, in order, so the session sees exactly the MCP it would have seen without this extension.
The two roles are separate classes because the obligations are: a tool cannot be made to seal an
attempt, and a host cannot be made to send one.

Three §6 obligations live here and nowhere else in this SDK:

- An `audit/attempt` is never batched. This binding writes one JSON-RPC message per frame and has no
  array form to put one in.
- The wait for a decision is bounded, and silence fails closed: an attempt that times out returns
  `unavailable`, which aborts the action rather than letting it run unrecorded (§7.2).
- Nothing is sent in an unnegotiated session (§6.2). `negotiate` is what opens the send path, so a
  transport that never negotiated, or negotiated and did not fit, refuses to send at all.

The audit frames also ride the `tools/call` they belong to. §4 defines `call_id` as that call's
JSON-RPC request id as a string, so the seam keeps the live inbound requests and tags its own frames
with the original id. On stdio this changes nothing; on a Streamable HTTP connection it is what puts
a server-to-client request on the stream of the request in flight rather than on a standalone one
the host may never have opened.
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any, Self

import anyio
import anyio.abc
from anyio import BrokenResourceError, ClosedResourceError
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.types import (
    INVALID_REQUEST,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)
from pydantic import TypeAdapter, ValidationError

from auditable_mcp.capability import NegotiationResult, negotiate
from auditable_mcp.mcp.declaration import capability_of, declare_into
from auditable_mcp.models import AttemptResponse, AuditCapability
from auditable_mcp.transport import AmcpUsageError, AuditEndpoint, unavailable

logger = logging.getLogger(__name__)

# The literal method names of §6. `params` IS the audit event object, never a wrapper.
ATTEMPT_METHOD = 'audit/attempt'
OUTCOME_METHOD = 'audit/outcome'
INITIALIZE_METHOD = 'initialize'

# Audit request ids are strings under this prefix. An MCP session numbers its own requests with
# integers, so the two id spaces cannot collide however long either side runs, and neither can claim
# the other's response by accident.
ID_PREFIX = 'amcp-'

# §6 leaves the bound on the wait to the transport, requiring only that it fail closed.
DEFAULT_REQUEST_TIMEOUT = 30.0

ReadStream = MemoryObjectReceiveStream[SessionMessage | Exception]
WriteStream = MemoryObjectSendStream[SessionMessage]
Frame = JSONRPCRequest | JSONRPCNotification | JSONRPCResponse | JSONRPCError

_RESPONSE_ADAPTER: TypeAdapter[AttemptResponse] = TypeAdapter(AttemptResponse)


class McpBindingError(AmcpUsageError):
    """The binding was driven into a state §6 does not define."""

    # end class


class HandshakeNotSeenError(McpBindingError):
    """Negotiation was asked for before the peer's `initialize` reached this seam (§6.1)."""

    # end class


class UnnegotiatedSendError(McpBindingError):
    """A send was attempted on a session that is not audit-negotiated (§6.2)."""

    # end class


class _Pending:
    """One in-flight `audit/attempt`, waiting for the host's decision."""

    def __init__(self) -> None:
        """Arm the wait with no decision yet."""
        self.arrived = anyio.Event()
        self.response: AttemptResponse | None = None
        # end def

    def settle(self, response: AttemptResponse) -> None:
        """Record the decision and release the waiter."""
        self.response = response
        self.arrived.set()
        # end def

    # end class


class _FrameSeam:
    """Stream plumbing shared by both roles: pass MCP through, take `audit/*` out.

    The session is handed the inner ends of two memory streams and drives them as it would drive the
    transport's own. Two pump tasks move messages across, so the session's receive loop is never the
    thing that has to be running for an audit frame to be answered, and an audit exchange in flight
    never stalls ordinary MCP traffic.
    """

    def __init__(self, read_stream: ReadStream, write_stream: WriteStream) -> None:
        """Wrap the transport's stream pair and build the pair the session will be given."""
        self._outer_read = read_stream
        self._outer_write = write_stream
        self._to_session, self._session_read = anyio.create_memory_object_stream[SessionMessage | Exception](1)
        self._session_write, self._from_session = anyio.create_memory_object_stream[SessionMessage](1)
        # Audit frames join the queue the session writes to, so one task owns the outbound stream and
        # the order messages leave in is the order they were produced in.
        self._frames_out = self._session_write.clone()
        self._task_group: anyio.abc.TaskGroup | None = None
        # The inbound requests still in flight, by the string form §4 gives their ids.
        self._live: dict[str, str | int] = {}
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
        """Settle whatever is in flight, then stop the pumps without waiting on the peer."""
        await self._on_close()
        await self._frames_out.aclose()
        task_group = self._task_group
        if task_group is None:
            return None
            # end if
        task_group.cancel_scope.cancel()
        return await task_group.__aexit__(exc_type, exc_val, exc_tb)
        # end def

    async def _pump_inbound(self) -> None:
        """Deliver everything the peer sends to the session, except the frames this side owns."""
        try:
            async for message in self._outer_read:
                if isinstance(message, Exception):
                    await self._to_session.send(message)
                    continue
                    # end if
                if not await self._intercept(message.message.root):
                    self._track(message.message.root)
                    await self._to_session.send(message)
                    # end if
                # end for
        except (BrokenResourceError, ClosedResourceError):
            logger.debug('the session stopped reading; the inbound pump ends with it')
        finally:
            await self._to_session.aclose()
            # end try
        # end def

    async def _pump_outbound(self) -> None:
        """Forward what the session and this seam write, unchanged and in order."""
        try:
            async for message in self._from_session:
                self._declare_on(message.message.root)
                self._retire(message.message.root)
                await self._outer_write.send(message)
                # end for
        except (BrokenResourceError, ClosedResourceError):
            logger.debug('the connection went away; the outbound pump ends with it')
            # end try
        # end def

    async def _send_frame(self, frame: Frame, related_request_id: str | int | None = None) -> None:
        """Queue one JSON-RPC message for the peer. One message per frame, never an array (§6)."""
        metadata = None if related_request_id is None else ServerMessageMetadata(related_request_id=related_request_id)
        await self._frames_out.send(SessionMessage(message=JSONRPCMessage(frame), metadata=metadata))
        # end def

    def _related_request_id(self, call_id: object) -> str | int | None:
        """The id §4's `call_id` names, if that call is still in flight.

        The string form is what the event carries; the transport routes on the original, so a numeric
        id must come back as the number it was - `42` and `"42"` are different requests to it.
        """
        return self._live.get(call_id) if isinstance(call_id, str) else None
        # end def

    def _track(self, frame: Frame) -> None:
        """Remember an inbound request while it is in flight.

        Only what reaches the session: a frame this seam answered itself is not a call anything
        still owes an answer to, and keeping it would grow this map for the life of the connection.
        """
        if isinstance(frame, JSONRPCRequest):
            self._live[str(frame.id)] = frame.id
            # end if
        # end def

    def _retire(self, frame: Frame) -> None:
        """A request leaves flight when its response goes out."""
        if isinstance(frame, JSONRPCResponse | JSONRPCError):
            self._live.pop(str(frame.id), None)
            # end if
        # end def

    async def _intercept(self, frame: Frame) -> bool:
        """Handle a frame this side owns; return True when the session must not see it."""
        raise NotImplementedError
        # end def

    def _declare_on(self, frame: Frame) -> None:
        """Declare this extension on the outgoing handshake, if this frame is it (§6.1)."""
        # end def

    async def _on_close(self) -> None:
        """Release anything the role is holding. Nothing by default."""
        # end def

    # end class


class McpAuditTransport(_FrameSeam):
    """The tool side of the wire: an `AuditTransport` that speaks §6 over an MCP connection.

    A tool is an MCP server, so both halves of the handshake pass through this seam: the host's
    declaration arrives in the `initialize` request, and the tool's goes out in the `initialize`
    result. The seam reads the first and writes the second, so `negotiate` needs nothing passed in and
    what the tool declared on the wire is what it negotiates with — there is no second copy to drift.
    """

    def __init__(
        self,
        read_stream: ReadStream,
        write_stream: WriteStream,
        declares: AuditCapability,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        """Wrap the transport's streams, hold the declaration, and arm the bound §6 leaves to this layer."""
        super().__init__(read_stream, write_stream)
        self._declares = declares
        self._handshake_id: str | int | None = None
        self._request_timeout = request_timeout
        self._pending: dict[str, _Pending] = {}
        self._next_id = 0
        self._handshake_seen = False
        self._host_capability: AuditCapability | None = None
        self._negotiated = False
        # end def

    @property
    def handshake_seen(self) -> bool:
        """True once the peer's `initialize` has passed through this seam."""
        return self._handshake_seen
        # end def

    @property
    def host_capability(self) -> AuditCapability | None:
        """What the host declared at `initialize`, or None if it declared nothing readable (§6.1)."""
        return self._host_capability
        # end def

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Compare the host's declaration against the tool's, and open the send path if they fit (§6.1).

        Args:
            offered: The audit capability this tool declares.

        Returns:
            The fit, carrying both declarations and the axis that decided it.

        Raises:
            HandshakeNotSeenError: Called before the peer's `initialize` reached this seam. Until then
                an absent declaration is indistinguishable from one that has not arrived, and reading
                it as absent would degrade a session that was about to negotiate (§6.2).
            McpBindingError: `offered` is not what this transport declared on the wire. Negotiating
                against a capability the host was never shown would make the outcome unverifiable by
                the peer that has to live with it (§6.1).
        """
        if not self._handshake_seen:
            raise HandshakeNotSeenError('the peer has not sent `initialize` yet; negotiate after the handshake (§6.1)')
            # end if
        if offered != self._declares:
            raise McpBindingError('this transport declared a different capability at `initialize` (§6.1)')
            # end if
        result = negotiate(self._host_capability, offered)
        self._negotiated = result.negotiated
        return result
        # end def

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Send `audit/attempt` and block for the host's decision, failing closed on silence (§6, §7.2)."""
        self._require_negotiated()
        request_id = self._new_id()
        pending = _Pending()
        self._pending[request_id] = pending
        try:
            await self._send_frame(
                JSONRPCRequest(jsonrpc='2.0', id=request_id, method=ATTEMPT_METHOD, params=dict(event)),
                self._related_request_id(event.get('call_id')),
            )
            with anyio.move_on_after(self._request_timeout):
                await pending.arrived.wait()
                # end with
        except (BrokenResourceError, ClosedResourceError):
            logger.warning('the connection is gone; %s could not be sent', ATTEMPT_METHOD)
            return unavailable()
        finally:
            self._pending.pop(request_id, None)
            # end try
        if pending.response is None:
            logger.warning('no decision for %s within %ss; failing closed', request_id, self._request_timeout)
            return unavailable()
            # end if
        return pending.response
        # end def

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Send `audit/outcome` as a notification: reported, not awaited (§6)."""
        self._require_negotiated()
        try:
            await self._send_frame(
                JSONRPCNotification(jsonrpc='2.0', method=OUTCOME_METHOD, params=dict(event)),
                self._related_request_id(event.get('call_id')),
            )
        except (BrokenResourceError, ClosedResourceError):
            # An outcome has no response channel and no retry in §6; the host detects the gap by the
            # attempt it sealed and never saw resolved, which is what §7.5 is for.
            logger.warning('the connection is gone; %s could not be sent', OUTCOME_METHOD)
            # end try
        # end def

    def _require_negotiated(self) -> None:
        """Refuse to put an audit frame on an unnegotiated session (§6.2)."""
        if not self._negotiated:
            raise UnnegotiatedSendError(
                'this session is not audit-negotiated, so no audit message may be sent; '
                'choose the transport with `transport_for` after `negotiate` (§6.2)'
            )
            # end if
        # end def

    def _new_id(self) -> str:
        """Return the next audit request id, in the string space the session never uses."""
        self._next_id += 1
        return f'{ID_PREFIX}{self._next_id}'
        # end def

    async def _intercept(self, frame: Frame) -> bool:
        """Claim the responses to this seam's own requests; read the handshake on the way past."""
        if isinstance(frame, JSONRPCRequest) and frame.method == INITIALIZE_METHOD:
            self._handshake_id = frame.id
            self._read_handshake(frame.params)
            return False
            # end if
        if isinstance(frame, JSONRPCResponse | JSONRPCError) and isinstance(frame.id, str):
            pending = self._pending.get(frame.id)
            if pending is not None:
                pending.settle(self._decision(frame))
                return True
                # end if
            # end if
        return False
        # end def

    def _decision(self, frame: JSONRPCResponse | JSONRPCError) -> AttemptResponse:
        """Read the host's decision, treating anything unreadable as a failure to record (§6, §7.2)."""
        # §6 reserves JSON-RPC errors for protocol faults and requires the tool to read one for an
        # attempt as a failure to record, exactly as for `unavailable`. A frame carrying both members
        # is not valid JSON-RPC, and the error is what stands: reading the result beside it would let
        # a malformed answer clear an operation.
        if isinstance(frame, JSONRPCError) or 'error' in (frame.model_extra or {}):
            logger.warning('audit/attempt %s answered with a JSON-RPC error', frame.id)
            return unavailable()
            # end if
        try:
            return _RESPONSE_ADAPTER.validate_python(frame.result)
        except ValidationError as error:
            logger.warning('audit/attempt %s answered with an unreadable result: %s', frame.id, error)
            return unavailable()
            # end try
        # end def

    def _read_handshake(self, params: dict[str, Any] | None) -> None:
        """Take the host's declaration out of the `initialize` request as it passes (§6.1)."""
        capabilities = (params or {}).get('capabilities')
        self._host_capability = capability_of(capabilities)
        self._handshake_seen = True
        # end def

    def _declare_on(self, frame: Frame) -> None:
        """Write the tool's declaration into the `initialize` result on its way out (§6.1)."""
        if isinstance(frame, JSONRPCResponse) and frame.id == self._handshake_id:
            capabilities = frame.result.setdefault('capabilities', {})
            if isinstance(capabilities, dict):
                declare_into(capabilities, self._declares)
                # end if
            # end if
        # end def

    async def _on_close(self) -> None:
        """Settle every attempt still in flight: a closed connection will not answer one (§7.2)."""
        for pending in self._pending.values():
            pending.settle(unavailable())
            # end for
        # end def

    # end class


class McpAuditReceiver(_FrameSeam):
    """The host side of the wire: answers `audit/attempt` and seals `audit/outcome` (§6, §7).

    A host is an MCP client, and the tool's declaration comes back in the `initialize` result the
    session already returns, so there is nothing to intercept for negotiation here: read it with
    `capability_of(result.capabilities)`. The host's own declaration goes out on the handshake, and it
    is `endpoint.capability` — the requirement the endpoint enforces at runtime (§7) and the one it
    declares are the same object, so a host cannot advertise one thing and apply another.
    """

    def __init__(self, read_stream: ReadStream, write_stream: WriteStream, endpoint: AuditEndpoint) -> None:
        """Wrap the transport's streams and bind them to the audit subsystem that decides."""
        super().__init__(read_stream, write_stream)
        self._endpoint = endpoint
        # end def

    def _declare_on(self, frame: Frame) -> None:
        """Write the host's declaration into the `initialize` request on its way out (§6.1)."""
        if isinstance(frame, JSONRPCRequest) and frame.method == INITIALIZE_METHOD and frame.params is not None:
            capabilities = frame.params.setdefault('capabilities', {})
            if isinstance(capabilities, dict):
                declare_into(capabilities, self._endpoint.capability)
                # end if
            # end if
        # end def

    async def _intercept(self, frame: Frame) -> bool:
        """Answer the audit traffic; leave every other message to the session."""
        if isinstance(frame, JSONRPCRequest) and frame.method == ATTEMPT_METHOD:
            await self._answer_attempt(frame)
            return True
            # end if
        if isinstance(frame, JSONRPCNotification) and frame.method == OUTCOME_METHOD:
            await self._seal_outcome(frame)
            return True
            # end if
        if isinstance(frame, JSONRPCRequest) and frame.method == OUTCOME_METHOD:
            # §6 defines the outcome channel as a notification. One sent as a request is a malformed
            # envelope, which is what a JSON-RPC error is for, and it is not sealed either way.
            await self._send_frame(
                JSONRPCError(
                    jsonrpc='2.0',
                    id=frame.id,
                    error=ErrorData(code=INVALID_REQUEST, message=f'{OUTCOME_METHOD} is a notification (§6)'),
                )
            )
            return True
            # end if
        if isinstance(frame, JSONRPCNotification) and frame.method == ATTEMPT_METHOD:
            # An attempt sent without an id has no response channel, so it cannot be accepted and the
            # tool cannot be told. Sealing it anyway would record an operation the tool never learned
            # it was cleared for, which is the one thing §6 guarantees against.
            logger.warning('%s arrived as a notification; it cannot be answered, so it is dropped', ATTEMPT_METHOD)
            return True
            # end if
        return False
        # end def

    async def _answer_attempt(self, frame: JSONRPCRequest) -> None:
        """Hand the event to the endpoint and return its decision as a JSON-RPC result (§6, §7.1)."""
        response: AttemptResponse
        try:
            response = await self._endpoint.handle_attempt(dict(frame.params or {}))
        except Exception:
            # §6 requires every audit-layer decision to travel as a result, never as a JSON-RPC error,
            # so an endpoint that raised has to be turned into one. It recorded nothing, which is what
            # `unavailable` says, and the tool already fails closed on it (§7.2). Narrowing this would
            # let a host-side defect reach the tool as a protocol fault instead of an audit decision.
            logger.exception('the audit endpoint raised while handling %s', ATTEMPT_METHOD)
            response = unavailable()
            # end try
        await self._send_frame(JSONRPCResponse(jsonrpc='2.0', id=frame.id, result=response.to_wire()))
        # end def

    async def _seal_outcome(self, frame: JSONRPCNotification) -> None:
        """Hand the outcome to the endpoint. A notification has no response channel (§6)."""
        try:
            await self._endpoint.handle_outcome(dict(frame.params or {}))
        except Exception:
            # There is no channel to answer on, so the endpoint's own anomaly set is where this belongs
            # (§7.6); the log is here because a raise instead of an anomaly is a host-side defect.
            logger.exception('the audit endpoint raised while handling %s', OUTCOME_METHOD)
            # end try
        # end def

    # end class
