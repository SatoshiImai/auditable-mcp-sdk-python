"""The audit transport seam and host-endpoint contract.

Auditable MCP carries tool-to-host messages while a `tools/call` is in flight (§6). This module
defines the exchange's two abstract sides and keeps the core free of any concrete wire; a binding
(§6.4, §6.5) carries them:

- `AuditTransport` — the tool's view, for one call. `send_attempt` resolves with the host's answer
  (the tool must not act unless it is `accept`, §6); `send_outcome` has no answer.
- `AuditEndpoint` — the host's view, i.e. what a transport delivers to. The host audit subsystem
  implements it; an in-process transport (`in_process.py`) forwards straight to it.

The per-operation calls are async because a real transport crosses the wire. Capability negotiation
is a local fit computation (§6.1), so it stays synchronous. Response construction helpers are provided
for host implementers. An integrator wires this seam over MCP; `InProcessTransport` embeds the host in
the tool's process.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from auditable_mcp.capability import NegotiationResult
from auditable_mcp.models import (
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    RejectReason,
    RejectResponse,
    UnavailableResponse,
)


class AmcpUsageError(Exception):
    """This SDK was driven into a state its own contract forbids.

    Distinct from a transport fault: a fault is a failure to record, which §7.2 turns into an
    `aborted` outcome and a fail-closed halt, whereas this is an integrator error that no audit
    outcome describes. The session's fail-closed catch re-raises it rather than filing an `aborted`
    record that blames the host for it (§6.2, §11.3).
    """

    # end class


def accept(
    seq: int,
    record_hash: str,
    host_ts: str,
    previous_hash: str,
    *,
    host_signature: str | None = None,
    host_key_id: str | None = None,
    log_id: str | None = None,
) -> AcceptResponse:
    """Build a Verifiable Accept, with the countersignature when the host countersigns (§7.1, §5.2)."""
    return AcceptResponse(
        seq=seq,
        record_hash=record_hash,
        host_ts=host_ts,
        previous_hash=previous_hash,
        host_signature=host_signature,
        host_key_id=host_key_id,
        log_id=log_id,
    )
    # end def


def reject(reason: RejectReason) -> RejectResponse:
    """Build a reject response with a Tier-1 reject `reason` (ledger integrity not guaranteed, §7.1)."""
    return RejectResponse(reason=reason)
    # end def


def unavailable() -> UnavailableResponse:
    """Build an unavailable response: nothing was decided (§7.1; `reason` is internal-error)."""
    return UnavailableResponse()
    # end def


@runtime_checkable
class AuditTransport(Protocol):
    """The tool-side transport for one call: negotiate, then send attempts and outcomes (§6)."""

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Present the tool's own capability and learn the host's declaration and the fit (§6.1, §6.2)."""
        ...

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Send an attempt and resolve with the host's answer (§6)."""
        ...

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Send an outcome, which has no answer (§6)."""
        ...

    # end class


@runtime_checkable
class AuditEndpoint(Protocol):
    """The host-side audit subsystem a transport delivers to."""

    @property
    def capability(self) -> AuditCapability:
        """The audit capability this host requires (§6.1)."""
        ...

    def open_session(self, session_id: str | None = None) -> str:
        """Issue a fresh audit session for a call the host audits, and return its id (§6.3)."""
        ...

    async def close_session(self, session_id: str) -> None:
        """Close an audit session because its call ended (§6.3)."""
        ...

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable (§7.1).

        `session_id`, when given, is the audit session of the call the attempt arrived on, which the
        event must carry (§6.3). `deadline`, when given, is a time on the event loop's clock
        (`anyio.current_time()`) after which the binding has already answered the tool `unavailable`
        (§6.4): an attempt the endpoint takes up after it is answered `unavailable` and records nothing.
        """
        ...

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Seal an outcome, or drop and record it (§7.2)."""
        ...

    # end class
