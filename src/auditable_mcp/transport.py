"""The audit transport seam and host-endpoint contract.

Auditable MCP carries tool-to-host messages while a `tools/call` is in flight (§6). This module
defines two abstract sides and keeps the core free of any concrete wire:

- `AuditTransport` — the tool's view. `send_attempt` is a blocking request (the tool awaits it and
  must not act unless the response is `accept`, §6); `send_outcome` is fire-and-forget.
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


def accept(seq: int, record_hash: str, host_ts: str, previous_hash: str) -> AcceptResponse:
    """Build a Verifiable Accept carrying the fields the tool needs for Polluted Stop (§7.1)."""
    return AcceptResponse(seq=seq, record_hash=record_hash, host_ts=host_ts, previous_hash=previous_hash)
    # end def


def reject(reason: RejectReason) -> RejectResponse:
    """Build a reject response with a Tier-1 reject `reason` (ledger integrity not guaranteed, §7.1)."""
    return RejectResponse(reason=reason)
    # end def


def unavailable() -> UnavailableResponse:
    """Build a retryable unavailable response (a host-internal failure, §7.1; `reason` is internal-error)."""
    return UnavailableResponse()
    # end def


@runtime_checkable
class AuditTransport(Protocol):
    """The tool-side transport: negotiate once, then send attempts (blocking) and outcomes."""

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Present the tool's offered capability and learn the host requirement and fit (§6.1)."""
        ...

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Send `audit/attempt` and block for the host response (§6)."""
        ...

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Send `audit/outcome` (a notification, not a completeness gate, §6)."""
        ...

    # end class


@runtime_checkable
class AuditEndpoint(Protocol):
    """The host-side audit subsystem a transport delivers to."""

    @property
    def capability(self) -> AuditCapability:
        """The audit capability this host requires (§6.1)."""
        ...

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable (§7.1)."""
        ...

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Seal a correlated outcome, or flag it as an anomaly (§7.2)."""
        ...

    # end class
