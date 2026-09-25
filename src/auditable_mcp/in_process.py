"""An in-process transport: the tool and host share a process, no wire.

This forwards `AuditTransport` calls straight to an `AuditEndpoint`. It is the transport used for
tests and for embedding the audit host in the same process as the tool. The host issues the audit
session (§6.3): open one with `async with host.session() as session_id:` for the span of the call, and
give the id to `AmcpSession`. A wire transport over MCP is wired against the same `AuditTransport` seam.
"""

from __future__ import annotations

from auditable_mcp.capability import NegotiationResult, negotiate
from auditable_mcp.models import AttemptResponse, AuditCapability
from auditable_mcp.transport import AuditEndpoint


class InProcessTransport:
    """Forwards audit messages directly to an in-process `AuditEndpoint` (implements `AuditTransport`)."""

    def __init__(self, endpoint: AuditEndpoint) -> None:
        """Bind the transport to the host endpoint it delivers to."""
        self._endpoint = endpoint
        # end def

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Compute the fit against the embedded endpoint's declaration; it is never undeclared (§6.1)."""
        return negotiate(self._endpoint.capability, offered)
        # end def

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Deliver an attempt to the endpoint and return its response."""
        return await self._endpoint.handle_attempt(event)
        # end def

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Deliver an outcome to the endpoint."""
        await self._endpoint.handle_outcome(event)
        # end def

    # end class
