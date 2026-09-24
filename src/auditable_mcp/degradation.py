"""What a tool does with a session that was not audit-negotiated (§6.2).

A tool that speaks this extension has to stay usable by hosts that do not, which is nearly every MCP
host today. In an unnegotiated session it sends no audit message at all - a host that did not declare
the extension answers an undeclared method with a JSON-RPC error, which §6 requires the tool to read
as a failure to record, so a tool that sends anyway fails closed against a peer that has done nothing
wrong - and serves `tools/call` exactly as a build without this extension would.

Two postures are admissible. Under **degraded** (the default) the tool serves the call and records
into an audit host it provides for itself: the recording does not stop, the host's witness does, and
§5.2 makes that legible in the records. Under **mandatory** the tool declines to serve, which
[SEP-2133] permits for an extension a deployment treats as required.

A third posture - serving the call while recording nothing and reporting nothing about the omission -
is not conformant, so `transport_for` refuses to return a transport for it: taking the degraded
posture requires somewhere to record.
"""

from enum import StrEnum

from auditable_mcp.capability import NegotiationResult
from auditable_mcp.models import Witness
from auditable_mcp.transport import AuditTransport


class Posture(StrEnum):
    """How a tool spends an audit obligation it cannot discharge against the host (§6.2)."""

    # Serve the call, and record into an audit host the tool provides for itself.
    DEGRADED = 'degraded'
    # Decline to serve, as [SEP-2133] permits for a mandatory extension.
    MANDATORY = 'mandatory'
    # end class


class UnnegotiatedSessionError(Exception):
    """The session was not audit-negotiated and the tool's posture is `mandatory` (§6.2)."""

    def __init__(self, negotiation: NegotiationResult) -> None:
        """Carry the negotiation so the integrator can report which axis refused."""
        self.negotiation = negotiation
        super().__init__(f'session is not audit-negotiated ({negotiation.outcome}); posture is mandatory')
        # end def

    # end class


def transport_for(
    negotiation: NegotiationResult,
    *,
    negotiated: AuditTransport,
    fallback: AuditTransport | None = None,
    posture: Posture = Posture.DEGRADED,
) -> AuditTransport:
    """Return the transport §6.2 permits for this session, or refuse to serve it.

    Args:
        negotiation: The result of comparing the host's declaration against the tool's (§6.1).
        negotiated: The transport to the host, used only when the session is audit-negotiated.
        fallback: A transport over an audit host the tool provides for itself, required by the
            degraded posture. An `InProcessTransport` over a tool-local `AuditHost` is the usual one.
        posture: What to do when the session is not audit-negotiated. Degraded by default.

    Returns:
        `negotiated` for an audit-negotiated session, otherwise `fallback`.

    Raises:
        UnnegotiatedSessionError: The session is not audit-negotiated and the posture is mandatory.
        ValueError: The posture is degraded and no `fallback` was given. Serving a call while
            neither recording the operations nor reporting the omission is not conformant (§6.2),
            so the degraded posture is not available without somewhere to record.
    """
    if negotiation.negotiated:
        return negotiated
        # end if
    if posture is Posture.MANDATORY:
        raise UnnegotiatedSessionError(negotiation)
        # end if
    # A tool that requires a witness cannot take the degraded posture: the audit host it provides for
    # itself holds no key a verifier's registry binds to a host (§5.2), so every action would abort
    # `host-unwitnessed` (§7.2) and the tool would serve while doing nothing. The coherent posture for
    # a tool with that requirement is mandatory, and saying so beats an unusable degraded session.
    if negotiation.tool.witness == Witness.HOST:
        raise ValueError('a tool that requires witness "host" cannot degrade; use Posture.MANDATORY (§5.2, §6.2)')
        # end if
    if fallback is None:
        raise ValueError('the degraded posture needs a fallback transport to record into (§6.2)')
        # end if
    return fallback
    # end def
