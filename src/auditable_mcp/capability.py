"""Audit capability negotiation (§6.1, §6.2).

Both parties declare the capability object under the `extensions` member of their MCP capabilities,
keyed by the extension identifier. Negotiation is a local fit computation — a declaration's
truthfulness is not verified — so this module only answers whether the two declarations fit, and on
which axis they do not.

The two axes run in opposite directions. On `level` the tool produces and the host requires, so a
tool offering L2 satisfies an L1 host. On `countersign` the host produces and the tool requires, so a
host offering `host` satisfies a tool that requires `none`. Each party enforces the axis on which it
is the one requiring.

A host that declared nothing is not a failed negotiation but an absent one, which §6.2 governs
differently: the tool must send no audit message at all and serve the call as an ordinary MCP tool.
`NegotiationOutcome` keeps the two apart, because a caller that collapsed them would either brick
the tool against ordinary hosts or paper over a real mismatch.
"""

from dataclasses import dataclass
from enum import StrEnum

from auditable_mcp.models import AuditCapability, Countersign, Level

# L2 obligations are a superset of L1, so an L2 tool satisfies an L1 requirement (a safe downgrade),
# while an L1-only tool does not satisfy an L2 requirement.
_LEVEL_RANK = {Level.L1: 1, Level.L2: 2}

# A host that signs satisfies a tool that requires a signature and one that does not; a host that
# does not sign satisfies only the latter.
_COUNTERSIGN_RANK = {Countersign.NONE: 1, Countersign.HOST: 2}


class NegotiationOutcome(StrEnum):
    """Why a call is or is not audit-negotiated (§6.2)."""

    NEGOTIATED = 'negotiated'
    # The peer declared no auditable-mcp capability. Not a mismatch: nothing was offered to compare.
    UNDECLARED = 'undeclared'
    MISMATCH = 'mismatch'
    # The declarations fit, and the host issued no audit session for this call: it did not ask to
    # audit it (§6.3). Like UNDECLARED, nothing is wrong with either party.
    NO_SESSION = 'no-session'
    # end class


@dataclass(frozen=True)
class NegotiationResult:
    """The outcome of a capability exchange, and which axis decided it."""

    tool: AuditCapability
    host: AuditCapability | None
    outcome: NegotiationOutcome
    version_match: bool
    level_fit: bool
    countersign_fit: bool

    @property
    def negotiated(self) -> bool:
        """True only for an audit-negotiated call; §6.2 governs every other case."""
        return self.outcome is NegotiationOutcome.NEGOTIATED
        # end def

    # end class


def level_satisfies(tool: AuditCapability, host: AuditCapability) -> bool:
    """Return True if the tool offers at least the level the host requires (§6.1)."""
    return _LEVEL_RANK.get(tool.level, 0) >= _LEVEL_RANK.get(host.level, 0)
    # end def


def countersign_satisfies(host: AuditCapability, tool: AuditCapability) -> bool:
    """Return True if the host provides at least the countersignature the tool requires (§5.2, §6.1)."""
    return _COUNTERSIGN_RANK.get(host.countersign, 0) >= _COUNTERSIGN_RANK.get(tool.countersign, 0)
    # end def


def negotiate(host: AuditCapability | None, tool: AuditCapability) -> NegotiationResult:
    """Compare a host and a tool declaration (§6.1).

    A `0.x` draft has no on-the-wire compatibility window, so a fit requires an exact `spec_version`
    match as well as both axes; the per-axis flags surface which one failed.

    Args:
        host: The capability the host declared, or None if it declared no auditable-mcp extension.
        tool: The capability the tool declares.

    Returns:
        A result carrying both declarations, the outcome, and the per-axis fit.
    """
    if host is None:
        return NegotiationResult(
            tool=tool,
            host=None,
            outcome=NegotiationOutcome.UNDECLARED,
            version_match=False,
            level_fit=False,
            countersign_fit=False,
        )
        # end if
    version_match = tool.spec_version == host.spec_version
    level_fit = level_satisfies(tool, host)
    countersign_fit = countersign_satisfies(host, tool)
    fits = version_match and level_fit and countersign_fit
    return NegotiationResult(
        tool=tool,
        host=host,
        outcome=NegotiationOutcome.NEGOTIATED if fits else NegotiationOutcome.MISMATCH,
        version_match=version_match,
        level_fit=level_fit,
        countersign_fit=countersign_fit,
    )
    # end def
