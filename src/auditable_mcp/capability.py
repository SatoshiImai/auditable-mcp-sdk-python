"""Audit capability negotiation (§6.1).

The capability object (`AuditCapability`, models.py) is exchanged bidirectionally during the MCP
`initialize` phase: the host declares the level it requires, the tool declares the level it
supports. Negotiation here is a local fit computation — a declaration's truthfulness is not verified
(the host enforces the required level at runtime, §7), so this only answers "does the offer meet the
requirement".
"""

from dataclasses import dataclass

from auditable_mcp.models import AuditCapability, Level

# L2 obligations are a superset of L1, so an L2 tool satisfies an L1 requirement (a safe downgrade),
# while an L1-only tool does not satisfy an L2 requirement.
_LEVEL_RANK = {Level.L1: 1, Level.L2: 2}


@dataclass(frozen=True)
class NegotiationResult:
    """The outcome of a capability exchange: the requirement, the offer, and the fit."""

    required: AuditCapability
    offered: AuditCapability
    satisfied: bool
    version_match: bool
    # end class


def capability_satisfies(offered: AuditCapability, required: AuditCapability) -> bool:
    """Return True if `offered` supports at least the `required` level.

    Args:
        offered: The capability the tool declares it supports.
        required: The capability the host requires.

    Returns:
        True if the offered level is at least the required level.
    """
    return _LEVEL_RANK.get(offered.level, 0) >= _LEVEL_RANK.get(required.level, 0)
    # end def


def negotiate(required: AuditCapability, offered: AuditCapability) -> NegotiationResult:
    """Compare a tool's offered capability against a host requirement (§6.1).

    A `0.x` draft has no on-the-wire compatibility window, so `satisfied` requires both a level fit
    and an exact `spec_version` match; `version_match` surfaces a version mismatch on its own.

    Args:
        required: The capability the host requires.
        offered: The capability the tool declares it supports.

    Returns:
        A result carrying both capabilities, whether the offer satisfies the requirement, and the
        version match.
    """
    version_match = offered.spec_version == required.spec_version
    satisfied = capability_satisfies(offered, required) and version_match
    return NegotiationResult(required=required, offered=offered, satisfied=satisfied, version_match=version_match)
    # end def
