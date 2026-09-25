"""Declaring and reading this extension in MCP capabilities (§6.1).

[SEP-2133] carries an extension's settings object in the `extensions` member of each party's
capabilities — `ClientCapabilities` for the host, `ServerCapabilities` for the tool — keyed by the
extension identifier. Where those capabilities travel is the binding's concern: `initialize` (§6.5),
or `server/discover` and each request's `_meta` (§6.4). These helpers put the audit capability there
and take a peer's back out. They work on any pydantic model or mapping rather than on the official
MCP types, so one pair of calls serves both sides and neither drags in the MCP package: `extensions`
is an open member and the capability models accept extras, so a declaration survives a peer whose
types predate [SEP-2133].

A declaration that does not validate is not a declaration: `capability_of` returns None for it, and
§6.2 then governs the call exactly as it governs a peer that declared nothing. An operator reading
the wire can tell the two apart; the protocol cannot and need not, because in both cases nothing was
agreed, so nothing may be sent.
"""

from collections.abc import Mapping, MutableMapping
from typing import Any

from pydantic import BaseModel, ValidationError

from auditable_mcp.models import EXTENSION_ID, AuditCapability

# The capabilities member [SEP-2133] reserves for extension settings objects (§6.1).
EXTENSIONS_MEMBER = 'extensions'


def audit_extension(capability: AuditCapability) -> dict[str, dict[str, object]]:
    """Return the `extensions` entry that declares this extension (§6.1).

    Args:
        capability: What this party declares — the audit capability a host requires or a tool offers.

    Returns:
        A single-entry mapping keyed by the extension identifier, ready to merge into `extensions`.
    """
    return {EXTENSION_ID: capability.to_wire()}
    # end def


def declare[CapabilitiesT: BaseModel](capabilities: CapabilitiesT, capability: AuditCapability) -> CapabilitiesT:
    """Return a copy of `capabilities` declaring this extension, keeping any others it declares (§6.1).

    Args:
        capabilities: The `ClientCapabilities` or `ServerCapabilities` this party is about to send.
        capability: The audit capability to declare.

    Returns:
        A copy carrying the merged `extensions` member. The original is left untouched.
    """
    extensions = {**_extensions(capabilities), **audit_extension(capability)}
    return capabilities.model_copy(update={EXTENSIONS_MEMBER: extensions})
    # end def


def declare_into(capabilities: MutableMapping[str, Any], capability: AuditCapability) -> None:
    """Declare this extension in a capabilities object already serialized for the wire (§6.1).

    The MCP session builds its own capabilities and offers no hook for an extension to add to them,
    so the binding merges the declaration in as they pass. Other extensions are kept.

    Args:
        capabilities: A capabilities object as it travels (§6.4, §6.5), mutated in place.
        capability: The audit capability this party declares.
    """
    extensions = {**_extensions(capabilities), **audit_extension(capability)}
    capabilities[EXTENSIONS_MEMBER] = extensions
    # end def


def capability_of(capabilities: object | None) -> AuditCapability | None:
    """Return the peer's declared audit capability, or None if it declared none this SDK can read (§6.1).

    Args:
        capabilities: The peer's capabilities, as a model or as the raw mapping from the wire.

    Returns:
        The declared capability, or None when the key is absent or its value does not validate.
    """
    declared: object | None = _extensions(capabilities).get(EXTENSION_ID)
    if declared is None:
        return None
        # end if
    if isinstance(declared, BaseModel):
        declared = declared.model_dump(mode='json')
        # end if
    try:
        return AuditCapability.model_validate(declared)
    except ValidationError:
        return None
        # end try
    # end def


def _extensions(capabilities: object | None) -> Mapping[str, Any]:
    """Return the `extensions` member of a capabilities model or mapping, empty when it has none."""
    if isinstance(capabilities, Mapping):
        member: object | None = capabilities.get(EXTENSIONS_MEMBER)
    else:
        member = getattr(capabilities, EXTENSIONS_MEMBER, None)
        # end if
    return member if isinstance(member, Mapping) else {}
    # end def
