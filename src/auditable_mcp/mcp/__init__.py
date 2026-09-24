"""The MCP binding: this extension's two methods on a real MCP connection (§6).

Importing this subpackage requires the official `mcp` package, which the core does not: install
`auditable-mcp-sdk[mcp]`. Everything else in this SDK works over the abstract `AuditTransport` seam
and carries no transport dependency at all.
"""

from auditable_mcp.mcp.declaration import EXTENSIONS_MEMBER, audit_extension, capability_of, declare, declare_into
from auditable_mcp.mcp.seam import (
    ATTEMPT_METHOD,
    DEFAULT_REQUEST_TIMEOUT,
    ID_PREFIX,
    INITIALIZE_METHOD,
    OUTCOME_METHOD,
    HandshakeNotSeenError,
    McpAuditReceiver,
    McpAuditTransport,
    McpBindingError,
    UnnegotiatedSendError,
)

__all__ = [
    'ATTEMPT_METHOD',
    'audit_extension',
    'capability_of',
    'declare',
    'declare_into',
    'DEFAULT_REQUEST_TIMEOUT',
    'EXTENSIONS_MEMBER',
    'HandshakeNotSeenError',
    'ID_PREFIX',
    'INITIALIZE_METHOD',
    'McpAuditReceiver',
    'McpAuditTransport',
    'McpBindingError',
    'OUTCOME_METHOD',
    'UnnegotiatedSendError',
]
