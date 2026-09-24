"""Auditable MCP SDK — a protocol machine for tool self-attestation into a tamper-evident ledger.

This package is a pure protocol machine (canonicalization, hashing, signing, state transitions).
It carries no storage backend and no tool business logic; persistence is the integrator's concern,
supplied through the adapter interfaces this SDK defines.

The `spec_version` implemented is `auditable-mcp/0.2`.
"""

from auditable_mcp.canonical import (
    CONTEXT_HASH_PREFIX,
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonicalize,
    has_unsafe_number,
    hash_canonical,
    sha256_hex,
)
from auditable_mcp.capability import (
    NegotiationOutcome,
    NegotiationResult,
    level_satisfies,
    negotiate,
    witness_satisfies,
)
from auditable_mcp.clock import Clock, SystemClock, now_iso
from auditable_mcp.decorator import auditable_tool, bound_session, current_session
from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash
from auditable_mcp.host import AuditHost, IntegrityAnomaly, SignatureVerifier
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    BoundaryObserver,
    Ed25519Signer,
    EgressObservation,
    KeyRegistry,
    KeyRegistryVerifier,
    ReconcileAnomaly,
    RegisteredKey,
    SignatureAlgorithm,
    ToolKey,
    generate_tool_key,
    reconcile,
    sign_event,
    verify_ecdsa_signature,
    verify_ed25519_signature,
)
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import (
    SPEC_VERSION,
    AbortReason,
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    AuditCapabilityInput,
    AuditEvent,
    Level,
    Outcome,
    RejectReason,
    RejectResponse,
    Status,
    TargetResource,
    UnavailableResponse,
    WireModel,
    first_validation_error,
)
from auditable_mcp.session import (
    AmcpAbortedError,
    AmcpSession,
    AuditedAction,
    Deps,
    EventSigner,
    SystemDeps,
)
from auditable_mcp.storage import InMemoryLedgerRepository, LedgerRepository, RepositoryError
from auditable_mcp.transport import (
    AuditEndpoint,
    AuditTransport,
    accept,
    reject,
    unavailable,
)
from auditable_mcp.verify import (
    DEFAULT_ADAPTER,
    RecordAdapter,
    VerifyIssue,
    VerifyReport,
    verify_chain,
    verify_ledger,
)

__version__ = '0.2.1'

__all__ = [
    'CONTEXT_HASH_PREFIX',
    'GENESIS_HASH',
    'MAX_SAFE_INTEGER',
    'SPEC_VERSION',
    'AbortReason',
    'AcceptResponse',
    'AmcpAbortedError',
    'AmcpSession',
    'AttemptResponse',
    'AuditCapability',
    'AuditCapabilityInput',
    'AuditEndpoint',
    'AuditEvent',
    'AuditHost',
    'AuditTransport',
    'AuditedAction',
    'BoundaryObserver',
    'CanonicalizationError',
    'Clock',
    'Deps',
    'Ed25519Signer',
    'EgressObservation',
    'EventSigner',
    'InMemoryLedgerRepository',
    'InProcessTransport',
    'IntegrityAnomaly',
    'KeyRegistry',
    'KeyRegistryVerifier',
    'Ledger',
    'LedgerRepository',
    'Level',
    'NegotiationOutcome',
    'NegotiationResult',
    'Outcome',
    'ReconcileAnomaly',
    'RegisteredKey',
    'RejectReason',
    'RejectResponse',
    'RepositoryError',
    'SealedRecord',
    'SignatureAlgorithm',
    'SignatureVerifier',
    'Status',
    'SystemClock',
    'SystemDeps',
    'TargetResource',
    'ToolKey',
    'UnavailableResponse',
    'VerifyIssue',
    'VerifyReport',
    'RecordAdapter',
    'DEFAULT_ADAPTER',
    'WireModel',
    'accept',
    'auditable_tool',
    'bound_session',
    'canonicalize',
    'level_satisfies',
    'witness_satisfies',
    'compute_record_hash',
    'current_session',
    'first_validation_error',
    'generate_tool_key',
    'hash_canonical',
    'has_unsafe_number',
    'negotiate',
    'now_iso',
    'reconcile',
    'reject',
    'sha256_hex',
    'sign_event',
    'unavailable',
    'verify_ecdsa_signature',
    'verify_ed25519_signature',
    'verify_chain',
    'verify_ledger',
    '__version__',
]
