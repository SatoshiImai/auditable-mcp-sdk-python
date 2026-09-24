"""Level 2: Ed25519 / ECDSA signing, verification, key material, and boundary reconciliation.

L1 and L2 share one event schema and one lifecycle; L2 only adds the signer (tool side) and the
signature verifier (host side), which the `AmcpSession` and `AuditHost` already accept via injection.
"""

from auditable_mcp.l2.keys import KeyRegistry, KeyRole, RegisteredKey, SignatureAlgorithm, ToolKey, generate_tool_key
from auditable_mcp.l2.reconcile import BoundaryObserver, EgressObservation, ReconcileAnomaly, reconcile
from auditable_mcp.l2.signing import Ed25519Signer, Ed25519WitnessSigner, sign_event, signature_payload
from auditable_mcp.l2.verification import (
    KeyRegistryVerifier,
    WitnessRegistryVerifier,
    verify_detached_signature,
    verify_ecdsa_signature,
    verify_ed25519_signature,
)

__all__ = [
    'BoundaryObserver',
    'Ed25519Signer',
    'Ed25519WitnessSigner',
    'EgressObservation',
    'KeyRegistry',
    'KeyRole',
    'KeyRegistryVerifier',
    'WitnessRegistryVerifier',
    'ReconcileAnomaly',
    'RegisteredKey',
    'SignatureAlgorithm',
    'ToolKey',
    'generate_tool_key',
    'reconcile',
    'sign_event',
    'signature_payload',
    'verify_detached_signature',
    'verify_ecdsa_signature',
    'verify_ed25519_signature',
]
