"""Level 2: Ed25519 / ES256 signing, verification, key material, and boundary reconciliation.

L1 and L2 share one event schema and one lifecycle; L2 only adds the signer (tool side) and the
signature verifier (host side), which the `AmcpSession` and `AuditHost` already accept via injection.
"""

from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm
from auditable_mcp.l2.jwk import REVOKED_MEMBER, ROLE_MEMBER, jwk_thumbprint, public_jwk, public_key_of
from auditable_mcp.l2.keys import (
    KeyRegistry,
    RegisteredKey,
    ToolKey,
    assert_registries_disjoint,
    generate_tool_key,
    load_tool_key,
    tool_key_pkcs8,
)
from auditable_mcp.l2.reconcile import BoundaryObserver, EgressObservation, ReconcileAnomaly, reconcile
from auditable_mcp.l2.signing import Ed25519Countersigner, Ed25519Signer, sign_event, signature_payload
from auditable_mcp.l2.verification import (
    CountersignatureRegistryVerifier,
    KeyRegistryVerifier,
    verify_detached_signature,
    verify_ecdsa_signature,
    verify_ed25519_signature,
)

__all__ = [
    'BoundaryObserver',
    'Ed25519Signer',
    'REVOKED_MEMBER',
    'ROLE_MEMBER',
    'Ed25519Countersigner',
    'EgressObservation',
    'KeyRegistry',
    'KeyRole',
    'KeyRegistryVerifier',
    'CountersignatureRegistryVerifier',
    'ReconcileAnomaly',
    'RegisteredKey',
    'SignatureAlgorithm',
    'ToolKey',
    'assert_registries_disjoint',
    'generate_tool_key',
    'tool_key_pkcs8',
    'jwk_thumbprint',
    'load_tool_key',
    'public_jwk',
    'public_key_of',
    'reconcile',
    'sign_event',
    'signature_payload',
    'verify_detached_signature',
    'verify_ecdsa_signature',
    'verify_ed25519_signature',
]
