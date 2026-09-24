"""Level-2 verification (host side).

Two detached-signature primitives over canonical(event − signature) (§8.2): `verify_ed25519_signature`
and `verify_ecdsa_signature` (AWS KMS does not offer Ed25519, so ECDSA P-256/SHA-256 covers the
KMS/HSM case). `KeyRegistryVerifier` is the host `SignatureVerifier`: it resolves the `key_id` in a
`KeyRegistry`, dispatches to the algorithm bound to that key (§5.1), and returns a Tier-1 reject
reason (`unknown-key` / `signature-invalid`) or None. Verification is local — the public key is
public, onboarded once — so no per-event KMS call is needed. One verifier handles a heterogeneous
fleet.
"""

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from auditable_mcp import fields, reasons
from auditable_mcp.l2.keys import KeyRegistry, RegisteredKey, SignatureAlgorithm
from auditable_mcp.l2.signing import signature_payload
from auditable_mcp.models import RejectReason

# An ECDSA P-256 wire signature is the fixed 64-byte IEEE P1363 r||s form (§5.1).
_P256_RAW_SIGNATURE_LEN = 64


def _decode_b64(signature_b64: object) -> bytes | None:
    """Return the decoded standard-base64 signature, or None if absent or malformed."""
    if not isinstance(signature_b64, str):
        return None
        # end if
    try:
        return base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
        # end try
    # end def


def _decode_signature(event: dict[str, object]) -> bytes | None:
    """Return the event's decoded base64 signature, or None if absent or malformed."""
    return _decode_b64(event.get(fields.SIGNATURE))
    # end def


def verify_detached_signature(
    payload: bytes,
    signature_b64: object,
    entry: RegisteredKey,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> bool:
    """Return True if a detached base64 signature over already-canonical `payload` verifies.

    Unlike the event-level helpers above, the payload is supplied rather than derived, so this serves
    a signature whose preimage is not an event - the witness signature over the host-assigned fields
    (§7.1). The algorithm comes from the registry entry, as for events (§5.1).
    """
    signature = _decode_b64(signature_b64)
    if signature is None:
        return False
        # end if
    try:
        if entry.algorithm == SignatureAlgorithm.ED25519:
            assert isinstance(entry.public_key, Ed25519PublicKey)
            entry.public_key.verify(signature, payload)
        else:
            if len(signature) != _P256_RAW_SIGNATURE_LEN:
                return False
                # end if
            assert isinstance(entry.public_key, EllipticCurvePublicKey)
            half = _P256_RAW_SIGNATURE_LEN // 2
            der = encode_dss_signature(int.from_bytes(signature[:half], 'big'), int.from_bytes(signature[half:], 'big'))
            algorithm = hash_algorithm if hash_algorithm is not None else hashes.SHA256()
            entry.public_key.verify(der, payload, ec.ECDSA(algorithm))
            # end if
    except InvalidSignature:
        return False
        # end try
    return True
    # end def


def verify_ed25519_signature(event: dict[str, object], public_key: Ed25519PublicKey) -> bool:
    """Return True if the event's base64 Ed25519 signature verifies against `public_key`."""
    signature = _decode_signature(event)
    if signature is None:
        return False
        # end if
    try:
        public_key.verify(signature, signature_payload(event))
    except InvalidSignature:
        return False
        # end try
    return True
    # end def


def verify_ecdsa_signature(
    event: dict[str, object],
    public_key: EllipticCurvePublicKey,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> bool:
    """Return True if the event's base64 signature verifies as ECDSA P-256/SHA-256 against `public_key`.

    The wire signature is the fixed-length IEEE P1363 ``r || s`` form (§5.1), not DER; it is converted
    to DER for the backend. A wrong-length or undecodable value verifies False (mapped to
    `signature-invalid` by the caller). The default hash is SHA-256 (matching `ECDSA_SHA_256`).
    """
    signature = _decode_signature(event)
    if signature is None or len(signature) != _P256_RAW_SIGNATURE_LEN:
        return False
        # end if
    half = _P256_RAW_SIGNATURE_LEN // 2
    der = encode_dss_signature(int.from_bytes(signature[:half], 'big'), int.from_bytes(signature[half:], 'big'))
    algorithm = hash_algorithm if hash_algorithm is not None else hashes.SHA256()
    try:
        public_key.verify(der, signature_payload(event), ec.ECDSA(algorithm))
    except InvalidSignature:
        return False
        # end try
    return True
    # end def


class KeyRegistryVerifier:
    """A host `SignatureVerifier` backed by an algorithm-bound `KeyRegistry`.

    Per event it resolves `key_id` to its registry entry and dispatches to the bound algorithm's
    primitive, so Ed25519 and ECDSA P-256 tools verify through one instance (§5.1). Verification is
    local; the ECDSA hash defaults to SHA-256.
    """

    def __init__(self, registry: KeyRegistry, *, hash_algorithm: hashes.HashAlgorithm | None = None) -> None:
        """Bind the verifier to the registry of onboarded public keys and the ECDSA hash."""
        self._registry = registry
        self._hash_algorithm = hash_algorithm
        # end def

    async def verify(self, event: dict[str, object]) -> RejectReason | None:
        """Return `unknown-key` / `signature-invalid`, or None if the signature verifies (local)."""
        key_id = event.get(fields.KEY_ID)
        entry = self._registry.get(key_id) if isinstance(key_id, str) else None
        if entry is None:
            return reasons.UNKNOWN_KEY
            # end if
        if entry.algorithm == SignatureAlgorithm.ED25519:
            assert isinstance(entry.public_key, Ed25519PublicKey)
            verified = verify_ed25519_signature(event, entry.public_key)
        else:
            assert isinstance(entry.public_key, EllipticCurvePublicKey)
            verified = verify_ecdsa_signature(event, entry.public_key, self._hash_algorithm)
            # end if
        if not verified:
            return reasons.SIGNATURE_INVALID
            # end if
        return None
        # end def

    # end class


class WitnessRegistryVerifier:
    """A tool-side witness verifier backed by the out-of-band registry of host keys (§7.1, §10.9).

    The witness registry has the same shape and the same algorithm identifiers as the Level-2 one
    and never shares an entry with it. A `host_key_id` with no current entry - never registered, or
    revoked - does not establish the witness, which maps onto `host-signature-invalid` rather than
    earning a code of its own (§7.6, §10.9).
    """

    def __init__(self, registry: KeyRegistry, *, hash_algorithm: hashes.HashAlgorithm | None = None) -> None:
        """Bind the verifier to the registry of onboarded host public keys and the ECDSA hash."""
        self._registry = registry
        self._hash_algorithm = hash_algorithm
        # end def

    async def verify(self, host_key_id: str, signature: str, payload: bytes) -> bool:
        """Return True if the signature verifies against the registered host key (local, no I/O)."""
        entry = self._registry.get(host_key_id)
        if entry is None:
            return False
            # end if
        return verify_detached_signature(payload, signature, entry, self._hash_algorithm)
        # end def

    # end class
