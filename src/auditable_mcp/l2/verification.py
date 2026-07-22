"""Level-2 verification (host side).

Two detached-signature primitives over canonical(event − signature) (§8.2): `verify_ed25519_signature`
and `verify_ecdsa_signature` (AWS KMS does not offer Ed25519, so ECDSA covers the KMS/HSM case).
`Ed25519SignatureVerifier` and `EcdsaSignatureVerifier` are the symmetric host `SignatureVerifier`
implementations: each resolves the `key_id` in a `KeyRegistry` and returns a reject reason
(`unknown-key` / `signature-invalid`) or None. Verification is local — the public key is public,
onboarded once — so no per-event KMS call is needed.
"""

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auditable_mcp import fields, reasons
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import signature_payload


def _decode_signature(event: dict[str, object]) -> bytes | None:
    """Return the event's decoded base64 signature, or None if absent or malformed."""
    signature_b64 = event.get(fields.SIGNATURE)
    if not isinstance(signature_b64, str):
        return None
        # end if
    try:
        return base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
        # end try
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
    """Return True if the event's base64 DER-ECDSA signature verifies against `public_key`.

    The default hash is SHA-256 (matching `ECDSA_SHA_256`).
    """
    signature = _decode_signature(event)
    if signature is None:
        return False
        # end if
    algorithm = hash_algorithm if hash_algorithm is not None else hashes.SHA256()
    try:
        public_key.verify(signature, signature_payload(event), ec.ECDSA(algorithm))
    except InvalidSignature:
        return False
        # end try
    return True
    # end def


class Ed25519SignatureVerifier:
    """A host `SignatureVerifier` backed by an Ed25519 public-key registry."""

    def __init__(self, registry: KeyRegistry[Ed25519PublicKey]) -> None:
        """Bind the verifier to the registry of onboarded Ed25519 public keys."""
        self._registry = registry
        # end def

    async def verify(self, event: dict[str, object]) -> str | None:
        """Return `unknown-key` / `signature-invalid`, or None if the Ed25519 signature verifies (local)."""
        key_id = event.get(fields.KEY_ID)
        public_key = self._registry.get(key_id) if isinstance(key_id, str) else None
        if public_key is None:
            return reasons.UNKNOWN_KEY
            # end if
        if not verify_ed25519_signature(event, public_key):
            return reasons.SIGNATURE_INVALID
            # end if
        return None
        # end def

    # end class


class EcdsaSignatureVerifier:
    """A host `SignatureVerifier` backed by an elliptic-curve public-key registry (ECDSA).

    The symmetric counterpart to `Ed25519SignatureVerifier` for keys held in a KMS/HSM or elsewhere;
    populate its registry with EC public keys (e.g. loaded from KMS, see `l2.adapters.aws_kms`).
    """

    def __init__(
        self,
        registry: KeyRegistry[EllipticCurvePublicKey],
        *,
        hash_algorithm: hashes.HashAlgorithm | None = None,
    ) -> None:
        """Bind the verifier to the registry of onboarded EC public keys and the ECDSA hash."""
        self._registry = registry
        self._hash_algorithm = hash_algorithm
        # end def

    async def verify(self, event: dict[str, object]) -> str | None:
        """Return `unknown-key` / `signature-invalid`, or None if the ECDSA signature verifies (local)."""
        key_id = event.get(fields.KEY_ID)
        public_key = self._registry.get(key_id) if isinstance(key_id, str) else None
        if public_key is None:
            return reasons.UNKNOWN_KEY
            # end if
        if not verify_ecdsa_signature(event, public_key, self._hash_algorithm):
            return reasons.SIGNATURE_INVALID
            # end if
        return None
        # end def

    # end class
