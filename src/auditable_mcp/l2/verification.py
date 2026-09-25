"""Level-2 verification (host side).

Two detached-signature primitives over canonical(event − signature) (§8.2): `verify_ed25519_signature`
and `verify_ecdsa_signature` (`ES256`, which every HSM and KMS offers). `KeyRegistryVerifier` is the
host `SignatureVerifier`: it resolves the `key_id` in a `KeyRegistry`, dispatches to the algorithm
bound to that key (§5.1), and returns a Tier-1 reject reason (`unknown-key` / `signature-invalid`) or
None. Verification is local — the public key is
public, onboarded once — so no per-event KMS call is needed. One verifier handles a heterogeneous
fleet.
"""

from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from auditable_mcp import fields, reasons
from auditable_mcp.encoding import b64_standard_decode, b64url_decode
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm
from auditable_mcp.l2.keys import KeyRegistry, RegisteredKey
from auditable_mcp.l2.signing import signature_payload
from auditable_mcp.models import KNOWN_SPEC_VERSIONS, SPEC_VERSION, RejectReason

# An ES256 wire signature is the fixed 64-byte r||s form (§5.1).
_P256_RAW_SIGNATURE_LEN = 64


def _decode_signature(event: dict[str, object]) -> bytes | None:
    """Return the event's decoded signature, or None if absent or malformed.

    A current event carries base64url without padding (§5.1). A record sealed under an earlier published
    version is decoded as that version encoded it, standard base64 with padding (§11.4).
    """
    version = event.get(fields.SPEC_VERSION)
    if version != SPEC_VERSION and version in KNOWN_SPEC_VERSIONS:
        return b64_standard_decode(event.get(fields.SIGNATURE))
        # end if
    return b64url_decode(event.get(fields.SIGNATURE))
    # end def


def verify_detached_signature(
    payload: bytes,
    encoded_signature: object,
    entry: RegisteredKey,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> bool:
    """Return True if a detached base64url signature over already-canonical `payload` verifies.

    Unlike the event-level helpers above, the payload is supplied rather than derived, so this serves
    a signature whose preimage is not an event - the countersignature over the host-assigned fields
    (§7.1). The algorithm comes from the registry entry, as for events (§5.1).
    """
    signature = b64url_decode(encoded_signature)
    if signature is None:
        return False
        # end if
    try:
        if entry.algorithm == SignatureAlgorithm.ED25519:
            if not isinstance(entry.public_key, Ed25519PublicKey):
                return False
                # end if
            entry.public_key.verify(signature, payload)
        else:
            if len(signature) != _P256_RAW_SIGNATURE_LEN or not isinstance(entry.public_key, EllipticCurvePublicKey):
                return False
                # end if
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
    """Return True if the event's base64url Ed25519 signature verifies against `public_key`."""
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
    """Return True if the event's base64url signature verifies as ES256 against `public_key`.

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
        """Bind the verifier to the registry of onboarded tool public keys and the ECDSA hash.

        Raises:
            ValueError: If `registry` holds host keys (§10.9).
        """
        if registry.role is not KeyRole.TOOL:
            raise ValueError('a Level-2 verifier needs a tool-key registry (§10.9)')
            # end if
        self._registry = registry
        self._hash_algorithm = hash_algorithm
        # end def

    def check(self, event: Mapping[str, object]) -> bool:
        """Return True if the event's own Level-2 signature verifies (synchronous, §7.4).

        Offline ledger verification (§11.4) is synchronous and reads stored records, so it uses this. A
        revoked key still verifies here: the records it signed while valid remain evidence (§10.9).
        `verify` is the async host-side form that reports which Tier-1 reason applies.
        """
        return self._reject_reason(dict(event), sealed=True) is None
        # end def

    async def verify(self, event: dict[str, object]) -> RejectReason | None:
        """Return `unknown-key` / `signature-invalid`, or None if the signature verifies (local).

        A host verifies a new event, so a revoked key is `unknown-key` here (§10.9).
        """
        return self._reject_reason(event, sealed=False)
        # end def

    def _reject_reason(self, event: dict[str, object], *, sealed: bool) -> RejectReason | None:
        """Resolve the key and dispatch to the bound algorithm (§5.1); None if it verifies."""
        key_id = event.get(fields.KEY_ID)
        if not isinstance(key_id, str):
            return reasons.UNKNOWN_KEY
            # end if
        entry = self._registry.get(key_id) if sealed else self._registry.current(key_id)
        if entry is None:
            return reasons.UNKNOWN_KEY
            # end if
        if entry.algorithm == SignatureAlgorithm.ED25519 and isinstance(entry.public_key, Ed25519PublicKey):
            verified = verify_ed25519_signature(event, entry.public_key)
        elif entry.algorithm == SignatureAlgorithm.ES256 and isinstance(entry.public_key, EllipticCurvePublicKey):
            verified = verify_ecdsa_signature(event, entry.public_key, self._hash_algorithm)
        else:
            verified = False
            # end if
        if not verified:
            return reasons.SIGNATURE_INVALID
            # end if
        return None
        # end def

    # end class


class CountersignatureRegistryVerifier:
    """A tool-side countersign verifier backed by the out-of-band registry of host keys (§7.1, §10.9).

    The countersign registry has the same shape and the same algorithm identifiers as the Level-2 one
    and never shares a key with it. A tool verifying a new accept refuses a `host_key_id` with no current
    entry - never registered, or revoked - which maps onto `host-signature-invalid` rather than earning a
    code of its own (§7.2, §7.6, §10.9). A verifier reading a sealed record checks it against a revoked
    entry as before, since the record was countersigned while the key was valid.
    """

    def __init__(self, registry: KeyRegistry, *, hash_algorithm: hashes.HashAlgorithm | None = None) -> None:
        """Bind the verifier to the registry of onboarded host public keys and the ECDSA hash.

        Raises:
            ValueError: If `registry` holds tool keys. A tool that can be found in the registry a
                verifier resolves `host_key_id` against can sign a countersignature payload with its own key and
                manufacture the host-countersigned state §5.2 says it cannot (§10.9).
        """
        if registry.role is not KeyRole.HOST:
            raise ValueError('a countersignature verifier needs a host-key registry (§10.9)')
            # end if
        self._registry = registry
        self._hash_algorithm = hash_algorithm
        # end def

    def check(self, host_key_id: str, signature: str, payload: bytes) -> bool:
        """Return True if a sealed record's countersignature verifies against the host key (synchronous).

        Offline ledger verification (§11.4) is synchronous and reads stored records, so it uses this
        directly. A revoked entry still verifies here (§10.9).
        """
        entry = self._registry.get(host_key_id)
        if entry is None:
            return False
            # end if
        return verify_detached_signature(payload, signature, entry, self._hash_algorithm)
        # end def

    async def verify(self, host_key_id: str, signature: str, payload: bytes) -> bool:
        """Return True if a new accept's countersignature verifies against a current host key (§7.2).

        A revoked key confirms nothing new, so an accept countersigned under one does not verify (§10.9).
        """
        entry = self._registry.current(host_key_id)
        if entry is None:
            return False
            # end if
        return verify_detached_signature(payload, signature, entry, self._hash_algorithm)
        # end def

    # end class
