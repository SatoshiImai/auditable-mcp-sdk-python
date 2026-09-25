"""AWS KMS signing/verification adapter (Level 2).

The tool's private key never leaves KMS: `AwsKmsSigner` calls `kms:Sign` to produce a detached
signature over the §8.2 payload, `ES256` for an `ECC_NIST_P256` key and `Ed25519` for an
`ECC_NIST_EDWARDS25519` one; `AwsKmsCountersigner` does the same for a host's countersignature.
`AwsKmsVerifier` fetches the public key once via `kms:GetPublicKey` and verifies locally —
public keys are public, so per-event KMS calls are unnecessary.

This module never imports `boto3`; it takes an injected, duck-typed client (the `KmsClient` protocol),
so importing it does not require the `auditable-mcp-sdk[aws]` extra and it is fully testable with a
fake client. The synchronous client is called through `asyncio.to_thread`, honouring the async
`EventSigner` / `SignatureVerifier` seams without blocking the event loop.
"""

import asyncio
import hashlib
from collections.abc import Mapping
from typing import Any, Final, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key

from auditable_mcp import fields
from auditable_mcp.encoding import b64url_encode
from auditable_mcp.l2.algorithms import KeyRole, PublicKey, SignatureAlgorithm
from auditable_mcp.l2.jwk import public_jwk
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import signature_payload
from auditable_mcp.l2.verification import KeyRegistryVerifier

# An ES256 wire signature is the fixed 64-byte r||s form (§5.1); each of r and s is a
# 32-byte big-endian integer.
_P256_COORD_LEN = 32

# KMS asymmetric signing algorithm for an ECC_NIST_P256 key; the digest is SHA-256.
DEFAULT_SIGNING_ALGORITHM = 'ECDSA_SHA_256'
# KMS request/response field values (AWS API surface, not the audit wire).
MESSAGE_TYPE_DIGEST = 'DIGEST'
# Ed25519 signs the message itself, not a digest of it: the scheme hashes internally, and a verifier
# built to §5.1 checks the signature against the canonical event, never against a hash of it.
MESSAGE_TYPE_RAW = 'RAW'
KMS_SIGNATURE = 'Signature'
KMS_PUBLIC_KEY = 'PublicKey'
KMS_KEY_SPEC = 'KeySpec'

# KMS key specs, and the signing algorithm each one takes for the two schemes §5.1 defines.
KEY_SPEC_P256 = 'ECC_NIST_P256'
KEY_SPEC_ED25519 = 'ECC_NIST_EDWARDS25519'
SIGNING_ALGORITHM_ED25519 = 'ED25519_SHA_512'

# `ED25519_PH_SHA_512` is Ed25519ph, which pre-hashes: its signatures do not verify under an ordinary
# Ed25519 verifier, so it is not a form this SDK can emit (§5.1).
_BY_KEY_SPEC: Final[dict[str, tuple[SignatureAlgorithm, str, str]]] = {
    KEY_SPEC_P256: (SignatureAlgorithm.ES256, DEFAULT_SIGNING_ALGORITHM, MESSAGE_TYPE_DIGEST),
    KEY_SPEC_ED25519: (SignatureAlgorithm.ED25519, SIGNING_ALGORITHM_ED25519, MESSAGE_TYPE_RAW),
}

# KMS signs at most this many bytes when the message is passed whole rather than as a digest. The
# limit is stated here so a payload over it is refused by name instead of arriving as a KMS error
# whose text says nothing about audit records.
MAX_RAW_MESSAGE_BYTES = 4096


class KmsClient(Protocol):
    """The subset of an AWS KMS client this adapter uses (boto3's `kms` client satisfies it)."""

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> Mapping[str, Any]:
        """Sign `Message` (a digest) and return a mapping with a `Signature` (DER bytes)."""
        ...

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]:
        """Return a mapping with a `PublicKey` (DER SubjectPublicKeyInfo bytes)."""
        ...

    # end class


def _require_bytes(response: Mapping[str, Any], field: str) -> bytes:
    """Extract a required bytes field from a KMS response, or raise."""
    value = response.get(field)
    if isinstance(value, bytes | bytearray):
        return bytes(value)
        # end if
    raise ValueError(f'KMS response is missing the bytes field {field!r}')
    # end def


async def load_kms_public_key(client: KmsClient, kms_key_id: str) -> PublicKey:
    """Fetch and parse a KMS key's public half (onboarding step).

    An `ECC_NIST_P256` key comes back as an `EllipticCurvePublicKey`, as it always has; an
    `ECC_NIST_EDWARDS25519` key as an `Ed25519PublicKey`. The key alone does not bind an algorithm to a
    `key_id` (§5.1): `kms_registry_entry` returns the registry entry with its algorithm, and is what a
    deployment provisions a peer from.

    Args:
        client: An injected KMS client.
        kms_key_id: The KMS key id/ARN to fetch.

    Returns:
        The public key.

    Raises:
        TypeError: The key is neither a P-256 nor an Ed25519 key, the two §5.1 defines.
    """
    response = await asyncio.to_thread(client.get_public_key, KeyId=kms_key_id)
    public_key = load_der_public_key(_require_bytes(response, KMS_PUBLIC_KEY))
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
        # end if
    if not isinstance(public_key, EllipticCurvePublicKey) or not isinstance(public_key.curve, SECP256R1):
        raise TypeError(f'KMS key {kms_key_id!r} is neither a P-256 elliptic-curve key nor an Ed25519 key (§5.1)')
        # end if
    return public_key
    # end def


async def kms_registry_entry(client: KmsClient, kms_key_id: str, *, key_id: str, role: KeyRole) -> dict[str, Any]:
    """Fetch a KMS key's public half and render the registry entry a peer is provisioned from.

    A key whose private half never leaves KMS is useless to a peer until its public half does. This
    is the door: it returns the same JWK the local key path produces, so a deployment hands over one
    form whether it signs locally or through KMS (§5.1).

    Args:
        client: An injected KMS client.
        kms_key_id: The KMS key id/ARN to fetch.
        key_id: The `key_id` events (or sealed records) will carry, which the entry binds.
        role: Whether this key signs as a tool or as a host (§10.9).

    Returns:
        The JWK, as `interop/key-exchange.json` pins the form.

    Raises:
        TypeError: The KMS key is not one of the algorithms §5.1 defines.
    """
    public_key, algorithm, _signing_algorithm, _message_type = await _kms_public_half(client, kms_key_id)
    return public_jwk(key_id, public_key, algorithm, role)
    # end def


async def _kms_public_half(client: KmsClient, kms_key_id: str) -> tuple[PublicKey, SignatureAlgorithm, str, str]:
    """Fetch a KMS key's public half and everything signing with it needs.

    The key spec comes from KMS rather than from configuration, so a key provisioned as one algorithm
    and configured as the other is refused here instead of failing per signature with a KMS error.

    Args:
        client: An injected KMS client.
        kms_key_id: The KMS key id/ARN.

    Returns:
        The public key, the §5.1 algorithm it is, the KMS signing algorithm, and the message type.

    Raises:
        TypeError: The key spec is not one this version defines (§12.1).
    """
    response = await asyncio.to_thread(client.get_public_key, KeyId=kms_key_id)
    key_spec = str(response.get(KMS_KEY_SPEC, ''))
    if key_spec not in _BY_KEY_SPEC:
        raise TypeError(f'KMS key {kms_key_id!r} is {key_spec or "of no stated spec"}, not an algorithm §5.1 defines')
        # end if
    algorithm, signing_algorithm, message_type = _BY_KEY_SPEC[key_spec]
    public_key = load_der_public_key(_require_bytes(response, KMS_PUBLIC_KEY))
    if not isinstance(public_key, EllipticCurvePublicKey | Ed25519PublicKey):
        raise TypeError(f'KMS key {kms_key_id!r} did not return a key of {key_spec}')
        # end if
    return public_key, algorithm, signing_algorithm, message_type
    # end def


class AwsKmsCountersigner:
    """A `Countersigner` that signs a sealed record's host-assigned fields through `kms:Sign` (§5.2).

    The countersign says who sealed a record, and it says it by a key the verifier's registry binds to a
    host. A key the signing process can read says only that something holding the key signed, which
    the process can also do after it is compromised and off the box. This adapter is what moves the
    private half out of reach; §10.2's limit - that a tool and a host in one party attest nothing
    against that party - is not touched by it.

    The algorithm comes from the key, not from configuration, so a key provisioned as one and
    configured as the other is refused at construction rather than per signature.
    """

    def __init__(
        self, client: KmsClient, kms_key_id: str, key_id: str, signing_algorithm: str, message_type: str
    ) -> None:
        """Bind the signer to a KMS key; prefer `from_kms`, which learns the algorithm from the key."""
        self._client = client
        self._kms_key_id = kms_key_id
        self._key_id = key_id
        self._signing_algorithm = signing_algorithm
        self._message_type = message_type
        # end def

    @classmethod
    async def from_kms(cls, client: KmsClient, kms_key_id: str, *, key_id: str | None = None) -> 'AwsKmsCountersigner':
        """Build a signer, reading the key's algorithm from KMS at onboarding.

        Args:
            client: An injected KMS client.
            kms_key_id: The KMS key id/ARN used to sign.
            key_id: The `host_key_id` sealed records will carry (defaults to `kms_key_id`).

        Returns:
            A signer bound to that key and the signing algorithm its spec takes.
        """
        _public_key, _algorithm, signing_algorithm, message_type = await _kms_public_half(client, kms_key_id)
        return cls(client, kms_key_id, key_id or kms_key_id, signing_algorithm, message_type)
        # end def

    @property
    def key_id(self) -> str:
        """The `host_key_id` a verifier's registry binds to this key."""
        return self._key_id
        # end def

    async def sign(self, payload: bytes) -> str:
        """Return the base64url detached signature over the already-canonical `payload`.

        Raises:
            ValueError: The payload is longer than KMS signs whole (Ed25519 only).
        """
        if self._message_type == MESSAGE_TYPE_RAW and len(payload) > MAX_RAW_MESSAGE_BYTES:
            raise ValueError(
                f'KMS signs at most {MAX_RAW_MESSAGE_BYTES} bytes whole; '
                f'this countersignature payload is {len(payload)}'
            )
            # end if
        message = hashlib.sha256(payload).digest() if self._message_type == MESSAGE_TYPE_DIGEST else payload
        response = await asyncio.to_thread(
            self._client.sign,
            KeyId=self._kms_key_id,
            Message=message,
            MessageType=self._message_type,
            SigningAlgorithm=self._signing_algorithm,
        )
        raw = _require_bytes(response, KMS_SIGNATURE)
        if self._message_type == MESSAGE_TYPE_DIGEST:
            # KMS returns an ASN.1/DER ECDSA signature; the wire form is the fixed 64-byte r||s (§5.1).
            r, s = decode_dss_signature(raw)
            raw = r.to_bytes(_P256_COORD_LEN, 'big') + s.to_bytes(_P256_COORD_LEN, 'big')
            # end if
        return b64url_encode(raw)
        # end def

    # end class


class AwsKmsSigner:
    """An `EventSigner` that signs via `kms:Sign`; the private key stays in KMS."""

    def __init__(
        self,
        client: KmsClient,
        kms_key_id: str,
        *,
        event_key_id: str | None = None,
        signing_algorithm: str = DEFAULT_SIGNING_ALGORITHM,
        message_type: str = MESSAGE_TYPE_DIGEST,
    ) -> None:
        """Bind the signer to a KMS key; prefer `from_kms`, which learns the algorithm from the key.

        Constructed directly, the signer signs ECDSA P-256 (`ECDSA_SHA_256` over a SHA-256 digest),
        which is what an `ECC_NIST_P256` key takes. An `ECC_NIST_EDWARDS25519` key takes
        `ED25519_SHA_512` over `RAW`, and KMS refuses every signature asked of it otherwise; `from_kms`
        reads the key spec and picks the pair, so it never has to be configured.

        Args:
            client: An injected KMS client.
            kms_key_id: The KMS key id/ARN used to sign.
            event_key_id: The `key_id` stamped into events for the host to resolve; defaults to
                `kms_key_id`.
            signing_algorithm: The KMS signing algorithm (default `ECDSA_SHA_256`).
            message_type: `DIGEST` for ECDSA, `RAW` for Ed25519, which hashes internally.
        """
        self._client = client
        self._kms_key_id = kms_key_id
        self._event_key_id = event_key_id if event_key_id is not None else kms_key_id
        self._signing_algorithm = signing_algorithm
        self._message_type = message_type
        # end def

    @classmethod
    async def from_kms(cls, client: KmsClient, kms_key_id: str, *, event_key_id: str | None = None) -> 'AwsKmsSigner':
        """Build a signer, reading the key's algorithm from KMS at onboarding.

        A key provisioned as one algorithm and configured as the other is refused here rather than
        failing per signature with a KMS error that says nothing about audit records.

        Args:
            client: An injected KMS client.
            kms_key_id: The KMS key id/ARN used to sign.
            event_key_id: The `key_id` stamped into events; defaults to `kms_key_id`.

        Returns:
            A signer bound to that key and the signing algorithm its spec takes.
        """
        _public_key, _algorithm, signing_algorithm, message_type = await _kms_public_half(client, kms_key_id)
        return cls(
            client,
            kms_key_id,
            event_key_id=event_key_id,
            signing_algorithm=signing_algorithm,
            message_type=message_type,
        )
        # end def

    @property
    def key_id(self) -> str:
        """The `key_id` this signer stamps, which names the sequence it advances (§7.4)."""
        return self._event_key_id
        # end def

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Stamp key_id and `signer_seq`, then sign the §8.2 payload via KMS.

        Raises:
            ValueError: The payload is longer than KMS signs whole (Ed25519 only).
        """
        signed = {**event, fields.KEY_ID: self._event_key_id, fields.SIGNER_SEQ: signer_seq}
        payload = signature_payload(signed)
        if self._message_type == MESSAGE_TYPE_RAW and len(payload) > MAX_RAW_MESSAGE_BYTES:
            # The event carries an address and a verdict, not a document, so this is a configuration
            # or a disclosure that grew - either way the refusal has to name the bound (§4.3).
            raise ValueError(
                f'KMS signs at most {MAX_RAW_MESSAGE_BYTES} bytes whole; this event canonicalizes to {len(payload)}'
            )
            # end if
        message = hashlib.sha256(payload).digest() if self._message_type == MESSAGE_TYPE_DIGEST else payload
        response = await asyncio.to_thread(
            self._client.sign,
            KeyId=self._kms_key_id,
            Message=message,
            MessageType=self._message_type,
            SigningAlgorithm=self._signing_algorithm,
        )
        raw = _require_bytes(response, KMS_SIGNATURE)
        if self._message_type == MESSAGE_TYPE_DIGEST:
            # KMS returns an ASN.1/DER signature; the wire form is the fixed 64-byte r||s (§5.1).
            r, s = decode_dss_signature(raw)
            raw = r.to_bytes(_P256_COORD_LEN, 'big') + s.to_bytes(_P256_COORD_LEN, 'big')
            # end if
        return {**signed, fields.SIGNATURE: b64url_encode(raw)}
        # end def

    # end class


class AwsKmsVerifier(KeyRegistryVerifier):
    """A `KeyRegistryVerifier` whose public keys are loaded from AWS KMS at onboarding.

    Verification (local, against the cached keys) is inherited; the KMS-specific part is only fetching
    the public keys via `kms:GetPublicKey` and binding each to the algorithm its key spec names:
    `ECC_NIST_P256` as `ES256`, `ECC_NIST_EDWARDS25519` as `Ed25519` (§5.1).
    """

    @classmethod
    async def from_kms(
        cls,
        client: KmsClient,
        key_map: Mapping[str, str],
        *,
        hash_algorithm: hashes.HashAlgorithm | None = None,
    ) -> 'AwsKmsVerifier':
        """Build a verifier by fetching each key's public half from KMS at onboarding.

        Args:
            client: An injected KMS client.
            key_map: Maps each event `key_id` to the KMS key id/ARN to fetch.
            hash_algorithm: The ECDSA hash (default SHA-256).

        Returns:
            A verifier holding the loaded public keys, each bound to the algorithm of its key spec.

        Raises:
            TypeError: A key's spec is not one this version defines (§12.1).
        """
        registry = KeyRegistry()
        for event_key_id, kms_key_id in key_map.items():
            public_key, algorithm, _signing_algorithm, _message_type = await _kms_public_half(client, kms_key_id)
            registry.register(event_key_id, public_key, algorithm)
            # end for
        return cls(registry, hash_algorithm=hash_algorithm)
        # end def

    # end class
