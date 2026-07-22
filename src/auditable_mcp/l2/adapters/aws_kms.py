"""AWS KMS signing/verification adapter (Level 2).

The tool's private key never leaves KMS: `AwsKmsSigner` calls `kms:Sign` to produce a detached
ECDSA signature over the §8.2 payload (AWS KMS does not offer Ed25519, so this is ECDSA P-256 by
default). `AwsKmsVerifier` fetches the public key once via `kms:GetPublicKey` and verifies locally —
public keys are public, so per-event KMS calls are unnecessary.

This module never imports `boto3`; it takes an injected, duck-typed client (the `KmsClient` protocol),
so importing it does not require the `auditable-mcp-sdk[aws]` extra and it is fully testable with a
fake client. The synchronous client is called through `asyncio.to_thread`, honouring the async
`EventSigner` / `SignatureVerifier` seams without blocking the event loop.
"""

import asyncio
import base64
import hashlib
from collections.abc import Mapping
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from auditable_mcp import fields
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import signature_payload
from auditable_mcp.l2.verification import EcdsaSignatureVerifier

# KMS asymmetric signing algorithm for an ECC_NIST_P256 key; the digest is SHA-256.
DEFAULT_SIGNING_ALGORITHM = 'ECDSA_SHA_256'
# KMS request/response field values (AWS API surface, not the audit wire).
MESSAGE_TYPE_DIGEST = 'DIGEST'
KMS_SIGNATURE = 'Signature'
KMS_PUBLIC_KEY = 'PublicKey'


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


async def load_kms_public_key(client: KmsClient, kms_key_id: str) -> EllipticCurvePublicKey:
    """Fetch and parse a KMS key's public half as an elliptic-curve public key (onboarding step)."""
    response = await asyncio.to_thread(client.get_public_key, KeyId=kms_key_id)
    public_key = load_der_public_key(_require_bytes(response, KMS_PUBLIC_KEY))
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise TypeError(f'KMS key {kms_key_id!r} is not an elliptic-curve key')
        # end if
    return public_key
    # end def


class AwsKmsSigner:
    """An `EventSigner` that signs via `kms:Sign`; the private key stays in KMS."""

    def __init__(
        self,
        client: KmsClient,
        kms_key_id: str,
        *,
        event_key_id: str | None = None,
        signing_algorithm: str = DEFAULT_SIGNING_ALGORITHM,
        start_sequence: int = 0,
    ) -> None:
        """Bind the signer to a KMS key.

        Args:
            client: An injected KMS client.
            kms_key_id: The KMS key id/ARN used to sign.
            event_key_id: The `key_id` stamped into events for the host to resolve; defaults to
                `kms_key_id`.
            signing_algorithm: The KMS signing algorithm (default `ECDSA_SHA_256`).
            start_sequence: The first per-key sequence value to emit.
        """
        self._client = client
        self._kms_key_id = kms_key_id
        self._event_key_id = event_key_id if event_key_id is not None else kms_key_id
        self._signing_algorithm = signing_algorithm
        self._next_sequence = start_sequence
        # end def

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Stamp key_id and the next sequence, then sign the §8.2 payload's digest via KMS."""
        sequence = self._next_sequence
        self._next_sequence += 1
        signed = {**event, fields.KEY_ID: self._event_key_id, fields.SEQUENCE: sequence}
        digest = hashlib.sha256(signature_payload(signed)).digest()
        response = await asyncio.to_thread(
            self._client.sign,
            KeyId=self._kms_key_id,
            Message=digest,
            MessageType=MESSAGE_TYPE_DIGEST,
            SigningAlgorithm=self._signing_algorithm,
        )
        signature = base64.b64encode(_require_bytes(response, KMS_SIGNATURE)).decode('ascii')
        return {**signed, fields.SIGNATURE: signature}
        # end def

    # end class


class AwsKmsVerifier(EcdsaSignatureVerifier):
    """An `EcdsaSignatureVerifier` whose EC public keys are loaded from AWS KMS at onboarding.

    Verification (local ECDSA against the cached keys) is inherited; the KMS-specific part is only
    fetching the public keys via `kms:GetPublicKey`.
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
            A verifier holding the loaded public keys.
        """
        registry: KeyRegistry[EllipticCurvePublicKey] = KeyRegistry()
        for event_key_id, kms_key_id in key_map.items():
            registry.register(event_key_id, await load_kms_public_key(client, kms_key_id))
            # end for
        return cls(registry, hash_algorithm=hash_algorithm)
        # end def

    # end class
