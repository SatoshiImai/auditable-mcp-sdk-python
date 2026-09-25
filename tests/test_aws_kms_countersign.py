"""M4: signing through KMS, for a countersignature and for a tool, on both algorithms §5.1 defines.

No AWS: the client is a fake that holds a real private key and answers the way KMS does, so the
signatures are genuine and the SDK's own verifiers check them.
"""

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditable_mcp.hashing import countersignature_payload
from auditable_mcp.l2 import CountersignatureRegistryVerifier, KeyRegistry, KeyRole, SignatureAlgorithm, public_key_of
from auditable_mcp.l2.adapters.aws_kms import (
    KEY_SPEC_ED25519,
    KEY_SPEC_P256,
    MAX_RAW_MESSAGE_BYTES,
    MESSAGE_TYPE_DIGEST,
    MESSAGE_TYPE_RAW,
    SIGNING_ALGORITHM_ED25519,
    AwsKmsCountersigner,
    AwsKmsSigner,
    kms_registry_entry,
)
from auditable_mcp.l2.verification import verify_detached_signature

LOG_ID = 'tenant-a'


class _FakeKms:
    """A KMS that really signs, so the SDK's verifiers check real signatures (no AWS, no network)."""

    def __init__(self, key_spec: str) -> None:
        """Hold a private key of `key_spec` and answer as KMS does for it."""
        self.key_spec = key_spec
        self.seen: list[dict[str, Any]] = []
        self._private = (
            Ed25519PrivateKey.generate() if key_spec == KEY_SPEC_ED25519 else ec.generate_private_key(ec.SECP256R1())
        )
        # end def

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:  # noqa: N803 - the KMS wire name
        """Return the SubjectPublicKeyInfo DER and the key spec, as `kms:GetPublicKey` does."""
        return {
            'KeySpec': self.key_spec,
            'PublicKey': self._private.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }
        # end def

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:  # noqa: N803
        """Sign as KMS does: DER for ECDSA over a digest, raw 64 bytes for Ed25519 over the message."""
        self.seen.append({'MessageType': MessageType, 'SigningAlgorithm': SigningAlgorithm, 'length': len(Message)})
        if isinstance(self._private, Ed25519PrivateKey):
            return {'Signature': self._private.sign(Message)}
            # end if
        return {'Signature': self._private.sign(Message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))}
        # end def

    # end class


def _payload() -> bytes:
    """The canonical host-assigned fields a countersignature signs (§7.1)."""
    return countersignature_payload(3, '2026-07-15T00:00:01.000Z', LOG_ID, '0' * 64, 'a' * 64)
    # end def


class TestTheCountersignSignsThroughKms:
    """§5.2: the countersign is worth something only while the private half is out of the signer's reach."""

    @pytest.mark.parametrize('key_spec', [KEY_SPEC_P256, KEY_SPEC_ED25519])
    async def test_a_signature_verifies_against_the_key_kms_published(self, key_spec: str) -> None:
        """The whole loop: KMS signs, its public half provisions a registry, the verifier agrees."""
        client = _FakeKms(key_spec)
        signer = await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host', key_id='odin-host-1')
        payload = _payload()
        signature = await signer.sign(payload)

        registry = KeyRegistry(KeyRole.HOST)
        entry_jwk = await kms_registry_entry(client, 'arn:aws:kms:host', key_id='odin-host-1', role=KeyRole.HOST)
        registry.load_jwks({'keys': [entry_jwk]})
        entry = registry.get('odin-host-1')
        assert entry is not None
        assert verify_detached_signature(payload, signature, entry)
        # end def

    @pytest.mark.parametrize(
        'key_spec,message_type', [(KEY_SPEC_P256, MESSAGE_TYPE_DIGEST), (KEY_SPEC_ED25519, MESSAGE_TYPE_RAW)]
    )
    async def test_the_message_reaches_kms_in_the_form_the_algorithm_takes(
        self, key_spec: str, message_type: str
    ) -> None:
        """ECDSA signs a digest; Ed25519 hashes internally and must see the message itself (§5.1)."""
        client = _FakeKms(key_spec)
        signer = await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host')
        await signer.sign(_payload())
        assert client.seen[0]['MessageType'] == message_type
        # end def

    async def test_the_ed25519_signing_algorithm_is_the_plain_one(self) -> None:
        """`ED25519_PH_SHA_512` pre-hashes, and its signatures do not verify under a plain verifier."""
        client = _FakeKms(KEY_SPEC_ED25519)
        signer = await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host')
        await signer.sign(_payload())
        assert client.seen[0]['SigningAlgorithm'] == SIGNING_ALGORITHM_ED25519
        # end def

    async def test_a_key_spec_this_version_does_not_define_is_refused_at_onboarding(self) -> None:
        """An RSA key signs happily and produces something no §5.1 verifier can check."""
        client = _FakeKms(KEY_SPEC_P256)
        client.key_spec = 'RSA_2048'
        with pytest.raises(TypeError, match='§5.1'):
            await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host')
            # end with
        # end def

    async def test_a_payload_over_what_kms_signs_whole_is_refused_by_name(self) -> None:
        """The refusal has to name the bound, or it arrives as a KMS error about nothing audit-shaped."""
        client = _FakeKms(KEY_SPEC_ED25519)
        signer = await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host')
        with pytest.raises(ValueError, match=str(MAX_RAW_MESSAGE_BYTES)):
            await signer.sign(b'x' * (MAX_RAW_MESSAGE_BYTES + 1))
            # end with
        # end def

    async def test_the_countersignature_verifier_accepts_what_kms_signed(self) -> None:
        """The tool's side of §7.2: it checks the countersignature with the registry, not with the adapter."""
        client = _FakeKms(KEY_SPEC_ED25519)
        signer = await AwsKmsCountersigner.from_kms(client, 'arn:aws:kms:host', key_id='odin-host-1')
        registry = KeyRegistry(KeyRole.HOST)
        entry_jwk = await kms_registry_entry(client, 'arn:aws:kms:host', key_id='odin-host-1', role=KeyRole.HOST)
        registry.load_jwks({'keys': [entry_jwk]})
        signature = await signer.sign(_payload())
        assert await CountersignatureRegistryVerifier(registry).verify('odin-host-1', signature, _payload())
        # end def

    # end class


class TestTheToolSignsThroughKms:
    """The same two algorithms on the Level-2 event path, which is where Janus's key goes."""

    @pytest.mark.parametrize('key_spec', [KEY_SPEC_P256, KEY_SPEC_ED25519])
    async def test_an_event_signed_through_kms_verifies_against_the_published_key(self, key_spec: str) -> None:
        """A tool whose key lives in KMS still produces a record the host can check (§5.1)."""
        client = _FakeKms(key_spec)
        signer = await AwsKmsSigner.from_kms(client, 'arn:aws:kms:tool', event_key_id='janus-menu-1')
        event = {'id': '00000000-0000-4000-8000-000000000001', 'action_type': 'db.read'}
        signed = await signer.sign(event, 7)
        assert signed['signer_seq'] == 7
        assert signed['key_id'] == 'janus-menu-1'

        registry = KeyRegistry(KeyRole.TOOL)
        entry_jwk = await kms_registry_entry(client, 'arn:aws:kms:tool', key_id='janus-menu-1', role=KeyRole.TOOL)
        registry.load_jwks({'keys': [entry_jwk]})
        entry = registry.get('janus-menu-1')
        assert entry is not None
        from auditable_mcp.l2 import signature_payload

        unsigned = {key: value for key, value in signed.items() if key != 'signature'}
        assert verify_detached_signature(signature_payload(unsigned), str(signed['signature']), entry)
        # end def

    async def test_the_published_entry_is_the_form_a_peer_is_provisioned_from(self) -> None:
        """A key whose private half never leaves KMS is useless to a peer until its public half does."""
        client = _FakeKms(KEY_SPEC_ED25519)
        jwk = await kms_registry_entry(client, 'arn:aws:kms:tool', key_id='janus-menu-1', role=KeyRole.TOOL)
        key_id, _public_key, algorithm, role = public_key_of(jwk)
        assert (key_id, algorithm, role) == ('janus-menu-1', SignatureAlgorithm.ED25519, KeyRole.TOOL)
        # end def

    # end class
