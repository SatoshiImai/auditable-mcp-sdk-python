"""Unit tests for the AWS KMS signing/verification adapter (fake KMS client, no boto3/AWS)."""

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import Ed25519Signer, generate_tool_key
from auditable_mcp.l2.adapters.aws_kms import (
    KEY_SPEC_ED25519,
    KEY_SPEC_P256,
    AwsKmsSigner,
    AwsKmsVerifier,
    _require_bytes,
    load_kms_public_key,
)
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Countersign, Level
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


class _FakeKms:
    """Emulates the KMS subset with a local EC P-256 key (stands in for a key held in KMS)."""

    def __init__(self) -> None:
        """Generate the backing EC key."""
        self._key = ec.generate_private_key(ec.SECP256R1())
        # end def

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER SubjectPublicKeyInfo, as KMS GetPublicKey does."""
        der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {'PublicKey': der, 'KeyId': KeyId, 'KeySpec': KEY_SPEC_P256}
        # end def

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign the provided digest (MessageType=DIGEST) and return a DER ECDSA signature."""
        signature = self._key.sign(Message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return {'Signature': signature}
        # end def


class _Clock:
    """A monotonic host clock producing valid timestamps."""

    def __init__(self) -> None:
        """Start at zero."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-07-15T00:00:{self._n:02d}.000Z'
        # end def


class _FixedDeps:
    """Deterministic id/time source producing valid UUIDs."""

    def __init__(self) -> None:
        """Start the id counter at zero."""
        self._n = 0
        # end def

    def new_id(self) -> str:
        """Return the next deterministic UUID-shaped id."""
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'
        # end def

    def now(self) -> str:
        """Return a fixed valid timestamp."""
        return '2026-07-15T00:00:01.000Z'
        # end def


def _event() -> dict[str, object]:
    """Build a wire attempt event."""
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': SPEC_VERSION,
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    # end def


async def test_kms_sign_then_verify_roundtrips() -> None:
    """A KMS-signed event verifies against the public key fetched from KMS."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:key-1', event_key_id='tool-1')
    signed = await signer.sign(_event(), 0)
    assert signed['key_id'] == 'tool-1'
    assert signed['signer_seq'] == 0
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:key-1'})
    assert await verifier.verify(signed) is None
    # end def


async def test_kms_unknown_key_is_reported() -> None:
    """A verifier with no key for the event's key_id reports unknown-key."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:key-1', event_key_id='tool-1')
    signed = await signer.sign(_event(), 0)
    verifier = AwsKmsVerifier(KeyRegistry())
    assert await verifier.verify(signed) == 'unknown-key'
    # end def


async def test_kms_tampered_body_is_signature_invalid() -> None:
    """Altering a field after KMS signing fails ECDSA verification."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:key-1', event_key_id='tool-1')
    signed = await signer.sign(_event(), 0)
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:key-1'})
    assert await verifier.verify({**signed, 'action_type': 'db.write'}) == 'signature-invalid'
    # end def


async def test_the_kms_signer_stamps_the_number_it_is_given() -> None:
    """The sequence is the session's section's, not the signer's, exactly as for the local signer."""
    signer = AwsKmsSigner(_FakeKms(), 'arn:aws:kms:key-1', event_key_id='tool-1')
    assert [(await signer.sign(_event(), n))['signer_seq'] for n in (0, 1, 2)] == [0, 1, 2]
    assert signer.key_id == 'tool-1'
    # end def


async def test_end_to_end_kms_without_stubs() -> None:
    """The KMS signer + verifier drop into the real host/session seams and produce a verifiable chain."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:tool', event_key_id='tool-1')
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:tool'})
    host = AuditHost(
        'tenant-a',
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        verifier=verifier,
        clock=_Clock(),
    )
    session = AmcpSession(InProcessTransport(host), host.open_session(), deps=_FixedDeps(), signer=signer)
    async with session.action('db.query', {'kind': 'database', 'ref': 'pg'}, mutates=False, egress=True):
        pass
        # end with
    records = host.records()
    assert [r.event['outcome'] for r in records] == ['attempted', 'success']
    assert [r.event['signer_seq'] for r in records] == [0, 1]
    assert [r.event['key_id'] for r in records] == ['tool-1', 'tool-1']
    assert host.anomalies() == []
    assert verify_ledger(records, host.digest()).ok
    # end def


def test_a_kms_response_without_the_bytes_field_is_refused() -> None:
    """An injected client is third-party code; a malformed answer is named, not indexed into."""
    with pytest.raises(ValueError, match='Signature'):
        _require_bytes({}, 'Signature')
        # end with
    # end def


@pytest.mark.asyncio
async def test_load_kms_public_key_reads_an_ed25519_kms_key() -> None:
    """An `ECC_NIST_EDWARDS25519` key is one of the two §5.1 defines, so its public half is returned."""
    tool_key = generate_tool_key('tool-1')
    loaded = await load_kms_public_key(_SpecKms(tool_key.public_key, KEY_SPEC_ED25519), 'arn:aws:kms:ed')  # type: ignore[arg-type]
    assert isinstance(loaded, Ed25519PublicKey)
    assert loaded.public_bytes_raw() == tool_key.public_key.public_bytes_raw()
    # end def


@pytest.mark.asyncio
async def test_load_kms_public_key_still_reads_a_p256_key_as_elliptic_curve() -> None:
    """A P-256 key comes back as the elliptic-curve key it always did."""
    loaded = await load_kms_public_key(_FakeKms(), 'arn:aws:kms:p256')  # type: ignore[arg-type]
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    # end def


@pytest.mark.asyncio
async def test_load_kms_public_key_refuses_a_key_of_no_algorithm_section_5_1_defines() -> None:
    """An RSA key is a provisioning error, named when the key is loaded."""
    client = _SpecKms(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(), 'RSA_2048')
    with pytest.raises(TypeError, match='neither a P-256'):
        await load_kms_public_key(client, 'arn:aws:kms:rsa')  # type: ignore[arg-type]
        # end with
    # end def


class _Ed25519Kms:
    """A KMS client holding an Ed25519 key, which signs only `ED25519_SHA_512` over `RAW`, as KMS does."""

    def __init__(self) -> None:
        """Generate the key KMS stands in for."""
        self._key = Ed25519PrivateKey.generate()
        # end def

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER form and the key spec."""
        der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {'PublicKey': der, 'KeySpec': KEY_SPEC_ED25519, 'SigningAlgorithms': ['ED25519_SHA_512']}
        # end def

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Refuse any pair but the one an Ed25519 key takes."""
        if SigningAlgorithm != 'ED25519_SHA_512' or MessageType != 'RAW':
            raise RuntimeError(f'ValidationException: {SigningAlgorithm}/{MessageType} is not valid for this key')
            # end if
        return {'Signature': self._key.sign(Message)}
        # end def

    # end class


@pytest.mark.asyncio
async def test_a_signer_from_kms_signs_with_an_ed25519_kms_key_that_the_constructor_default_cannot() -> None:
    """The constructor defaults to ECDSA P-256; `from_kms` reads the key spec and signs Ed25519."""
    kms = _Ed25519Kms()
    arn = 'arn:aws:kms:ap-northeast-1:1:key/ed'
    verifier = await AwsKmsVerifier.from_kms(kms, {'tool-1': arn})
    host = AuditHost('tenant-a', {'level': Level.L2}, verifier=verifier)
    with pytest.raises(RuntimeError, match='ValidationException'):
        await AwsKmsSigner(kms, arn, event_key_id='tool-1').sign(_event(), 0)
        # end with
    signer = await AwsKmsSigner.from_kms(kms, arn, event_key_id='tool-1')
    performed: list[bool] = []
    async with host.session() as session_id:
        session = AmcpSession(InProcessTransport(host), session_id, signer=signer)
        async with session.action('db.read', {'kind': 'table', 'ref': 'c'}, mutates=False, egress=False):
            performed.append(True)
            # end async with
        # end async with
    assert performed == [True]
    assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success']
    # end def


class _SpecKms:
    """A KMS client that answers `GetPublicKey` with a given key and key spec."""

    def __init__(self, public_key: object, key_spec: str) -> None:
        """Hold the public half and the spec KMS reports for it."""
        self._der = public_key.public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._key_spec = key_spec
        # end def

    def get_public_key(self, **_kwargs: object) -> dict[str, object]:
        """Return the DER form and the key spec, as KMS GetPublicKey does."""
        return {'PublicKey': self._der, 'KeySpec': self._key_spec}
        # end def

    # end class


@pytest.mark.asyncio
async def test_the_verifier_binds_an_ed25519_kms_key_as_ed25519() -> None:
    """The algorithm comes from the key spec KMS reports, so an Ed25519 key verifies Ed25519 signatures."""
    tool_key = generate_tool_key('tool-1')
    client = _SpecKms(tool_key.public_key, KEY_SPEC_ED25519)
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:ed'})  # type: ignore[arg-type]
    signed = await Ed25519Signer.from_tool_key(tool_key).sign(_event(), 0)
    assert verifier.check(signed)
    # end def


@pytest.mark.asyncio
async def test_the_verifier_binds_a_p256_kms_key_as_es256() -> None:
    """A P-256 key verifies the ES256 signatures the KMS signer makes."""
    client = _FakeKms()
    signed = await AwsKmsSigner(client, 'arn:aws:kms:p256', event_key_id='tool-1').sign(_event(), 0)
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:p256'})
    assert verifier.check(signed)
    # end def


@pytest.mark.asyncio
async def test_the_verifier_refuses_a_kms_key_spec_this_version_does_not_define() -> None:
    """An RSA key is a provisioning error, named at onboarding rather than at every verification."""
    client = _SpecKms(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(), 'RSA_2048')
    with pytest.raises(TypeError, match='RSA_2048'):
        await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:rsa'})  # type: ignore[arg-type]
        # end with
    # end def
