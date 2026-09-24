"""Unit tests for the AWS KMS signing/verification adapter (fake KMS client, no boto3/AWS)."""

from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.adapters.aws_kms import AwsKmsSigner, AwsKmsVerifier
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Level, Witness
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger


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
        return {'PublicKey': der, 'KeyId': KeyId}
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
        'call_id': 'call_abc',
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
    signed = await signer.sign(_event())
    assert signed['key_id'] == 'tool-1'
    assert signed['signer_seq'] == 0
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:key-1'})
    assert await verifier.verify(signed) is None
    # end def


async def test_kms_unknown_key_is_reported() -> None:
    """A verifier with no key for the event's key_id reports unknown-key."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:key-1', event_key_id='tool-1')
    signed = await signer.sign(_event())
    verifier = AwsKmsVerifier(KeyRegistry())
    assert await verifier.verify(signed) == 'unknown-key'
    # end def


async def test_kms_tampered_body_is_signature_invalid() -> None:
    """Altering a field after KMS signing fails ECDSA verification."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:key-1', event_key_id='tool-1')
    signed = await signer.sign(_event())
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:key-1'})
    assert await verifier.verify({**signed, 'action_type': 'db.write'}) == 'signature-invalid'
    # end def


async def test_kms_signer_emits_a_monotonic_sequence() -> None:
    """The KMS signer stamps 0, 1, 2, … like the local signer."""
    signer = AwsKmsSigner(_FakeKms(), 'arn:aws:kms:key-1', event_key_id='tool-1')
    assert [(await signer.sign(_event()))['signer_seq'] for _ in range(3)] == [0, 1, 2]
    # end def


async def test_end_to_end_kms_without_stubs() -> None:
    """The KMS signer + verifier drop into the real host/session seams and produce a verifiable chain."""
    client = _FakeKms()
    signer = AwsKmsSigner(client, 'arn:aws:kms:tool', event_key_id='tool-1')
    verifier = await AwsKmsVerifier.from_kms(client, {'tool-1': 'arn:aws:kms:tool'})
    host = AuditHost(
        'tenant-a',
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', witness=Witness.NONE),
        verifier=verifier,
        clock=_Clock(),
    )
    session = AmcpSession(InProcessTransport(host), 'call_1', deps=_FixedDeps(), signer=signer)
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
