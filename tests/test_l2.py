"""Unit tests for the Level-2 layer: Ed25519 signing, verification, and reconciliation."""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    BoundaryObserver,
    EcdsaSignatureVerifier,
    Ed25519SignatureVerifier,
    Ed25519Signer,
    EgressObservation,
    KeyRegistry,
    generate_tool_key,
    reconcile,
    sign_event,
    signature_payload,
    verify_ed25519_signature,
)
from auditable_mcp.ledger import Ledger
from auditable_mcp.models import AuditCapability, Level
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger


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


def _event(event_id: str = '00000000-0000-4000-8000-000000000001', **overrides: object) -> dict[str, object]:
    """Build a wire attempt event."""
    event: dict[str, object] = {
        'id': event_id,
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
    }
    event.update(overrides)
    return event
    # end def


def test_sign_then_verify_roundtrips() -> None:
    """A freshly signed event verifies against its own public key."""
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert signed['key_id'] == 'k1'
    assert signed['sequence'] == 0
    assert verify_ed25519_signature(signed, key.public_key)
    # end def


def test_tampered_body_fails_verification() -> None:
    """Altering any field after signing invalidates the signature."""
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    tampered = {**signed, 'action_type': 'db.write'}
    assert not verify_ed25519_signature(tampered, key.public_key)
    # end def


def test_tampered_signature_fails_verification() -> None:
    """A substituted signature does not verify."""
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    forged = {**signed, 'signature': base64.b64encode(b'\x00' * 64).decode('ascii')}
    assert not verify_ed25519_signature(forged, key.public_key)
    # end def


def test_non_base64_signature_is_rejected_gracefully() -> None:
    """A malformed (non-base64) signature returns False rather than raising."""
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert not verify_ed25519_signature({**signed, 'signature': 'not-base64!!'}, key.public_key)
    # end def


async def test_verifier_reports_unknown_key() -> None:
    """The verifier rejects an event whose key_id was never onboarded."""
    verifier = Ed25519SignatureVerifier(KeyRegistry())
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert await verifier.verify(signed) == 'unknown-key'
    # end def


async def test_verifier_accepts_a_registered_valid_signature() -> None:
    """A signature from a registered key verifies as None (no reject reason)."""
    key = generate_tool_key('k1')
    registry = KeyRegistry()
    registry.register_tool_key(key)
    verifier = Ed25519SignatureVerifier(registry)
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert await verifier.verify(signed) is None
    # end def


async def test_verifier_reports_forged_signature() -> None:
    """A signature that does not match the registered key is signature-invalid."""
    signing_key = generate_tool_key('k1')
    other_key = generate_tool_key('k1')
    registry = KeyRegistry()
    registry.register('k1', other_key.public_key)  # wrong public key registered under the same id
    verifier = Ed25519SignatureVerifier(registry)
    signed = sign_event(_event(), signing_key.key_id, 0, signing_key.private_key)
    assert await verifier.verify(signed) == 'signature-invalid'
    # end def


async def test_ecdsa_verifier_roundtrips_and_reports_unknown_key() -> None:
    """EcdsaSignatureVerifier verifies a local ECDSA signature and reports unknown-key symmetrically."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    base = {**_event(), 'key_id': 'k1', 'sequence': 0}
    signature = base64.b64encode(private_key.sign(signature_payload(base), ec.ECDSA(hashes.SHA256())))
    signed = {**base, 'signature': signature.decode('ascii')}

    registry: KeyRegistry[EllipticCurvePublicKey] = KeyRegistry()
    registry.register('k1', private_key.public_key())
    assert await EcdsaSignatureVerifier(registry).verify(signed) is None
    assert await EcdsaSignatureVerifier(KeyRegistry()).verify(signed) == 'unknown-key'
    # end def


async def test_signer_emits_a_monotonic_sequence() -> None:
    """Ed25519Signer stamps 0, 1, 2, … across successive events."""
    key = generate_tool_key('k1')
    signer = Ed25519Signer.from_tool_key(key)
    assert [(await signer.sign(_event()))['sequence'] for _ in range(3)] == [0, 1, 2]
    # end def


async def test_end_to_end_l2_without_stubs() -> None:
    """A real signer, verifier, host, and session complete an L2 action with verifiable signatures."""
    tool_key = generate_tool_key('tool-1')
    registry = KeyRegistry()
    registry.register_tool_key(tool_key)
    host = AuditHost(
        'tenant-a', AuditCapability(level=Level.L2), verifier=Ed25519SignatureVerifier(registry), clock=_Clock()
    )
    session = AmcpSession(
        InProcessTransport(host),
        'call_1',
        deps=_FixedDeps(),
        signer=Ed25519Signer.from_tool_key(tool_key),
    )
    async with session.action('db.query', {'kind': 'database', 'ref': 'pg'}, mutates=False, egress=True):
        pass
        # end with
    records = host.records()
    assert [r.event['outcome'] for r in records] == ['attempted', 'success']
    assert [r.event['sequence'] for r in records] == [0, 1]
    for record in records:
        assert verify_ed25519_signature(record.event, tool_key.public_key)
        # end for
    assert host.anomalies() == []
    assert verify_ledger(records, host.digest()).ok
    # end def


def _egress_event(event_id: str, call_id: str, ref: str, *, egress: bool) -> dict[str, object]:
    """Build an event with a given egress flag and target ref."""
    return _event(event_id, call_id=call_id, egress=egress, target_resource={'kind': 'endpoint', 'ref': ref})
    # end def


def test_reconcile_flags_unreported_egress() -> None:
    """A boundary-observed egress with no self-report is an unreported-egress anomaly."""
    ledger = Ledger('t')
    ledger.append(
        _egress_event('00000000-0000-4000-8000-000000000001', 'c1', 'https://api.example', egress=True),
        '2026-07-15T00:00:01.000Z',
    )
    observer = BoundaryObserver()
    observer.observe_egress('c1', 'https://api.example')  # reported
    observer.observe_egress('c1', 'https://evil.example')  # suppressed
    anomalies = reconcile(ledger.records(), observer.for_call('c1'), 'c1')
    assert [a.destination for a in anomalies] == ['https://evil.example']
    assert anomalies[0].kind == 'unreported-egress'
    # end def


def test_reconcile_ignores_non_egress_self_reports() -> None:
    """A self-report with egress=false does not count as reporting the destination."""
    ledger = Ledger('t')
    ledger.append(
        _egress_event('00000000-0000-4000-8000-000000000001', 'c1', 'https://api.example', egress=False),
        '2026-07-15T00:00:01.000Z',
    )
    observations = [EgressObservation('c1', 'https://api.example')]
    anomalies = reconcile(ledger.records(), observations, 'c1')
    assert [a.destination for a in anomalies] == ['https://api.example']
    # end def


def test_reconcile_clean_when_all_egress_is_reported() -> None:
    """No anomaly when every observed egress was self-reported."""
    ledger = Ledger('t')
    ledger.append(
        _egress_event('00000000-0000-4000-8000-000000000001', 'c1', 'https://api.example', egress=True),
        '2026-07-15T00:00:01.000Z',
    )
    observations = [EgressObservation('c1', 'https://api.example')]
    assert reconcile(ledger.records(), observations, 'c1') == []
    # end def
