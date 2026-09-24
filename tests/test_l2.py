"""Unit tests for the Level-2 layer: Ed25519 signing, verification, and reconciliation."""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import (
    BoundaryObserver,
    Ed25519Signer,
    EgressObservation,
    KeyRegistry,
    KeyRegistryVerifier,
    SignatureAlgorithm,
    generate_tool_key,
    reconcile,
    sign_event,
    signature_payload,
    verify_ed25519_signature,
)
from auditable_mcp.ledger import Ledger
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Level, Witness
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger


def _ecdsa_sign(
    event: dict[str, object], key_id: str, signer_seq: int, private_key: ec.EllipticCurvePrivateKey
) -> dict[str, object]:
    """Sign an event as ECDSA P-256 with a local key, in the wire r||s form (§5.1)."""
    base = {**event, 'key_id': key_id, 'signer_seq': signer_seq}
    der = private_key.sign(signature_payload(base), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return {**base, 'signature': base64.b64encode(raw).decode('ascii')}
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


def _event(event_id: str = '00000000-0000-4000-8000-000000000001', **overrides: object) -> dict[str, object]:
    """Build a wire attempt event."""
    event: dict[str, object] = {
        'id': event_id,
        'spec_version': SPEC_VERSION,
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
    assert signed['signer_seq'] == 0
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
    verifier = KeyRegistryVerifier(KeyRegistry())
    key = generate_tool_key('k1')
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert await verifier.verify(signed) == 'unknown-key'
    # end def


async def test_verifier_accepts_a_registered_valid_signature() -> None:
    """A signature from a registered key verifies as None (no reject reason)."""
    key = generate_tool_key('k1')
    registry = KeyRegistry()
    registry.register_tool_key(key)
    verifier = KeyRegistryVerifier(registry)
    signed = sign_event(_event(), key.key_id, 0, key.private_key)
    assert await verifier.verify(signed) is None
    # end def


async def test_verifier_reports_forged_signature() -> None:
    """A signature that does not match the registered key is signature-invalid."""
    signing_key = generate_tool_key('k1')
    other_key = generate_tool_key('other')
    registry = KeyRegistry()
    registry.register('k1', other_key.public_key, SignatureAlgorithm.ED25519)  # wrong key under the same id
    verifier = KeyRegistryVerifier(registry)
    signed = sign_event(_event(), signing_key.key_id, 0, signing_key.private_key)
    assert await verifier.verify(signed) == 'signature-invalid'
    # end def


async def test_verifier_handles_a_heterogeneous_fleet() -> None:
    """One verifier dispatches Ed25519 and ECDSA P-256 keys by the registry's algorithm (§5.1)."""
    ed = generate_tool_key('ed-tool')
    ec_private = ec.generate_private_key(ec.SECP256R1())
    registry = KeyRegistry()
    registry.register_tool_key(ed)
    registry.register('ec-tool', ec_private.public_key(), SignatureAlgorithm.ECDSA_P256_SHA256)
    verifier = KeyRegistryVerifier(registry)

    ed_signed = sign_event(_event(), ed.key_id, 0, ed.private_key)
    assert await verifier.verify(ed_signed) is None
    ec_signed = _ecdsa_sign(_event('00000000-0000-4000-8000-000000000002'), 'ec-tool', 0, ec_private)
    assert await verifier.verify(ec_signed) is None
    forged = _ecdsa_sign(
        _event('00000000-0000-4000-8000-000000000003'), 'ec-tool', 1, ec.generate_private_key(ec.SECP256R1())
    )
    assert await verifier.verify(forged) == 'signature-invalid'
    # end def


def test_key_registry_lifecycle() -> None:
    """Re-registering a key_id with a different key is forbidden; revoke is forward-only (§10.9)."""
    registry = KeyRegistry()
    a = generate_tool_key('tool-1')
    b = generate_tool_key('tool-1')
    registry.register_tool_key(a)
    registry.register_tool_key(a)  # idempotent
    try:
        registry.register_tool_key(b)
        raise AssertionError('expected a rotation conflict')
    except ValueError:
        pass
        # end try
    registry.revoke('tool-1')
    assert registry.get('tool-1') is None
    # end def


async def test_signer_emits_a_monotonic_sequence() -> None:
    """Ed25519Signer stamps 0, 1, 2, … across successive events."""
    key = generate_tool_key('k1')
    signer = Ed25519Signer.from_tool_key(key)
    assert [(await signer.sign(_event()))['signer_seq'] for _ in range(3)] == [0, 1, 2]
    # end def


async def test_end_to_end_l2_without_stubs() -> None:
    """A real signer, verifier, host, and session complete an L2 action with verifiable signatures."""
    tool_key = generate_tool_key('tool-1')
    registry = KeyRegistry()
    registry.register_tool_key(tool_key)
    host = AuditHost(
        'tenant-a',
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', witness=Witness.NONE),
        verifier=KeyRegistryVerifier(registry),
        clock=_Clock(),
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
    assert [r.event['signer_seq'] for r in records] == [0, 1]
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
