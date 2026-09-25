"""Cross-language conformance: reproduce every golden vector byte-for-byte (spec §8.4, §11.1).

A vector mismatch means the SDK is non-conformant, not a different-but-valid encoding.
"""

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auditable_mcp import (
    SPEC_VERSION,
    AuditCapability,
    AuditEvent,
    AuditHost,
    ExpectedIdentity,
    Level,
    SealedRecord,
    UnaccountedSignerSeq,
    canonicalize,
    compute_record_hash,
    sha256_hex,
    unaccounted_signer_seq,
    verify_ledger,
)
from auditable_mcp.encoding import b64url_decode
from auditable_mcp.hashing import GENESIS_HASH, countersignature_payload
from auditable_mcp.l2 import (
    CountersignatureRegistryVerifier,
    KeyRegistry,
    KeyRegistryVerifier,
    KeyRole,
    SignatureAlgorithm,
)

_VECTORS_DIR = Path(__file__).resolve().parents[2] / 'spec' / 'vectors'


def _published_key(chain: dict[str, Any], key_id: str) -> Ed25519PublicKey:
    """The Ed25519 public key a chain vector publishes as a JWK under `key_id`."""
    jwk = chain['keys'][key_id]['jwk']
    raw = b64url_decode(jwk['x'])
    assert raw is not None
    return Ed25519PublicKey.from_public_bytes(raw)
    # end def


def test_canonicalization_vectors_reproduce_exact_bytes_and_hash(
    canonicalization_vectors: list[dict[str, Any]],
) -> None:
    """Every canonicalization vector must reproduce the exact JCS string and SHA-256."""
    for vector in canonicalization_vectors:
        canonical = canonicalize(vector['value'])
        assert canonical == vector['canonical'], vector['name']
        assert sha256_hex(canonical) == vector['sha256'], vector['name']
        # end for


def test_event_vectors_canonicalize_and_hash_exactly(event_vectors: list[dict[str, Any]]) -> None:
    """Each golden event canonicalizes to the exact bytes and hash."""
    for vector in event_vectors:
        canonical = canonicalize(vector['event'])
        assert canonical == vector['canonical'], vector['name']
        assert sha256_hex(canonical) == vector['sha256'], vector['name']
        # end for


def test_event_vectors_roundtrip_through_the_pydantic_model(event_vectors: list[dict[str, Any]]) -> None:
    """Parsing a golden event into AuditEvent and re-emitting it preserves the exact wire bytes."""
    for vector in event_vectors:
        event = AuditEvent.model_validate(vector['event'])
        assert event.to_wire() == vector['event'], vector['name']
        assert canonicalize(event.to_wire()) == vector['canonical'], vector['name']
        # end for


def test_event_vectors_validate_against_the_shared_schema(
    event_vectors: list[dict[str, Any]],
    event_schema_validator: Any,
) -> None:
    """Every golden event — and the model's re-emission of it — validates against the shared schema."""
    for vector in event_vectors:
        assert not list(event_schema_validator.iter_errors(vector['event'])), vector['name']
        emitted = AuditEvent.model_validate(vector['event']).to_wire()
        assert not list(event_schema_validator.iter_errors(emitted)), vector['name']
        # end for


def _reproduce_chain(chain: dict[str, Any]) -> None:
    """Recompute each record hash from the §8.2 preimage and verify the chain links to the digest."""
    previous_hash = GENESIS_HASH
    for index, record in enumerate(chain['records']):
        assert record['seq'] == index
        assert record['previous_hash'] == previous_hash
        recomputed = compute_record_hash(
            record['event'],
            record['seq'],
            record['host_ts'],
            record['previous_hash'],
        )
        assert recomputed == record['record_hash'], f'record {index}'
        previous_hash = recomputed
        # end for
    assert previous_hash == chain['digest']
    # end def


def test_chain_vector_record_hashes_and_links_reproduce(chain_vector: dict[str, Any]) -> None:
    """The Level-1 golden chain reproduces byte-for-byte."""
    _reproduce_chain(chain_vector)
    # end def


def test_signed_chain_vector_reproduces_with_signature_in_the_preimage(chain_signed_vector: dict[str, Any]) -> None:
    """The Level-2 signed chain reproduces: the record_hash preimage includes the signature (§8.2)."""
    _reproduce_chain(chain_signed_vector)
    # end def


def test_countersignature_preimage_reproduces_the_golden_bytes(chain_countersigned_vector: dict[str, Any]) -> None:
    """The bytes a countersignature covers must match the vector exactly (§7.1, §8.4)."""
    for record in chain_countersigned_vector['records']:
        payload = countersignature_payload(
            record['seq'], record['host_ts'], record['log_id'], record['previous_hash'], record['record_hash']
        )
        assert payload.decode('utf-8') == record['countersignature_preimage']['canonical'], record['seq']
        assert sha256_hex(payload.decode('utf-8')) == record['countersignature_preimage']['sha256'], record['seq']
        # end for
    # end def


def test_the_countersigned_chain_hashes_identically_to_the_uncountersigned_one(
    chain_vector: dict[str, Any], chain_countersigned_vector: dict[str, Any]
) -> None:
    """The signature sits outside the §8.2 preimage, so both chains seal to the same bytes (§5.2)."""
    assert chain_countersigned_vector['digest'] == chain_vector['digest']
    previous = GENESIS_HASH
    for countersigned, plain in zip(chain_countersigned_vector['records'], chain_vector['records'], strict=True):
        computed = compute_record_hash(countersigned['event'], countersigned['seq'], countersigned['host_ts'], previous)
        assert computed == countersigned['record_hash'] == plain['record_hash'], countersigned['seq']
        assert countersigned['host_signature'], 'the countersigned vector must carry a signature'
        previous = computed
        # end for
    # end def
    # end def


def test_every_countersignature_verifies_against_the_published_host_key(
    chain_countersigned_vector: dict[str, Any],
) -> None:
    """The vector's countersignatures are real, over the preimage with `log_id` (§5.1, §7.1)."""
    for record in chain_countersigned_vector['records']:
        key = _published_key(chain_countersigned_vector, record['host_key_id'])
        signature = b64url_decode(record['host_signature'])
        assert signature is not None
        key.verify(signature, record['countersignature_preimage']['canonical'].encode('utf-8'))
        # end for
    # end def


def test_every_level_2_signature_verifies_numbered_from_zero(chain_signed_vector: dict[str, Any]) -> None:
    """The signed chain's events are one session, numbered 0, 1, ..., and their signatures verify (§7.4)."""
    registry = KeyRegistry()
    for key_id in chain_signed_vector['keys']:
        registry.register(key_id, _published_key(chain_signed_vector, key_id), SignatureAlgorithm.ED25519)
        # end for
    verifier = KeyRegistryVerifier(registry)
    for index, record in enumerate(chain_signed_vector['records']):
        assert record['event']['signer_seq'] == index
        assert verifier.check(record['event']), index
        # end for
    # end def


def test_signer_seq_accounting_reports_exactly_the_pinned_values() -> None:
    """§11.4's procedure is pinned so two verifiers report the same values for one ledger."""
    cases = json.loads((_VECTORS_DIR / 'signer-seq-accounting.json').read_text(encoding='utf-8'))
    for case in cases:
        expected = [UnaccountedSignerSeq(**gap) for gap in case['unaccounted']]
        assert unaccounted_signer_seq(case['records']) == expected, case['name']
        # end for
    # end def


class _VectorClock:
    """A monotonic host clock for replaying a vector's steps."""

    def __init__(self) -> None:
        """Start at zero."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-07-15T00:01:{self._n:02d}.000Z'
        # end def

    # end class


async def test_signer_seq_replay_steps_decide_exactly_as_pinned() -> None:
    """§7.1, §7.2, §7.4: the replay window is the decided set, and each step answers as the vector pins."""
    vector = json.loads((_VECTORS_DIR / 'signer-seq-replay.json').read_text(encoding='utf-8'))
    registry = KeyRegistry()
    for key_id in vector['keys']:
        registry.register(key_id, _published_key(vector, key_id), SignatureAlgorithm.ED25519)
        # end for
    capability = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign='none')
    host = AuditHost('tenant-a', capability, verifier=KeyRegistryVerifier(registry), clock=_VectorClock())
    session_id = vector['steps'][0]['event']['session_id']
    host.open_session(session_id)
    for step in vector['steps']:
        expected = step['expect']
        host.persistence_available = step['host_available']
        before_anomalies, before_records = len(host.anomalies()), len(host.records())
        if step['channel'] == 'attempt':
            response = await host.handle_attempt(step['event'], session_id=session_id)
            wire = response.to_wire()
            for member in ('status', 'reason', 'seq'):
                if member in expected:
                    assert wire.get(member) == expected[member], step['name']
                    # end if
                # end for
        else:
            await host.handle_outcome(step['event'], session_id=session_id)
            assert (len(host.records()) > before_records) == expected['sealed'], step['name']
            # end if
        new_kinds = [anomaly.kind for anomaly in host.anomalies()[before_anomalies:]]
        assert new_kinds == expected['anomalies'], step['name']
        # end for
    # end def


def test_verifier_cases_report_exactly_the_pinned_anomaly_kinds() -> None:
    """§10.10, §11.4: the out-of-band inputs and the record checks give the pinned kinds for each ledger."""
    vector = json.loads((_VECTORS_DIR / 'verifier-cases.json').read_text(encoding='utf-8'))
    registry = KeyRegistry(KeyRole.HOST)
    for key_id in vector['keys']:
        registry.register(key_id, _published_key(vector, key_id), SignatureAlgorithm.ED25519)
        # end for
    checker = CountersignatureRegistryVerifier(registry).check
    for case in vector['cases']:
        options = case['options']
        identity = options.get('expected_identity')
        expected = (
            ExpectedIdentity(log_id=identity['log_id'], host_key_ids=frozenset(identity['host_key_ids']))
            if identity is not None
            else None
        )
        report = verify_ledger(
            [SealedRecord.from_dict(record) for record in case['records']],
            countersignature_checker=checker,
            expected_identity=expected,
            countersignature_required=options.get('countersignature_required', False),
        )
        assert sorted(issue.kind for issue in report.issues) == case['expect_kinds'], case['name']
        # end for
    # end def
