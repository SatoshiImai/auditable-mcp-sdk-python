"""Unit tests for the typed wire contracts."""

import pytest
from pydantic import TypeAdapter, ValidationError

from auditable_mcp.models import (
    SPEC_VERSION,
    AcceptResponse,
    AttemptResponse,
    AuditEvent,
    Outcome,
    RejectResponse,
    TargetResource,
    UnavailableResponse,
    first_sealed_validation_error,
)

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
TS_WITHOUT_SECONDS = '2026-07-15T00:00Z'

_ADAPTER: TypeAdapter[object] = TypeAdapter(AttemptResponse)


def _minimal_event() -> AuditEvent:
    """Build a minimal valid attempt event."""
    return AuditEvent(
        id='00000000-0000-4000-8000-000000000001',
        spec_version=SPEC_VERSION,
        ts='2026-07-15T00:00:01.000Z',
        session_id=SESSION,
        action_type='db.read',
        mutates=False,
        egress=False,
        target_resource=TargetResource(kind='table', ref='customers'),
        outcome=Outcome.ATTEMPTED,
    )
    # end def


def test_to_wire_omits_absent_optionals() -> None:
    """Unset optional fields must not appear in the emitted wire object."""
    wire = _minimal_event().to_wire()
    assert 'reason' not in wire
    assert 'signature' not in wire
    assert 'scope_hint' not in wire['target_resource']
    assert wire['spec_version'] == SPEC_VERSION
    # end def


def test_boolean_effects_are_not_coerced() -> None:
    """Strict mode rejects a truthy int for a boolean effect flag (a protocol machine must not guess)."""
    with pytest.raises(ValidationError):
        AuditEvent(
            id='00000000-0000-4000-8000-000000000001',
            spec_version=SPEC_VERSION,
            ts='2026-07-15T00:00:01.000Z',
            session_id=SESSION,
            action_type='db.read',
            mutates=1,  # type: ignore[arg-type]
            egress=False,
            target_resource=TargetResource(kind='table', ref='customers'),
            outcome=Outcome.ATTEMPTED,
        )
        # end with
    # end def


def test_unknown_fields_are_forbidden() -> None:
    """extra='forbid' mirrors the schema's additionalProperties: false."""
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(
            {
                'id': '00000000-0000-4000-8000-000000000001',
                'spec_version': SPEC_VERSION,
                'ts': '2026-07-15T00:00:01.000Z',
                'session_id': SESSION,
                'action_type': 'db.read',
                'mutates': False,
                'egress': False,
                'target_resource': {'kind': 'table', 'ref': 'customers'},
                'outcome': 'attempted',
                'surprise': 'boom',
            }
        )
        # end with
    # end def


def test_wrong_spec_version_is_rejected() -> None:
    """spec_version is pinned to the implemented contract version."""
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(
            {
                'id': '00000000-0000-4000-8000-000000000001',
                'spec_version': 'auditable-mcp/0.1.1',
                'ts': '2026-07-15T00:00:01.000Z',
                'session_id': SESSION,
                'action_type': 'db.read',
                'mutates': False,
                'egress': False,
                'target_resource': {'kind': 'table', 'ref': 'customers'},
                'outcome': 'attempted',
            }
        )
        # end with
    # end def


def test_missing_spec_version_is_rejected() -> None:
    """spec_version is REQUIRED on an event and is never defaulted in; an omission is an error (§4)."""
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(
            {
                'id': '00000000-0000-4000-8000-000000000001',
                'ts': '2026-07-15T00:00:01.000Z',
                'session_id': SESSION,
                'action_type': 'db.read',
                'mutates': False,
                'egress': False,
                'target_resource': {'kind': 'table', 'ref': 'customers'},
                'outcome': 'attempted',
            }
        )
        # end with
    # end def


def test_attempt_response_union_discriminates_on_status() -> None:
    """The tagged union parses each variant by its status discriminator."""
    accept = _ADAPTER.validate_python(
        {
            'status': 'accept',
            'seq': 0,
            'record_hash': 'a' * 64,
            'host_ts': '2026-07-15T00:00:01.000Z',
            'previous_hash': '0' * 64,
        }
    )
    assert isinstance(accept, AcceptResponse)
    reject = _ADAPTER.validate_python({'status': 'reject', 'reason': 'schema-invalid'})
    assert isinstance(reject, RejectResponse)
    unavailable = _ADAPTER.validate_python({'status': 'unavailable', 'reason': 'internal-error'})
    assert isinstance(unavailable, UnavailableResponse)
    # end def


def test_unavailable_carries_nothing_but_its_reason() -> None:
    """`retryable` is not a field of an unavailable response (§7.1): §7.1's idempotent retry says what may follow."""
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({'status': 'unavailable', 'reason': 'x', 'retryable': False})
        # end with
    # end def


def test_a_half_present_countersign_pair_is_refused() -> None:
    """§7.1: `host_signature` and `host_key_id` appear together or not at all, on the wire too."""
    base = {
        'status': 'accept',
        'seq': 0,
        'record_hash': '0' * 64,
        'host_ts': '2026-07-15T00:00:01.000Z',
        'previous_hash': '0' * 64,
    }
    assert _ADAPTER.validate_python(base) is not None
    for half in ({'host_signature': 'AAAA'}, {'host_key_id': 'h1'}):
        with pytest.raises(ValidationError):
            _ADAPTER.validate_python({**base, **half})
            # end with
        # end for
    # end def


def test_a_current_timestamp_without_seconds_is_refused() -> None:
    """`ts` and `host_ts` are RFC 3339 date-times, whose seconds are required (§4, §7.1)."""
    event = _minimal_event().to_wire()
    event['ts'] = TS_WITHOUT_SECONDS
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(event)
        # end with
    error = first_sealed_validation_error(event)
    assert error is not None
    assert error.startswith('ts: ')
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python(
            {
                'status': 'accept',
                'seq': 0,
                'record_hash': '0' * 64,
                'host_ts': TS_WITHOUT_SECONDS,
                'previous_hash': '0' * 64,
            }
        )
        # end with
    # end def


def test_an_earlier_record_without_seconds_still_validates() -> None:
    """A record sealed before 0.4 is read against its own pattern, which made seconds optional (§11.4)."""
    v03 = _minimal_event().to_wire()
    v03.update(spec_version='auditable-mcp/0.3', ts=TS_WITHOUT_SECONDS)
    assert first_sealed_validation_error(v03) is None
    for version in ('auditable-mcp/0.1', 'auditable-mcp/0.2'):
        earlier = {key: value for key, value in v03.items() if key != 'session_id'}
        earlier.update(spec_version=version, call_id='call-1')
        assert first_sealed_validation_error(earlier) is None, version
        # end for
    # end def
