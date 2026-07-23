"""Unit tests for the typed wire contracts."""

import pytest
from pydantic import TypeAdapter, ValidationError

from auditable_mcp.models import (
    AcceptResponse,
    AttemptResponse,
    AuditEvent,
    Outcome,
    RejectResponse,
    TargetResource,
    UnavailableResponse,
)

_ADAPTER: TypeAdapter[object] = TypeAdapter(AttemptResponse)


def _minimal_event() -> AuditEvent:
    """Build a minimal valid attempt event."""
    return AuditEvent(
        id='00000000-0000-4000-8000-000000000001',
        spec_version='auditable-mcp/0.1.1',
        ts='2026-07-15T00:00:01.000Z',
        call_id='call_abc',
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
    assert wire['spec_version'] == 'auditable-mcp/0.1.1'
    # end def


def test_boolean_effects_are_not_coerced() -> None:
    """Strict mode rejects a truthy int for a boolean effect flag (a protocol machine must not guess)."""
    with pytest.raises(ValidationError):
        AuditEvent(
            id='00000000-0000-4000-8000-000000000001',
            spec_version='auditable-mcp/0.1.1',
            ts='2026-07-15T00:00:01.000Z',
            call_id='call_abc',
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
                'spec_version': 'auditable-mcp/0.1.1',
                'ts': '2026-07-15T00:00:01.000Z',
                'call_id': 'call_abc',
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
                'spec_version': 'auditable-mcp/0.2',
                'ts': '2026-07-15T00:00:01.000Z',
                'call_id': 'call_abc',
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
                'call_id': 'call_abc',
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
    unavailable = _ADAPTER.validate_python({'status': 'unavailable', 'reason': 'internal-error', 'retryable': True})
    assert isinstance(unavailable, UnavailableResponse)
    # end def


def test_unavailable_must_be_retryable() -> None:
    """An unavailable response with retryable=false is invalid (§7.1)."""
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python({'status': 'unavailable', 'reason': 'x', 'retryable': False})
        # end with
    # end def
