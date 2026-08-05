"""Drift guard: the Pydantic model's acceptance must match the normative JSON Schema.

The pattern constants in `models.py` are hand-copied from `spec/schema/`. This test locks that copy
to the vendored schema over a set of valid and deliberately-invalid samples: the Pydantic verdict and
the JSON Schema verdict must agree, and both must match the expected outcome. If the spec changes a
pattern (e.g. `ts` becomes a Unix timestamp) and the copied constant is not updated, the verdicts
diverge here and the build fails.

Only pattern / range / required / enum / closed-shape cases are covered — not the places where the
model is intentionally stricter than the schema (it forbids silent coercion such as `1` for a bool),
which are exercised in `tests/test_models.py`.
"""

from typing import Any

from pydantic import ValidationError

from auditable_mcp.models import AuditCapability, first_validation_error

_VALID_BASE: dict[str, Any] = {
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

_FULL_VALID: dict[str, Any] = {
    **_VALID_BASE,
    'traceparent': '00-abc-def-01',
    'target_resource': {'kind': 'table', 'ref': 'customers', 'scope_hint': 'row:x=1'},
    'action_context': {'dialect': 'postgres'},
    'action_context_hash': 'sha256:' + 'a' * 64,
    'signer_seq': 0,
    'key_id': 'k1',
    'signature': 'c2ln',
}

# (name, event, expected_valid)
_SAMPLES: list[tuple[str, dict[str, Any], bool]] = [
    ('minimal-valid', _VALID_BASE, True),
    ('full-valid', _FULL_VALID, True),
    ('uppercase-uuid', {**_VALID_BASE, 'id': 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'}, True),
    ('nil-uuid', {**_VALID_BASE, 'id': '00000000-0000-0000-0000-000000000000'}, True),
    ('bad-uuid', {**_VALID_BASE, 'id': 'not-a-uuid'}, False),
    ('uuid-bad-version', {**_VALID_BASE, 'id': '00000000-0000-9000-8000-000000000001'}, False),
    ('stale-spec-version', {**_VALID_BASE, 'spec_version': 'auditable-mcp/0.1'}, False),
    ('ts-garbage', {**_VALID_BASE, 'ts': 'yesterday'}, False),
    ('ts-bad-month', {**_VALID_BASE, 'ts': '2026-13-01T00:00:00Z'}, False),
    ('ts-feb-30', {**_VALID_BASE, 'ts': '2026-02-30T00:00:00Z'}, False),
    ('ts-offset-not-z', {**_VALID_BASE, 'ts': '2026-07-15T00:00:01+09:00'}, False),
    ('ach-bad', {**_VALID_BASE, 'action_context_hash': 'sha256:XYZ'}, False),
    ('ach-valid', {**_VALID_BASE, 'action_context_hash': 'sha256:' + 'a' * 64}, True),
    ('signer-seq-negative', {**_VALID_BASE, 'signer_seq': -1}, False),
    ('signer-seq-too-large', {**_VALID_BASE, 'signer_seq': 2**53}, False),
    ('empty-key-id', {**_FULL_VALID, 'key_id': ''}, False),
    ('signature-not-base64', {**_FULL_VALID, 'signature': 'not base64!'}, False),
    ('aborted-without-reason', {**_VALID_BASE, 'outcome': 'aborted'}, False),
    ('aborted-with-reason', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'host-rejected'}, True),
    ('aborted-bad-reason', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'because'}, False),
    ('extra-property', {**_VALID_BASE, 'surprise': 'boom'}, False),
    ('missing-required', {key: value for key, value in _VALID_BASE.items() if key != 'target_resource'}, False),
    ('bad-outcome', {**_VALID_BASE, 'outcome': 'weird'}, False),
    ('empty-action-type', {**_VALID_BASE, 'action_type': ''}, False),
]


def test_pydantic_acceptance_matches_the_vendored_schema(event_schema_validator: Any) -> None:
    """For every sample, Pydantic and the JSON Schema agree, and both match the expected outcome."""
    for name, event, expected in _SAMPLES:
        schema_ok = not list(event_schema_validator.iter_errors(event))
        pydantic_ok = first_validation_error(event) is None
        assert schema_ok == expected, f'schema disagreed on {name} (got {schema_ok})'
        assert pydantic_ok == expected, f'pydantic disagreed on {name} (got {pydantic_ok})'
        assert schema_ok == pydantic_ok, f'pydantic/schema drift on {name}'
        # end for
    # end def


_CAP_VALID: dict[str, Any] = {'spec_version': 'auditable-mcp/0.2', 'level': 'L1', 'attempt': 'request'}

# (name, capability, expected_valid) — all three fields REQUIRED (§6.1): a missing one is rejected, not
# defaulted, so a peer cannot bypass version negotiation by omission.
_CAP_SAMPLES: list[tuple[str, dict[str, Any], bool]] = [
    ('cap-valid', _CAP_VALID, True),
    ('cap-l2', {**_CAP_VALID, 'level': 'L2'}, True),
    ('cap-missing-spec-version', {key: value for key, value in _CAP_VALID.items() if key != 'spec_version'}, False),
    ('cap-missing-level', {key: value for key, value in _CAP_VALID.items() if key != 'level'}, False),
    ('cap-missing-attempt', {key: value for key, value in _CAP_VALID.items() if key != 'attempt'}, False),
    ('cap-bad-level', {**_CAP_VALID, 'level': 'L3'}, False),
    ('cap-bad-attempt', {**_CAP_VALID, 'attempt': 'response'}, False),
    ('cap-extra-property', {**_CAP_VALID, 'surprise': 'boom'}, False),
]


def _capability_pydantic_ok(capability: dict[str, Any]) -> bool:
    """Return True if the capability validates against the strict AuditCapability model."""
    try:
        AuditCapability.model_validate(capability)
        return True
    except ValidationError:
        return False
    # end def


def test_capability_pydantic_acceptance_matches_the_vendored_schema(capability_schema_validator: Any) -> None:
    """The capability model and the normative capability JSON Schema agree on every sample (§6.1)."""
    for name, capability, expected in _CAP_SAMPLES:
        schema_ok = not list(capability_schema_validator.iter_errors(capability))
        pydantic_ok = _capability_pydantic_ok(capability)
        assert schema_ok == expected, f'schema disagreed on {name} (got {schema_ok})'
        assert pydantic_ok == expected, f'pydantic disagreed on {name} (got {pydantic_ok})'
        assert schema_ok == pydantic_ok, f'pydantic/schema drift on {name}'
        # end for
    # end def
