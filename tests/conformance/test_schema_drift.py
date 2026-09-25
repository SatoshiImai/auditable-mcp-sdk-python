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

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, TypeAdapter, ValidationError

from auditable_mcp.models import (
    SPEC_VERSION,
    AttemptResponse,
    AuditCapability,
    AuditRequestMeta,
    AuditResultMeta,
    first_sealed_validation_error,
    first_validation_error,
)

_SCHEMA_DIR = Path(__file__).resolve().parents[2] / 'spec' / 'schema'

_VALID_BASE: dict[str, Any] = {
    'id': '00000000-0000-4000-8000-000000000001',
    'spec_version': SPEC_VERSION,
    'ts': '2026-07-15T00:00:01.000Z',
    'session_id': '0198f3a2-5c1e-7000-8000-00000000abc0',
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
    ('uppercase-uuid', {**_VALID_BASE, 'id': 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'}, False),
    ('uppercase-session-id', {**_VALID_BASE, 'session_id': '0198F3A2-5C1E-7000-8000-00000000ABC0'}, False),
    ('nil-session-id', {**_VALID_BASE, 'session_id': '00000000-0000-0000-0000-000000000000'}, False),
    ('key-id-alone', {**_VALID_BASE, 'key_id': 'k1'}, False),
    ('signature-without-signer-seq', {**_VALID_BASE, 'key_id': 'k1', 'signature': 'c2ln'}, False),
    ('signer-seq-as-integral-float', {**_FULL_VALID, 'signer_seq': 1.0}, True),
    ('signer-seq-as-fraction', {**_FULL_VALID, 'signer_seq': 1.5}, False),
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
    ('signature-base64url', {**_FULL_VALID, 'signature': 'c2ln_-A'}, True),
    ('signature-standard-base64-padded', {**_FULL_VALID, 'signature': 'c2lnbg=='}, False),
    ('signature-standard-base64-alphabet', {**_FULL_VALID, 'signature': 'c2l+/g'}, False),
    ('session-id-not-a-uuid', {**_VALID_BASE, 'session_id': 'call_abc'}, False),
    ('session-id-missing', {key: value for key, value in _VALID_BASE.items() if key != 'session_id'}, False),
    ('call-id-is-not-a-field', {**_VALID_BASE, 'call_id': 'call_abc'}, False),
    ('aborted-without-reason', {**_VALID_BASE, 'outcome': 'aborted'}, False),
    ('aborted-with-reason', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'host-rejected'}, True),
    ('aborted-bad-reason', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'because'}, False),
    ('aborted-uncountersigned', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'host-uncountersigned'}, True),
    ('aborted-unwitnessed-is-not-a-code', {**_VALID_BASE, 'outcome': 'aborted', 'reason': 'host-unwitnessed'}, False),
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


_CAP_VALID: dict[str, Any] = {'spec_version': SPEC_VERSION, 'level': 'L1', 'attempt': 'request', 'countersign': 'none'}

# (name, capability, expected_valid) — all four fields REQUIRED (§6.1): a missing one is rejected, not
# defaulted, so a peer cannot bypass version or countersignature negotiation by omission.
_CAP_SAMPLES: list[tuple[str, dict[str, Any], bool]] = [
    ('cap-valid', _CAP_VALID, True),
    ('cap-l2', {**_CAP_VALID, 'level': 'L2'}, True),
    ('cap-missing-spec-version', {key: value for key, value in _CAP_VALID.items() if key != 'spec_version'}, False),
    ('cap-missing-level', {key: value for key, value in _CAP_VALID.items() if key != 'level'}, False),
    ('cap-missing-attempt', {key: value for key, value in _CAP_VALID.items() if key != 'attempt'}, False),
    ('cap-bad-level', {**_CAP_VALID, 'level': 'L3'}, False),
    ('cap-bad-attempt', {**_CAP_VALID, 'attempt': 'response'}, False),
    ('cap-countersign-host', {**_CAP_VALID, 'countersign': 'host'}, True),
    ('cap-missing-countersign', {key: value for key, value in _CAP_VALID.items() if key != 'countersign'}, False),
    ('cap-bad-countersign', {**_CAP_VALID, 'countersign': 'self'}, False),
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


_ACCEPT: dict[str, Any] = {
    'status': 'accept',
    'seq': 0,
    'record_hash': 'a' * 64,
    'host_ts': '2026-07-15T00:00:01.000Z',
    'previous_hash': '0' * 64,
}
_TRIPLE: dict[str, Any] = {'host_signature': 'c2ln', 'host_key_id': 'host-key', 'log_id': 'tenant-a'}

# (name, response, expected_valid): the countersignature triple travels whole (§7.1), and `unavailable`
# carries nothing but its reason.
_RESPONSE_SAMPLES: list[tuple[str, dict[str, Any], bool]] = [
    ('accept', _ACCEPT, True),
    ('accept-countersigned', {**_ACCEPT, **_TRIPLE}, True),
    ('accept-without-log-id', {**_ACCEPT, 'host_signature': 'c2ln', 'host_key_id': 'host-key'}, False),
    ('accept-log-id-alone', {**_ACCEPT, 'log_id': 'tenant-a'}, False),
    ('accept-standard-base64', {**_ACCEPT, **_TRIPLE, 'host_signature': 'c2lnbg=='}, False),
    ('reject', {'status': 'reject', 'reason': 'replay-detected'}, True),
    ('unavailable', {'status': 'unavailable', 'reason': 'internal-error'}, True),
    (
        'unavailable-retryable-is-not-a-field',
        {'status': 'unavailable', 'reason': 'internal-error', 'retryable': True},
        False,
    ),
]


def test_response_acceptance_matches_the_vendored_schema() -> None:
    """The Attempt Response model and its normative JSON Schema agree on every sample (§7.1)."""
    schema = json.loads((_SCHEMA_DIR / 'audit-attempt-response.schema.json').read_text(encoding='utf-8'))
    validator = Draft202012Validator(schema)
    adapter: TypeAdapter[Any] = TypeAdapter(AttemptResponse)
    for name, response, expected in _RESPONSE_SAMPLES:
        schema_ok = not list(validator.iter_errors(response))
        try:
            adapter.validate_python(response)
            pydantic_ok = True
        except ValidationError:
            pydantic_ok = False
            # end try
        assert schema_ok == expected, f'schema disagreed on {name} (got {schema_ok})'
        assert pydantic_ok == expected, f'pydantic disagreed on {name} (got {pydantic_ok})'
        # end for
    # end def


_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'

# (schema file, model, name, object, expected_valid): the `_meta` objects of the §6.4 binding.
_META_SAMPLES: list[tuple[str, type[BaseModel], str, dict[str, Any], bool]] = [
    ('audit-request-meta.schema.json', AuditRequestMeta, 'session-only', {'session_id': _SESSION}, True),
    (
        'audit-request-meta.schema.json',
        AuditRequestMeta,
        'with-responses',
        {'session_id': _SESSION, 'responses': {'00000000-0000-4000-8000-000000000001': _ACCEPT}},
        True,
    ),
    ('audit-request-meta.schema.json', AuditRequestMeta, 'session-not-uuid', {'session_id': 'call-1'}, False),
    (
        'audit-request-meta.schema.json',
        AuditRequestMeta,
        'responses-key-not-a-uuid',
        {'session_id': _SESSION, 'responses': {'not-an-id': _ACCEPT}},
        False,
    ),
    (
        'audit-request-meta.schema.json',
        AuditRequestMeta,
        'responses-key-uppercase',
        {'session_id': _SESSION, 'responses': {'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA': _ACCEPT}},
        False,
    ),
    (
        'audit-request-meta.schema.json',
        AuditRequestMeta,
        'nil-session',
        {'session_id': '00000000-0000-0000-0000-000000000000'},
        False,
    ),
    ('audit-request-meta.schema.json', AuditRequestMeta, 'extra', {'session_id': _SESSION, 'x': 1}, False),
    (
        'audit-result-meta.schema.json',
        AuditResultMeta,
        'one-event',
        {'session_id': _SESSION, 'events': [{**_VALID_BASE}]},
        True,
    ),
    ('audit-result-meta.schema.json', AuditResultMeta, 'no-events', {'session_id': _SESSION, 'events': []}, False),
    (
        'audit-result-meta.schema.json',
        AuditResultMeta,
        'invalid-event-object',
        {'session_id': _SESSION, 'events': [{'outcome': 'attempted'}]},
        True,
    ),
    (
        'audit-result-meta.schema.json',
        AuditResultMeta,
        'non-object-item',
        {'session_id': _SESSION, 'events': [42]},
        False,
    ),
]


def test_meta_objects_match_the_vendored_schemas() -> None:
    """The §6.4 `_meta` models and their normative JSON Schemas agree on every sample."""
    for file, model, name, value, expected in _META_SAMPLES:
        validator = Draft202012Validator(json.loads((_SCHEMA_DIR / file).read_text(encoding='utf-8')))
        schema_ok = not list(validator.iter_errors(value))
        try:
            model.model_validate(value)
            pydantic_ok = True
        except ValidationError:
            pydantic_ok = False
            # end try
        assert schema_ok == expected, f'schema disagreed on {file}:{name} (got {schema_ok})'
        assert pydantic_ok == expected, f'pydantic disagreed on {file}:{name} (got {pydantic_ok})'
        # end for
    # end def


def _earlier_base(version: str) -> dict[str, Any]:
    """A valid event of an earlier published version: it names its call by `call_id`, not a session."""
    event = {key: value for key, value in _VALID_BASE.items() if key != 'session_id'}
    return {**event, 'spec_version': version, 'call_id': 'call-1'}
    # end def


# (version, name, event, expected_valid): each earlier version against its own vendored schema (§11.4).
_EARLIER_SAMPLES: list[tuple[str, str, dict[str, Any], bool]] = [
    *(
        sample
        for version in ('0.1', '0.1.1', '0.2')
        for sample in (
            (version, 'minimal', _earlier_base(f'auditable-mcp/{version}'), True),
            (
                version,
                'uppercase-uuid',
                {**_earlier_base(f'auditable-mcp/{version}'), 'id': 'A' * 8 + _VALID_BASE['id'][8:]},
                True,
            ),
            (
                version,
                'session-id-is-not-a-field',
                {**_earlier_base(f'auditable-mcp/{version}'), 'session_id': _SESSION},
                False,
            ),
            (
                version,
                'call-id-missing',
                {k: v for k, v in _earlier_base(f'auditable-mcp/{version}').items() if k != 'call_id'},
                False,
            ),
        )
    ),
    ('0.1', 'sequence', {**_earlier_base('auditable-mcp/0.1'), 'sequence': 3, 'key_id': 'k', 'signature': 'x'}, True),
    ('0.1', 'free-reason', {**_earlier_base('auditable-mcp/0.1'), 'outcome': 'aborted', 'reason': 'anything'}, True),
    ('0.1', 'aborted-without-reason', {**_earlier_base('auditable-mcp/0.1'), 'outcome': 'aborted'}, True),
    ('0.1', 'signer-seq-is-not-a-field', {**_earlier_base('auditable-mcp/0.1'), 'signer_seq': 0}, False),
    (
        '0.2',
        'standard-base64-signature',
        {**_earlier_base('auditable-mcp/0.2'), 'signer_seq': 0, 'key_id': 'k', 'signature': 'c2lnbg=='},
        True,
    ),
    (
        '0.2',
        'base64url-signature',
        {**_earlier_base('auditable-mcp/0.2'), 'signer_seq': 0, 'key_id': 'k', 'signature': 'c2l_-g'},
        False,
    ),
    ('0.2', 'aborted-without-reason', {**_earlier_base('auditable-mcp/0.2'), 'outcome': 'aborted'}, False),
    (
        '0.2',
        'uncountersigned-is-not-a-reason',
        {**_earlier_base('auditable-mcp/0.2'), 'outcome': 'aborted', 'reason': 'host-uncountersigned'},
        False,
    ),
    ('0.1.1', 'sequence-is-not-a-field', {**_earlier_base('auditable-mcp/0.1.1'), 'sequence': 0}, False),
]


def test_earlier_versions_match_their_own_vendored_schemas() -> None:
    """A sealed record of an earlier version is read in that version's shape, as its schema defines it."""
    for version, name, event, expected in _EARLIER_SAMPLES:
        schema_file = _SCHEMA_DIR / 'earlier' / version / 'audit-event.schema.json'
        validator = Draft202012Validator(json.loads(schema_file.read_text(encoding='utf-8')))
        schema_ok = not list(validator.iter_errors(event))
        pydantic_ok = first_sealed_validation_error(event) is None
        assert schema_ok == expected, f'schema disagreed on {version}:{name} (got {schema_ok})'
        assert pydantic_ok == expected, f'pydantic disagreed on {version}:{name} (got {pydantic_ok})'
        # end for
    # end def
