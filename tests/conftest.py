"""Shared fixtures: the vendored spec schema and golden conformance vectors."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SPEC_DIR = _REPO_ROOT / 'spec'
_SCHEMA_DIR = _SPEC_DIR / 'schema'
_VECTORS_DIR = _SPEC_DIR / 'vectors'


def _load(path: Path) -> Any:
    """Read and parse a JSON file."""
    return json.loads(path.read_text(encoding='utf-8'))
    # end def


@pytest.fixture
def canonicalization_vectors() -> list[dict[str, Any]]:
    """Golden RFC 8785 canonicalization vectors (value -> canonical string + sha256)."""
    return _load(_VECTORS_DIR / 'canonicalization.json')
    # end def


@pytest.fixture
def event_vectors() -> list[dict[str, Any]]:
    """Golden per-event vectors (event -> canonical string + sha256)."""
    return _load(_VECTORS_DIR / 'events.json')
    # end def


@pytest.fixture
def chain_vector() -> dict[str, Any]:
    """The golden sealed-chain vector (records + tail digest)."""
    return _load(_VECTORS_DIR / 'chain.json')
    # end def


@pytest.fixture
def chain_signed_vector() -> dict[str, Any]:
    """The golden signed sealed-chain vector (record_hash includes the signature, §8.2)."""
    return _load(_VECTORS_DIR / 'chain-signed.json')
    # end def


@pytest.fixture
def chain_countersigned_vector() -> dict[str, Any]:
    """The golden countersigned chain: the same records as chain.json plus the countersignature (§8.4)."""
    return _load(_VECTORS_DIR / 'chain-countersigned.json')
    # end def


@pytest.fixture
def error_cases() -> list[dict[str, Any]]:
    """Golden events a host MUST reject (attempt) or drop and flag (outcome), with the Tier-1 code."""
    return _load(_VECTORS_DIR / 'error-cases.json')
    # end def


@pytest.fixture
def event_schema_validator() -> Draft202012Validator:
    """A validator for the normative audit-event JSON Schema."""
    schema = _load(_SCHEMA_DIR / 'audit-event.schema.json')
    return Draft202012Validator(schema)
    # end def


@pytest.fixture
def capability_schema_validator() -> Draft202012Validator:
    """A validator for the normative audit-capability JSON Schema."""
    schema = _load(_SCHEMA_DIR / 'audit-capability.schema.json')
    return Draft202012Validator(schema)
    # end def
