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
def event_schema_validator() -> Draft202012Validator:
    """A validator for the normative audit-event JSON Schema."""
    schema = _load(_SCHEMA_DIR / 'audit-event.schema.json')
    return Draft202012Validator(schema)
    # end def
