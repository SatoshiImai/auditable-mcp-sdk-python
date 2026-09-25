"""M5: the frozen bytes both SDK ports read, so neither proves only that it agrees with itself.

These vectors are not part of the specification (§5.1 leaves provisioning to the deployment); they
pin what this project's two ports agree on. See `interop/README.md`.
"""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from auditable_mcp.l2 import (
    KeyRegistry,
    KeyRole,
    SignatureAlgorithm,
    jwk_thumbprint,
    load_tool_key,
    public_jwk,
    public_key_of,
)

_VECTORS = json.loads((Path(__file__).resolve().parents[1] / 'interop' / 'key-exchange.json').read_text('utf-8'))


def _refusals() -> list[tuple[str, dict[str, Any]]]:
    """The malformed documents both ports must refuse, named for the report."""
    return [(case['name'], case['jwk']) for case in _VECTORS['refused_jwks']]
    # end def


@pytest.mark.parametrize('role,member', [(KeyRole.TOOL, 'tool_jwks'), (KeyRole.HOST, 'host_jwks')])
def test_a_committed_set_loads_and_renders_back_identically(role: KeyRole, member: str) -> None:
    """Reading the frozen bytes and writing them again must produce the same document."""
    registry = KeyRegistry(role)
    registry.load_jwks(_VECTORS[member])
    assert registry.to_jwks() == _VECTORS[member]
    # end def


def test_every_committed_thumbprint_matches() -> None:
    """A person comparing a key out of band sees the same value from either port (RFC 7638)."""
    for member in ('tool_jwks', 'host_jwks'):
        for jwk in _VECTORS[member]['keys']:
            assert jwk_thumbprint(jwk) == _VECTORS['thumbprints'][jwk['kid']]
            # end for
        # end for
    # end def


def test_a_committed_private_key_reads_back_to_its_published_public_half() -> None:
    """The PKCS#8 one port writes is the PKCS#8 the other reads (M2)."""
    for entry in _VECTORS['private_keys']:
        tool_key = load_tool_key(entry['kid'], base64.b64decode(entry['pkcs8_base64']))
        rendered = public_jwk(tool_key.key_id, tool_key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        assert jwk_thumbprint(rendered) == entry['public_jwk_thumbprint']
        # end for
    # end def


@pytest.mark.parametrize('name,jwk', _refusals(), ids=[name for name, _ in _refusals()])
def test_a_committed_refusal_is_refused(name: str, jwk: dict[str, Any]) -> None:
    """The set of documents each port refuses has to be the same set, or one accepts what the other will not."""
    with pytest.raises(ValueError):
        public_key_of(jwk)
        # end with
    # end def


def test_a_set_of_the_other_role_is_refused() -> None:
    """A tool key held as a host's lets a tool sign itself into the countersigned state (§5.2)."""
    mismatch = _VECTORS['role_mismatch']
    with pytest.raises(ValueError):
        KeyRegistry(KeyRole(mismatch['load_into_role'])).load_jwks(mismatch['jwks'])
        # end with
    # end def


@pytest.mark.parametrize('case', _VECTORS['refused_jwks_sets'], ids=[c['name'] for c in _VECTORS['refused_jwks_sets']])
def test_a_committed_set_refusal_leaves_the_registry_untouched(case: dict[str, Any]) -> None:
    """A refused set lands nothing: a half-provisioned registry verifies some records and rejects others."""
    registry = KeyRegistry(KeyRole.TOOL)
    before = registry.to_jwks()
    with pytest.raises(ValueError):
        registry.load_jwks(case['jwks'])
        # end with
    assert registry.to_jwks() == before
    # end def


@pytest.mark.parametrize(
    'case', _VECTORS['refused_thumbprints'], ids=[c['name'] for c in _VECTORS['refused_thumbprints']]
)
def test_a_thumbprint_of_an_incomplete_key_is_refused(case: dict[str, Any]) -> None:
    """A thumbprint of something that is not a key would match nothing a person could check (RFC 7638)."""
    with pytest.raises(ValueError):
        jwk_thumbprint(case['jwk'])
        # end with
    # end def


def test_a_committed_private_key_reads_the_same_from_pem() -> None:
    """A secret manager hands a key over as PEM; both ports read it to the same key as the DER."""
    for entry in _VECTORS['private_keys']:
        from_der = load_tool_key(entry['kid'], base64.b64decode(entry['pkcs8_base64']))
        from_pem = load_tool_key(entry['kid'], entry['pkcs8_pem'].encode('ascii'))
        assert from_pem.public_key.public_bytes_raw() == from_der.public_key.public_bytes_raw()
        # end for
    # end def
