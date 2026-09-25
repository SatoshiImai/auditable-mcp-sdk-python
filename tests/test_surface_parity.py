"""The two ports export the same public surface, apart from differences each language's idiom explains.

Comparing names is not enough on its own - a port can export the same name with a different shape,
which is what the interop vectors pin. But a name one port exports and the other does not is the
earlier, cheaper failure.

The TypeScript port is read from its sibling checkout, as the walk's cross-language cases already do.
Without it the test skips rather than passing: absence is not agreement.
"""

import re
from pathlib import Path
from typing import Final

import pytest

import auditable_mcp

_TS_INDEX: Final = Path(__file__).resolve().parents[2] / 'auditable-mcp-sdk-ts' / 'src' / 'index.ts'

# Every name one port exports and the other does not, and why. A new entry here is a decision to
# accept an asymmetry; an unexplained one fails the test.
_ONLY_IN_PYTHON: Final[dict[str, str]] = {
    '__version__': 'package metadata; the TypeScript port reads it from package.json',
    'WireModel': 'the pydantic base the wire models share; TypeScript validates with Zod schemas',
    'auditable_tool': 'a decorator; the TypeScript counterpart is `withAudit`',
    'bound_session': 'a contextvar binding; TypeScript passes the session explicitly',
    'current_session': 'reads the contextvar `bound_session` sets',
}
_ONLY_IN_TYPESCRIPT: Final[dict[str, str]] = {
    'EcdsaVerify': 'the injectable ECDSA primitive; TypeScript ships two engines, Python uses `cryptography`',
    'Ed25519Engine': 'the injectable Ed25519 primitive, for the same reason',
    'Ed25519KeyPair': 'the raw key pair that engine returns',
    'ActionOptions': 'an options object; Python takes keyword arguments',
    'AuditHostOptions': 'an options object; Python takes keyword arguments',
    'VerifyOptions': 'an options object; Python takes keyword arguments',
    'AuditSpec': 'the options `withAudit` takes; Python decorates',
    'VerifyLedgerOptions': 'an options object; Python takes keyword arguments',
    'with_audit': 'the wrapper counterpart of the `auditable_tool` decorator',
    'Jwk': 'a type alias for a plain object; Python uses `dict[str, str]`',
    'JwkEntry': 'a named tuple type; Python returns a plain tuple',
    'JwkSet': 'a type alias for a plain object; Python uses `dict`',
    'accept_response_schema': 'a Zod schema; Python validates through the pydantic model',
    'attempt_response_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_capability_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_event_schema': 'a Zod schema; Python validates through the pydantic model',
    'reject_response_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_request_meta_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_result_meta_schema': 'a Zod schema; Python validates through the pydantic model',
    'target_resource_schema': 'a Zod schema; Python validates through the pydantic model',
    'unavailable_response_schema': 'a Zod schema; Python validates through the pydantic model',
}


def _typescript_exports() -> set[str]:
    """Read the names the TypeScript port's entry point re-exports, in this port's spelling."""
    names: set[str] = set()
    for block in re.findall(r'export\s+(?:type\s+)?\{([^}]*)\}', _TS_INDEX.read_text('utf-8')):
        for item in block.split(','):
            name = re.sub(r'^type\s+', '', item.strip()).split(' as ')[-1].strip()
            if name:
                names.add(name if name[:1].isupper() else re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower())
                # end if
            # end for
        # end for
    return names
    # end def


@pytest.mark.skipif(not _TS_INDEX.is_file(), reason='the TypeScript port is not checked out beside this one')
def test_the_two_ports_export_the_same_surface() -> None:
    """Any name one port has and the other lacks is either explained above or a defect."""
    python = set(auditable_mcp.__all__)
    typescript = _typescript_exports()
    assert sorted(python - typescript - set(_ONLY_IN_PYTHON)) == []
    assert sorted(typescript - python - set(_ONLY_IN_TYPESCRIPT)) == []
    # end def


@pytest.mark.skipif(not _TS_INDEX.is_file(), reason='the TypeScript port is not checked out beside this one')
def test_every_explained_difference_is_still_a_difference() -> None:
    """An explanation for a gap that has closed is a stale claim, and it would hide the next real gap."""
    python = set(auditable_mcp.__all__)
    typescript = _typescript_exports()
    assert sorted(name for name in _ONLY_IN_PYTHON if name in typescript or name not in python) == []
    assert sorted(name for name in _ONLY_IN_TYPESCRIPT if name in python or name not in typescript) == []
    # end def
