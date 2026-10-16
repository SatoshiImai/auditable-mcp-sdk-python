"""The salted hash of an internal context (§4.3): vectors, opening, and an action that seals one."""

import json
import re
from typing import Any

from auditable_mcp import AmcpSession, AuditHost, InProcessTransport
from auditable_mcp.encoding import b64url_encode
from auditable_mcp.salted_hash import (
    SALTED_HASH_PATTERN,
    disclosure_of,
    new_salt,
    open_salted_hash,
    salted_hash_of,
)


def test_reproduces_the_shared_vectors(salted_hash_vectors: list[dict[str, Any]]) -> None:
    for vector in salted_hash_vectors:
        assert salted_hash_of(vector['disclosure']) == vector['salted_hash'], vector['name']
        salt, value = vector['decoded']
        if isinstance(value, dict):
            assert disclosure_of(salt, value) == vector['disclosure'], vector['name']
            assert open_salted_hash(vector['disclosure'], vector['salted_hash']) == value, vector['name']
            # end if
        # end for
    # end def


def test_opens_with_its_own_disclosure_and_no_other() -> None:
    context: dict[str, object] = {'table': 'customers', 'rows': 3}
    disclosure = disclosure_of(new_salt(), context)
    digest = salted_hash_of(disclosure)
    assert re.fullmatch(SALTED_HASH_PATTERN, digest)
    assert open_salted_hash(disclosure, digest) == context
    assert open_salted_hash(disclosure_of(new_salt(), context), digest) is None
    # end def


def test_refuses_a_disclosure_that_is_not_a_salt_and_an_object() -> None:
    for decoded in (['s'], ['s', 'US'], [1, {}], ['s', {}, 'x']):
        disclosure = b64url_encode(json.dumps(decoded).encode('utf-8'))
        assert open_salted_hash(disclosure, salted_hash_of(disclosure)) is None
        # end for
    # end def


async def test_an_action_seals_one_salted_hash_on_attempt_and_outcome() -> None:
    host = AuditHost('tenant-a')
    session_id = host.open_session()
    session = AmcpSession(InProcessTransport(host), session_id)
    context: dict[str, object] = {'customer': '山田太郎', 'amount': 1200000}
    async with session.action(
        'payment.send',
        {'kind': 'account', 'ref': 'acct-1'},
        mutates=True,
        egress=True,
        commit_salted=context,
    ) as action:
        disclosure = action.disclosure
        # end async with
    hashes = [record.event.get('action_context_salted_hash') for record in host.records()]
    assert len(hashes) == 2
    assert hashes[0] == hashes[1]
    assert disclosure is not None
    assert open_salted_hash(disclosure, str(hashes[0])) == context
    assert '山田太郎' not in json.dumps([record.to_dict() for record in host.records()], ensure_ascii=False)
    # end def
