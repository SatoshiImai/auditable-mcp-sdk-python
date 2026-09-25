"""What a type checker sees of the public surface, checked by running one."""

from pathlib import Path

from mypy import api

_RETURNS_FROM_AN_ACTION = """
from auditable_mcp import AmcpSession


async def read(session: AmcpSession) -> str:
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        return 'rows'
"""


def test_a_function_that_returns_inside_an_action_type_checks_under_strict(tmp_path: Path) -> None:
    """`AuditedAction.__aexit__` never suppresses, so mypy does not read the block as one that may fall through."""
    snippet = tmp_path / 'snippet.py'
    snippet.write_text(_RETURNS_FROM_AN_ACTION, encoding='utf-8')
    stdout, stderr, status = api.run(['--strict', '--no-incremental', str(snippet)])
    assert status == 0, stdout + stderr
    # end def
