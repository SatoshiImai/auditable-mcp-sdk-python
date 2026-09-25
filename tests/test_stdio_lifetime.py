"""A tool behind its seam, over a real stdio pipe, ends when its client closes the connection."""

import os
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from auditable_mcp.host import AuditHost
from auditable_mcp.mcp import McpAuditReceiver

_TOOL = Path(__file__).with_name('stdio_tool.py')
# Below the MCP client's own grace period (2s), after which it terminates a server that did not exit.
_EXIT_BOUND = 1.0


@pytest.mark.parametrize('audited', [True, False], ids=['audited-host', 'ordinary-host'])
@pytest.mark.parametrize('modern', [True, False], ids=['section-6.4-mrtr', 'section-6.5-initialize'])
async def test_the_tool_process_exits_on_its_own_when_the_client_closes(
    tmp_path: Path, audited: bool, modern: bool
) -> None:
    """The seam closes the transport's write stream, so stdio's writer ends and the process exits on EOF."""
    marker = tmp_path / 'exited'
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(_TOOL)],
        env={**os.environ, 'STDIO_TOOL_EXIT_MARKER': str(marker)},
    )
    host = AuditHost('tenant-a')
    with anyio.fail_after(10):
        async with stdio_client(parameters) as (read_stream, write_stream):
            if audited:
                async with McpAuditReceiver(read_stream, write_stream, host) as receiver:
                    async with ClientSession(receiver.read_stream, receiver.write_stream) as session:
                        await (session.discover() if modern else session.initialize())
                        result = await session.call_tool('read_customers', {})
                        # end async with
                    # end async with
            else:
                async with ClientSession(read_stream, write_stream) as session:
                    await (session.discover() if modern else session.initialize())
                    result = await session.call_tool('read_customers', {})
                    # end async with
                # end if
            closing = anyio.current_time()
            # end async with
        closed_in = anyio.current_time() - closing
        # end with
    assert not result.is_error
    assert marker.read_text(encoding='utf-8') == 'exited'
    assert closed_in < _EXIT_BOUND, f'the tool took {closed_in:.2f}s to exit after the client closed'
    # end def
