"""A minimal auditable tool served over real stdio, run as a subprocess by `test_stdio_lifetime.py`.

It writes `STDIO_TOOL_EXIT_MARKER` once its process is about to exit, so the test can tell a tool that
ended on its own from one its client had to terminate.
"""

import os
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.stdio import stdio_server

from auditable_mcp import SPEC_VERSION, AuditCapability, Countersign, Level
from auditable_mcp.mcp import McpAuditTransport

CAPABILITY = AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE)
server = MCPServer('stdio-tool')


@server.tool()
async def read_customers() -> str:
    """Return a fixed answer; what is under test is the process's lifetime, not the call."""
    return 'ok'
    # end def


async def main() -> None:
    """Serve one connection behind the tool's seam until the client closes stdin."""
    async with stdio_server() as (read_stream, write_stream):
        async with McpAuditTransport(read_stream, write_stream, CAPABILITY) as wire:
            lowlevel = server._lowlevel_server
            await lowlevel.run(wire.read_stream, wire.write_stream, lowlevel.create_initialization_options())
            # end async with
        # end async with
    # end def


if __name__ == '__main__':
    anyio.run(main)
    Path(os.environ['STDIO_TOOL_EXIT_MARKER']).write_text('exited', encoding='utf-8')
    # end if
