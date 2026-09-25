"""An auditable MCP tool, served over real stdio or Streamable HTTP, for the walk.

Not a test double: a separate process speaking the official stdio transport, so the walk exercises
real pipes, real framing, a real process boundary, and the §6 wire on top of all of it. The tool runs
several audited operations concurrently inside one `tools/call`, which is what §7.1 and §7.4 are for.
It serves whichever binding the host's call is made under (§6.4, §6.5); the seam reads that from the
call.

Run by `walk/run.py`; the level, the posture and the concurrency come from the environment so the
runner can drive the same tool through every configuration. `WALK_SERVER=high-level` serves the tool
through the official SDK's high-level `MCPServer` instead of the low-level `Server`; its handlers see
`str(request_id)`, not the id the call was made with. `WALK_TRANSPORT=http` serves Streamable HTTP
instead of stdio, through `AuditedStreamableHTTP` wrapping the official session manager, which is the
path a deployment takes.
"""

import base64
import json
import os
import socket
import sys
import threading
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import anyio.from_thread
import anyio.lowlevel
import mcp.types as types
import uvicorn
from mcp.server.lowlevel import Server
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route

from auditable_mcp import (
    SPEC_VERSION,
    AmcpSession,
    AuditCapability,
    AuditHost,
    Countersign,
    InProcessTransport,
    Level,
    Posture,
    SealedRecord,
    TargetResource,
    transport_for,
    verify_ledger,
)
from auditable_mcp.l2 import (
    Ed25519Signer,
    KeyRegistry,
    KeyRegistryVerifier,
    ToolKey,
    generate_tool_key,
    load_tool_key,
)
from auditable_mcp.mcp import (
    AuditedStreamableHTTP,
    HttpForwarder,
    McpAuditCall,
    McpAuditTransport,
    negotiate_unaudited,
)
from auditable_mcp.session import new_session_id

TOOL_NAME = 'read_customers'
HTTP_URL_LINE = 'WALK_HTTP_URL='


class _YieldingStore:
    """A store whose write yields, so the tool's own host has §7.1's window to get wrong."""

    def __init__(self) -> None:
        """Start empty."""
        self.rows: list[SealedRecord] = []
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Yield, then store."""
        await anyio.sleep(0)
        self.rows.append(record)
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """No prior chain."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Everything stored."""
        return list(self.rows)
        # end def

    # end class


class _RemoteSigner:
    """A signer whose latency is uneven, the shape of every remote one (§5.1 KMS).

    Wraps the real signer so the event is genuinely signed; only the waiting is simulated. Without
    it a local Ed25519 signer never yields, so nothing in the walk can reorder and §7.4's section
    would be exercised by no case at all.
    """

    def __init__(self, inner: Ed25519Signer) -> None:
        """Wrap the real signer and count the calls, to vary the wait."""
        self._inner = inner
        self._calls = 0
        # end def

    @property
    def key_id(self) -> str:
        """The wrapped signer's key, which names the sequence it advances."""
        return self._inner.key_id
        # end def

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Number first, then wait - which is the order a remote signer works in (§5.1).

        The AWS KMS adapter takes `signer_seq` and then awaits the service, so the number is fixed
        before the latency that can reorder the emission. Waiting first would number in wake order
        and reproduce nothing.
        """
        self._calls += 1
        # Captured before the await: reading the counter afterwards gives every caller the same
        # value on a runtime where awaiting the inner signer lets every other caller number first.
        wait = max(0.0, 0.060 - self._calls * 0.006)
        signed = await self._inner.sign(event, signer_seq)
        # Each later call waits less than every earlier one, so without §7.4's section the emission
        # order is exactly the reverse of the numbering - deterministically, not by chance.
        await anyio.sleep(wait)
        return signed
        # end def

    # end class


def _onboarded_key(key_id: str, private_key_b64: str) -> ToolKey:
    """Rebuild the key the registry was provisioned with (§5.1), or mint one if the walk is L1.

    The key travels as PKCS#8, which is the form the SDK pins.
    """
    if not private_key_b64:
        return generate_tool_key(key_id)
        # end if
    return load_tool_key(key_id, base64.b64decode(private_key_b64))
    # end def


def _settings() -> dict[str, object]:
    """Read the walk's knobs from the environment."""
    return {
        'level': Level.L2 if os.environ.get('WALK_LEVEL', 'L1') == 'L2' else Level.L1,
        'countersign': Countersign.HOST if os.environ.get('WALK_TOOL_COUNTERSIGN') == 'host' else Countersign.NONE,
        'posture': Posture.MANDATORY if os.environ.get('WALK_POSTURE') == 'mandatory' else Posture.DEGRADED,
        'operations': int(os.environ.get('WALK_OPERATIONS', '4')),
        'disclose_bytes': int(os.environ.get('WALK_DISCLOSE_BYTES', '0')),
        'die_after': int(os.environ.get('WALK_DIE_AFTER', '0')),
        'slow_signer': os.environ.get('WALK_SIGNER') == 'slow',
        'egress_every': int(os.environ.get('WALK_EGRESS_EVERY', '0')),
        'unreported_egress': int(os.environ.get('WALK_UNREPORTED_EGRESS', '0')),
        'key_id': os.environ.get('WALK_TOOL_KEY_ID', 'walk-tool-key'),
        'private_key': os.environ.get('WALK_TOOL_PRIVATE_KEY', ''),
        'high_level': os.environ.get('WALK_SERVER') == 'high-level',
    }
    # end def


class _WalkTool:
    """The walk's tool, independent of the transport it is served over."""

    def __init__(self) -> None:
        """Read the knobs, and build the key, the signer and the tool's own host."""
        self.settings = _settings()
        self.capability = AuditCapability(
            spec_version=SPEC_VERSION,
            level=self.settings['level'],  # type: ignore[arg-type]
            attempt='request',
            countersign=self.settings['countersign'],  # type: ignore[arg-type]
        )
        tool_key = _onboarded_key(str(self.settings['key_id']), str(self.settings['private_key']))
        signer: object | None = Ed25519Signer.from_tool_key(tool_key) if self.capability.level == Level.L2 else None
        if signer is not None and self.settings['slow_signer']:
            signer = _RemoteSigner(signer)  # type: ignore[arg-type]
            # end if
        self.signer = signer
        # The degraded posture records into a host the tool provides for itself (§6.2).
        local_registry = KeyRegistry()
        local_registry.register_tool_key(tool_key)
        self.local_host = AuditHost(
            'tool-local',
            self.capability.model_copy(update={'countersign': Countersign.NONE}),
            verifier=KeyRegistryVerifier(local_registry) if self.capability.level == Level.L2 else None,
            repository=_YieldingStore(),
        )
        # end def

    async def serve(self, call: McpAuditCall | None, params: Mapping[str, Any] | None) -> str:
        """Run the call's operations, audited by the host where the call is negotiated (§6.2).

        `call` is None for a call served outside the seam, which under Streamable HTTP is a call that
        carries no audit session; the tool takes the same posture for it as for any unnegotiated call.
        """
        settings = self.settings
        local_host = self.local_host
        negotiation = (
            call.negotiate(self.capability) if call is not None else negotiate_unaudited(params, self.capability)
        )
        fallback = InProcessTransport(local_host)
        transport = transport_for(
            negotiation,
            negotiated=call if call is not None else fallback,
            fallback=fallback,
            posture=settings['posture'],  # type: ignore[arg-type]
        )
        session_id = call.session_id if call is not None else new_session_id()
        if transport is not call:
            # The degraded posture: the tool is its own host, and issues the session itself (§6.3).
            local_host.open_session(session_id)
            # end if
        session = AmcpSession(transport, session_id, signer=self.signer)  # type: ignore[arg-type]

        disclose_bytes = int(settings['disclose_bytes'])  # type: ignore[arg-type]
        disclose = {'rows': 'x' * disclose_bytes} if disclose_bytes else None
        die_after = int(settings['die_after'])  # type: ignore[arg-type]
        done = 0

        egress_every = int(settings['egress_every'])  # type: ignore[arg-type]
        # The operations the tool performs but does not report as egress: §7.5's suppression by
        # omission, which only a boundary observation can catch.
        unreported = int(settings['unreported_egress'])  # type: ignore[arg-type]

        async def operation(n: int) -> None:
            nonlocal done
            egress = bool(egress_every) and n % egress_every == 0 and n >= unreported * egress_every
            async with session.action(
                'net.send' if egress else 'db.read',
                TargetResource(kind='endpoint' if egress else 'table', ref=f'customers_{n}'),
                mutates=False,
                egress=egress,
                disclose=disclose,
            ):
                # A real operation yields, which is where concurrent operations interleave.
                await anyio.sleep(0)
                done += 1
                if die_after and done >= die_after:
                    # The tool process dies with an attempt sealed and no outcome: the completeness
                    # gap §10.8 exists for, seen across a real process boundary.
                    os._exit(1)
                    # end if
                # end async with
            # end def

        try:
            async with anyio.create_task_group() as operations:
                for n in range(int(settings['operations'])):  # type: ignore[arg-type]
                    operations.start_soon(operation, n)
                    # end for
                # end async with
        finally:
            if transport is not call:
                await local_host.close_session(session_id)
                # end if
            # end try
        return (
            f'negotiated={negotiation.negotiated} outcome={negotiation.outcome} '
            f'local_records={len(local_host.records())} '
            f'local_verifies={verify_ledger(local_host.records()).ok} '
            f'local_anomalies={len(local_host.anomalies())}'
        )
        # end def

    def build(self, audit: McpAuditTransport | None) -> tuple[Server, InitializationOptions]:
        """The tool's server, serving its calls behind `audit`, or outside any seam when it is None."""
        if self.settings['high_level']:
            high_level = MCPServer('walk-tool')

            @high_level.tool(name=TOOL_NAME, description='read rows')
            async def read_customers(ctx: Context) -> str:
                context = ctx.request_context
                call = audit.call(context.request_id) if audit is not None else None
                return await self.serve(call, context.params)
                # end def

            # MCPServer has no public way to run on streams it is given, so the walk reaches for the
            # low-level server it wraps, as any tool behind this seam has to.
            lowlevel = high_level._lowlevel_server
            return lowlevel, lowlevel.create_initialization_options()
            # end if

        server: Server = Server('walk-tool')

        async def list_tools(_context: object, _params: types.PaginatedRequestParams) -> types.ListToolsResult:
            return types.ListToolsResult(
                tools=[types.Tool(name=TOOL_NAME, description='read rows', inputSchema={'type': 'object'})]
            )
            # end def

        async def call_tool(context: Any, _params: types.CallToolRequestParams) -> types.CallToolResult:
            call = audit.call(context.request_id) if audit is not None else None
            text = await self.serve(call, context.params)
            return types.CallToolResult(content=[types.TextContent(type='text', text=text)])
            # end def

        server.add_request_handler('tools/list', types.PaginatedRequestParams, list_tools)  # type: ignore[arg-type]
        server.add_request_handler('tools/call', types.CallToolRequestParams, call_tool)  # type: ignore[arg-type]
        options = InitializationOptions(
            server_name='walk-tool',
            server_version='0.0.0',
            capabilities=types.ServerCapabilities(tools=types.ToolsCapability()),
        )
        return server, options
        # end def

    # end class


async def _serve_stdio(tool: _WalkTool) -> None:
    """Serve one connection over stdio until the host disconnects."""
    async with stdio_server() as (read_stream, write_stream):
        async with McpAuditTransport(read_stream, write_stream, tool.capability) as audit:
            server, options = tool.build(audit)
            await server.run(audit.read_stream, audit.write_stream, options)
            # end async with
        # end async with
    # end def


def _peers(instance: str) -> str | None:
    """The endpoint of another instance of this deployment, from the file the runner keeps.

    Read at every lookup, because the runner learns the instances' ports only once they listen.
    """
    peers_file = os.environ.get('WALK_PEERS_FILE')
    if not peers_file or not Path(peers_file).is_file():
        return None
        # end if
    peers = json.loads(Path(peers_file).read_text(encoding='utf-8'))
    url = peers.get(instance) if isinstance(peers, dict) else None
    return url if isinstance(url, str) else None
    # end def


async def _serve_http(tool: _WalkTool) -> None:
    """Serve Streamable HTTP on an ephemeral loopback port until the process is stopped.

    Once it listens, the process writes one line `WALK_HTTP_URL=<url>` to stdout, which is how the runner
    finds it; the TypeScript walk tool does the same. `WALK_INSTANCE` names this instance in its round
    tokens, and with `WALK_PEERS_FILE` it forwards a retry it does not hold to the instance that does
    (§6.4 round affinity). It stops on SIGTERM or SIGINT, and when its stdin ends: the runner holds that
    pipe open for the life of the case, so a runner that dies does not leave the tool behind.
    """
    official, _options = tool.build(None)
    manager = StreamableHTTPSessionManager(official, json_response=True)
    forwarder = HttpForwarder(_peers) if os.environ.get('WALK_PEERS_FILE') else None
    entry = AuditedStreamableHTTP(
        manager,
        lambda seam: tool.build(seam)[0],
        tool.capability,
        instance=os.environ.get('WALK_INSTANCE') or None,
        forward=forwarder,
    )

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run(), entry.run():
            yield
            # end async with
        if forwarder is not None:
            await forwarder.aclose()
            # end if
        # end def

    app = Starlette(routes=[Route('/mcp', endpoint=entry)], lifespan=lifespan)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, lifespan='on', log_level='warning', timeout_graceful_shutdown=1))
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(server.serve, [sock])
        while not server.started:
            await anyio.sleep(0.01)
            # end while
        # The runner's handshake with this process, not a diagnostic: it reads this line off stdout.
        sys.stdout.write(f'{HTTP_URL_LINE}http://127.0.0.1:{port}/mcp\n')
        sys.stdout.flush()
        token = anyio.lowlevel.current_token()

        def stop_at_end_of_input() -> None:
            sys.stdin.buffer.read()
            anyio.from_thread.run_sync(setattr, server, 'should_exit', True, token=token)
            # end def

        # A daemon thread, so a blocking read never holds the process open once the server has stopped.
        threading.Thread(target=stop_at_end_of_input, daemon=True).start()
        # end async with
    # end def


async def main() -> None:
    """Serve one auditable tool over the transport `WALK_TRANSPORT` names: stdio, or http."""
    tool = _WalkTool()
    if os.environ.get('WALK_TRANSPORT') == 'http':
        await _serve_http(tool)
        return
        # end if
    await _serve_stdio(tool)
    # end def


if __name__ == '__main__':
    anyio.run(main)
    # end if
