"""An auditable MCP tool, served over real stdio, for the walk.

Not a test double: a separate process speaking the official stdio transport, so the walk exercises
real pipes, real framing, a real process boundary, and the §6 wire on top of all of it. The tool runs
several audited operations concurrently inside one `tools/call`, which is what §7.1 and §7.4 are for.

Run by `walk/run.py`; the level, the posture and the concurrency come from the environment so the
runner can drive the same tool through every configuration.
"""

import base64
import os

import anyio
import mcp.types as types
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.lowlevel import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

from auditable_mcp import (
    SPEC_VERSION,
    AmcpSession,
    AuditCapability,
    AuditHost,
    InProcessTransport,
    Level,
    Posture,
    TargetResource,
    Witness,
    transport_for,
)
from auditable_mcp.l2 import Ed25519Signer, KeyRegistry, KeyRegistryVerifier, ToolKey, generate_tool_key
from auditable_mcp.mcp import McpAuditTransport

TOOL_NAME = 'read_customers'


def _onboarded_key(key_id: str, private_key_b64: str) -> ToolKey:
    """Rebuild the key the registry was provisioned with (§5.1), or mint one if the walk is L1."""
    if not private_key_b64:
        return generate_tool_key(key_id)
        # end if
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


def _settings() -> dict[str, object]:
    """Read the walk's knobs from the environment."""
    return {
        'level': Level.L2 if os.environ.get('WALK_LEVEL', 'L1') == 'L2' else Level.L1,
        'witness': Witness.HOST if os.environ.get('WALK_WITNESS') == 'host' else Witness.NONE,
        'posture': Posture.MANDATORY if os.environ.get('WALK_POSTURE') == 'mandatory' else Posture.DEGRADED,
        'operations': int(os.environ.get('WALK_OPERATIONS', '4')),
        'disclose_bytes': int(os.environ.get('WALK_DISCLOSE_BYTES', '0')),
        'die_after': int(os.environ.get('WALK_DIE_AFTER', '0')),
        'key_id': os.environ.get('WALK_TOOL_KEY_ID', 'walk-tool-key'),
        'private_key': os.environ.get('WALK_TOOL_PRIVATE_KEY', ''),
    }
    # end def


async def main() -> None:
    """Serve one auditable tool over stdio until the host disconnects."""
    settings = _settings()
    capability = AuditCapability(
        spec_version=SPEC_VERSION,
        level=settings['level'],  # type: ignore[arg-type]
        attempt='request',
        witness=settings['witness'],  # type: ignore[arg-type]
    )
    tool_key = _onboarded_key(str(settings['key_id']), str(settings['private_key']))
    signer = Ed25519Signer.from_tool_key(tool_key) if capability.level == Level.L2 else None

    # The degraded posture records into a host the tool provides for itself (§6.2).
    local_registry = KeyRegistry()
    local_registry.register_tool_key(tool_key)
    local_host = AuditHost(
        'tool-local',
        AuditCapability(spec_version=SPEC_VERSION, level=capability.level, attempt='request', witness=Witness.NONE),
        verifier=KeyRegistryVerifier(local_registry) if capability.level == Level.L2 else None,
    )

    server: Server = Server('walk-tool')

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=TOOL_NAME, description='read rows', inputSchema={'type': 'object'})]
        # end def

    async with stdio_server() as (read_stream, write_stream):
        async with McpAuditTransport(read_stream, write_stream, capability) as audit:

            @server.call_tool(validate_input=False)
            async def call_tool(name: str, arguments: dict[str, object]) -> list[types.TextContent]:
                negotiation = audit.negotiate(capability)
                transport = transport_for(
                    negotiation,
                    negotiated=audit,
                    fallback=InProcessTransport(local_host),
                    posture=settings['posture'],  # type: ignore[arg-type]
                )
                session = AmcpSession(transport, str(arguments.get('call_id', 'call')), signer=signer)

                disclose_bytes = int(settings['disclose_bytes'])  # type: ignore[arg-type]
                disclose = {'rows': 'x' * disclose_bytes} if disclose_bytes else None
                die_after = int(settings['die_after'])  # type: ignore[arg-type]
                done = 0

                async def operation(n: int) -> None:
                    nonlocal done
                    async with session.action(
                        'db.read',
                        TargetResource(kind='table', ref=f'customers_{n}'),
                        mutates=False,
                        egress=False,
                        disclose=disclose,
                    ):
                        # A real operation yields; this is where the reordering used to happen.
                        await anyio.sleep(0)
                        done += 1
                        if die_after and done >= die_after:
                            # The tool process dies with an attempt sealed and no outcome: the
                            # completeness gap §10.8 exists for, seen across a real process boundary.
                            os._exit(1)
                            # end if
                        # end async with
                    # end def

                async with anyio.create_task_group() as operations:
                    for n in range(int(settings['operations'])):  # type: ignore[arg-type]
                        operations.start_soon(operation, n)
                        # end for
                    # end async with
                return [
                    types.TextContent(
                        type='text',
                        text=f'negotiated={negotiation.negotiated} outcome={negotiation.outcome} '
                        f'local_records={len(local_host.records())}',
                    )
                ]
                # end def

            options = InitializationOptions(
                server_name='walk-tool',
                server_version='0.0.0',
                capabilities=types.ServerCapabilities(tools=types.ToolsCapability()),
            )
            await server.run(audit.read_stream, audit.write_stream, options)
            # end async with
        # end async with
    # end def


if __name__ == '__main__':
    anyio.run(main)
    # end if
