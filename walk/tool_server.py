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
    SealedRecord,
    TargetResource,
    Witness,
    transport_for,
    verify_ledger,
)
from auditable_mcp.l2 import Ed25519Signer, KeyRegistry, KeyRegistryVerifier, ToolKey, generate_tool_key
from auditable_mcp.mcp import McpAuditTransport

TOOL_NAME = 'read_customers'


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

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Number first, then wait - which is the order a remote signer works in (§5.1).

        The AWS KMS adapter takes `signer_seq` and then awaits the service, so the number is fixed
        before the latency that can reorder the emission. Waiting first would number in wake order
        and reproduce nothing.
        """
        self._calls += 1
        # Captured before the await: reading the counter afterwards gives every caller the same
        # value on a runtime where awaiting the inner signer lets every other caller number first.
        wait = max(0.0, 0.060 - self._calls * 0.006)
        signed = await self._inner.sign(event)
        # Each later call waits less than every earlier one, so without §7.4's section the emission
        # order is exactly the reverse of the numbering - deterministically, not by chance.
        await anyio.sleep(wait)
        return signed
        # end def

    # end class


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
        'witness': Witness.HOST if os.environ.get('WALK_TOOL_WITNESS') == 'host' else Witness.NONE,
        'posture': Posture.MANDATORY if os.environ.get('WALK_POSTURE') == 'mandatory' else Posture.DEGRADED,
        'operations': int(os.environ.get('WALK_OPERATIONS', '4')),
        'disclose_bytes': int(os.environ.get('WALK_DISCLOSE_BYTES', '0')),
        'die_after': int(os.environ.get('WALK_DIE_AFTER', '0')),
        'slow_signer': os.environ.get('WALK_SIGNER') == 'slow',
        'start_signer_seq': int(os.environ.get('WALK_START_SIGNER_SEQ', '0')),
        'egress_every': int(os.environ.get('WALK_EGRESS_EVERY', '0')),
        'unreported_egress': int(os.environ.get('WALK_UNREPORTED_EGRESS', '0')),
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
    signer: object | None = (
        Ed25519Signer.from_tool_key(tool_key, start_signer_seq=int(settings['start_signer_seq']))  # type: ignore[arg-type]
        if capability.level == Level.L2
        else None
    )
    if signer is not None and settings['slow_signer']:
        signer = _RemoteSigner(signer)
        # end if

    # The degraded posture records into a host the tool provides for itself (§6.2).
    local_registry = KeyRegistry()
    local_registry.register_tool_key(tool_key)
    local_host = AuditHost(
        'tool-local',
        AuditCapability(spec_version=SPEC_VERSION, level=capability.level, attempt='request', witness=Witness.NONE),
        verifier=KeyRegistryVerifier(local_registry) if capability.level == Level.L2 else None,
        repository=_YieldingStore(),
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

                egress_every = int(settings['egress_every'])  # type: ignore[arg-type]
                # The operations the tool performs but does not report as egress: §7.5's suppression
                # by omission, which only a boundary observation can catch.
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
                        f'local_records={len(local_host.records())} '
                        f'local_verifies={verify_ledger(local_host.records()).ok} '
                        f'local_anomalies={len(local_host.anomalies())}',
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
