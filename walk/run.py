"""Drive the auditable tool over a real stdio pipe and check what the ledger holds.

The suite runs everything in one process over memory streams. This does not: the tool is a separate
process, the wire is a real pipe, and the host is the official MCP client with an `McpAuditReceiver`
in front of it. What the walk is for is the failure modes that only exist across that boundary -
framing, back-pressure, process lifetime, and a tool whose operations really are concurrent.

Each case states what it expects of the ledger, not of the SDK's internals, so a case that fails
names a fact about the audit trail.

    python walk/run.py            # every case
    python walk/run.py degraded   # the cases whose name contains `degraded`
"""

from __future__ import annotations

import base64
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import anyio
from cryptography.hazmat.primitives import serialization
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from auditable_mcp import (
    SPEC_VERSION,
    AuditCapability,
    AuditHost,
    Level,
    RepositoryError,
    SealedRecord,
    Witness,
    verify_ledger,
)
from auditable_mcp.l2 import (
    Ed25519WitnessSigner,
    KeyRegistry,
    KeyRegistryVerifier,
    KeyRole,
    ToolKey,
    generate_tool_key,
)
from auditable_mcp.mcp import McpAuditReceiver, capability_of

TOOL = Path(__file__).with_name('tool_server.py')
TS_TOOL = Path(__file__).resolve().parents[2] / 'auditable-mcp-sdk-ts' / 'walk' / 'tool-server.ts'
OPERATIONS = 4


class _Store:
    """A durable repository whose write yields, which is where §7.1's window used to open.

    `fail_after` makes it stop accepting writes partway, the way a store that has gone away does. A
    host that cannot persist replies `unavailable` (§7.1) and the tool fails closed.
    """

    def __init__(self, fail_after: int = 0) -> None:
        """Start empty, optionally failing once `fail_after` records are stored."""
        self.rows: list[SealedRecord] = []
        self._fail_after = fail_after
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Yield, then store - or refuse, once the store has been told to go away."""
        await anyio.sleep(0)
        if self._fail_after and len(self.rows) >= self._fail_after:
            raise RepositoryError('the store went away')
            # end if
        self.rows.append(record)
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """No prior chain for a fresh walk."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Everything stored, in append order."""
        return list(self.rows)
        # end def

    # end class


@dataclass
class Case:
    """One configuration of the tool, and what its audit trail must show."""

    name: str
    environment: dict[str, str]
    # The tool under test. The default is this SDK's; the cross-language cases name the other port's,
    # which proves the wire interoperates rather than that one implementation agrees with itself.
    tool: str = 'python'
    host_level: Level = Level.L1
    host_witness: Witness = Witness.NONE
    audited: bool = True
    expect_negotiated: bool = True
    expect_records: int = OPERATIONS * 2
    expect_local_records: int = 0
    calls: int = 1
    sequential_calls: int = 1
    host_fails_after: int = 0
    expect_local_verifies: bool = True
    expect_call_error: bool = False
    expect_tool_death: bool = False
    death: str = ''
    findings: list[str] = field(default_factory=list)

    # end class


CASES: list[Case] = [
    Case('l1-negotiated', {'WALK_LEVEL': 'L1'}),
    Case('l2-negotiated', {'WALK_LEVEL': 'L2'}, host_level=Level.L2),
    Case(
        'l2-witnessed',
        {'WALK_LEVEL': 'L2', 'WALK_WITNESS': 'host'},
        host_level=Level.L2,
        host_witness=Witness.HOST,
    ),
    Case(
        'degraded-host-does-not-speak-it',
        {'WALK_LEVEL': 'L2'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=OPERATIONS * 2,
    ),
    Case(
        'l2-thirty-two-concurrent-operations',
        {'WALK_LEVEL': 'L2', 'WALK_OPERATIONS': '32'},
        host_level=Level.L2,
        expect_records=64,
    ),
    Case(
        'l2-two-concurrent-tool-calls',
        {'WALK_LEVEL': 'L2'},
        host_level=Level.L2,
        calls=2,
        expect_records=OPERATIONS * 2 * 2,
    ),
    Case(
        'l2-a-large-disclosed-context',
        {'WALK_LEVEL': 'L2', 'WALK_DISCLOSE_BYTES': '200000'},
        host_level=Level.L2,
    ),
    Case(
        'the-tool-dies-mid-call',
        {'WALK_LEVEL': 'L2', 'WALK_DIE_AFTER': '2'},
        host_level=Level.L2,
        expect_records=-1,
        expect_tool_death=True,
    ),
    Case(
        'mandatory-refuses-an-unaudited-host',
        {'WALK_LEVEL': 'L1', 'WALK_POSTURE': 'mandatory'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_call_error=True,
    ),
    Case(
        'a-tool-that-requires-a-witness-will-not-degrade',
        {'WALK_LEVEL': 'L1', 'WALK_TOOL_WITNESS': 'host', 'WALK_POSTURE': 'mandatory'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_call_error=True,
    ),
    Case(
        'a-witnessing-host-satisfies-a-tool-that-requires-one',
        {'WALK_LEVEL': 'L1', 'WALK_TOOL_WITNESS': 'host'},
        host_witness=Witness.HOST,
    ),
    Case(
        'a-long-lived-connection',
        {'WALK_LEVEL': 'L2'},
        host_level=Level.L2,
        sequential_calls=20,
        expect_records=OPERATIONS * 2 * 20,
    ),
    Case(
        'the-host-stops-persisting-mid-connection',
        {'WALK_LEVEL': 'L1'},
        sequential_calls=3,
        host_fails_after=OPERATIONS,
        expect_records=-1,
        expect_call_error=True,
    ),
    Case(
        'degraded-concurrency-in-the-tools-own-host',
        {'WALK_LEVEL': 'L1', 'WALK_OPERATIONS': '16'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=32,
    ),
    Case(
        'l2-with-a-remote-signer',
        {'WALK_LEVEL': 'L2', 'WALK_SIGNER': 'slow', 'WALK_OPERATIONS': '8'},
        host_level=Level.L2,
        expect_records=16,
    ),
    Case('crosslang-ts-tool-l1', {'WALK_LEVEL': 'L1'}, tool='typescript'),
    Case('crosslang-ts-tool-l2', {'WALK_LEVEL': 'L2'}, tool='typescript', host_level=Level.L2),
    Case(
        'crosslang-ts-tool-l2-witnessed',
        {'WALK_LEVEL': 'L2', 'WALK_WITNESS': 'host'},
        tool='typescript',
        host_level=Level.L2,
        host_witness=Witness.HOST,
    ),
    Case(
        'crosslang-ts-tool-degraded',
        {'WALK_LEVEL': 'L2'},
        tool='typescript',
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=OPERATIONS * 2,
    ),
    Case(
        'crosslang-ts-tool-degraded-concurrency',
        {'WALK_LEVEL': 'L1', 'WALK_OPERATIONS': '16'},
        tool='typescript',
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=32,
    ),
    Case(
        'crosslang-ts-tool-remote-signer',
        {'WALK_LEVEL': 'L2', 'WALK_SIGNER': 'slow', 'WALK_OPERATIONS': '8'},
        tool='typescript',
        host_level=Level.L2,
        expect_records=16,
    ),
    Case(
        'degraded-host-requires-a-higher-level',
        {'WALK_LEVEL': 'L1'},
        host_level=Level.L2,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=OPERATIONS * 2,
    ),
]


def _onboard() -> tuple[ToolKey, str]:
    """Mint the tool's key here and hand out each half, the way onboarding does (§5.1)."""
    key = generate_tool_key('walk-tool-key')
    private_bytes = key.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, base64.b64encode(private_bytes).decode('ascii')
    # end def


def _host(case: Case, tool_key: ToolKey) -> tuple[AuditHost, _Store]:
    """Build the host this case declares, durable and (where asked) witnessing."""
    store = _Store(case.host_fails_after)
    capability = AuditCapability(
        spec_version=SPEC_VERSION, level=case.host_level, attempt='request', witness=case.host_witness
    )
    registry = KeyRegistry(KeyRole.TOOL)
    registry.register_tool_key(tool_key)
    verifier = KeyRegistryVerifier(registry) if case.host_level == Level.L2 else None
    witness_key = generate_tool_key('walk-host-key')
    signer = Ed25519WitnessSigner(witness_key.key_id, witness_key.private_key)
    host = AuditHost(
        'tenant-walk',
        capability,
        verifier=verifier,
        witness_signer=signer if case.host_witness == Witness.HOST else None,
        repository=store,
    )
    return host, store
    # end def


async def _run(case: Case) -> Case:
    """Start the tool, call it, and read the ledger it wrote."""
    tool_key, private_key_b64 = _onboard()
    host, store = _host(case, tool_key)
    command, args = (sys.executable, [str(TOOL)])
    if case.tool == 'typescript':
        command, args = ('npx', ['tsx', str(TS_TOOL)])
        # end if
    parameters = StdioServerParameters(
        command=command,
        args=args,
        env={
            **os.environ,
            'WALK_OPERATIONS': str(OPERATIONS),
            'WALK_TOOL_KEY_ID': tool_key.key_id,
            'WALK_TOOL_PRIVATE_KEY': private_key_b64,
            **case.environment,
        },
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        try:
            if case.audited:
                async with McpAuditReceiver(read_stream, write_stream, host) as receiver:
                    await _call(case, receiver.read_stream, receiver.write_stream, host)
                    # end async with
            else:
                await _call(case, read_stream, write_stream, host)
                # end if
        except BaseException as error:  # noqa: BLE001 - a dying tool takes the session with it
            if not case.expect_tool_death:
                raise
                # end if
            case.death = case.death or repr(error)[:120]
            # end try
        # end async with

    records = host.records()
    if case.expect_records >= 0 and len(records) != case.expect_records:
        case.findings.append(f'ledger holds {len(records)} records, expected {case.expect_records}')
        # end if
    if case.expect_tool_death:
        if not case.death:
            case.findings.append('the tool was supposed to die and the call returned normally')
            # end if
        attempts = [r for r in records if r.event.get('outcome') == 'attempted']
        outcomes = [r for r in records if r.event.get('outcome') != 'attempted']
        if len(attempts) <= len(outcomes):
            case.findings.append(
                f'no completeness gap was left behind: {len(attempts)} attempts, {len(outcomes)} outcomes'
            )
            # end if
        # end if
    if records:
        report = verify_ledger(records, host.digest())
        if not report.ok:
            case.findings.append(f'ledger does not verify: {[issue.kind for issue in report.issues]}')
            # end if
        if host.anomalies():
            case.findings.append(
                f'anomalies against a tool that did nothing wrong: {[a.kind for a in host.anomalies()]}'
            )
            # end if
        seqs = [record.seq for record in records]
        if seqs != sorted(set(seqs)):
            case.findings.append(f'two records share a position (§7.1): {seqs}')
            # end if
        if case.host_witness == Witness.HOST and any(r.host_signature is None for r in records):
            case.findings.append('a witnessing host left a record unsigned (§7.1)')
            # end if
        if [row.record_hash for row in store.rows] != [record.record_hash for record in records]:
            case.findings.append('the durable store and the in-memory chain disagree')
            # end if
        # end if
    return case
    # end def


async def _call(case: Case, read_stream: object, write_stream: object, host: AuditHost) -> None:
    """Initialize, read the tool's declaration, and call it once."""
    async with ClientSession(read_stream, write_stream) as session:  # type: ignore[arg-type]
        result = await session.initialize()
        declared = capability_of(result.capabilities)
        if case.audited and declared is None:
            case.findings.append('the tool declared nothing at initialize (§6.1)')
            # end if
        if not case.audited and declared is None:
            case.findings.append('the tool declared nothing even for an unaudited host (§6.1)')
            # end if
        tools = await session.list_tools()
        if [tool.name for tool in tools.tools] != ['read_customers']:
            case.findings.append('ordinary MCP changed because this extension is present (§6.2)')
            # end if
        results: list[object] = []

        async def one_call(n: int) -> None:
            results.append(await session.call_tool('read_customers', {'call_id': f'walk-call-{n}'}))
            # end def

        try:
            for _round in range(case.sequential_calls):
                async with anyio.create_task_group() as calls:
                    for n in range(case.calls):
                        calls.start_soon(one_call, n)
                        # end for
                    # end async with
                # end for
        except BaseException as error:  # noqa: BLE001 - the tool process may be gone
            if not (case.expect_tool_death or case.expect_call_error):
                raise
                # end if
            case.death = repr(error)[:120]
            # end try
        if case.expect_call_error and not any(getattr(call, 'isError', False) for call in results) and not case.death:
            case.findings.append('the call was supposed to fail and it did not')
            # end if
        for call in results:
            text = ''.join(block.text for block in call.content if hasattr(block, 'text'))  # type: ignore[attr-defined]
            if call.isError:  # type: ignore[attr-defined]
                if not case.expect_call_error:
                    case.findings.append(f'the tool call failed: {text}')
                    # end if
                continue
                # end if
            if f'negotiated={case.expect_negotiated}' not in text:
                case.findings.append(f'negotiation was not {case.expect_negotiated}: {text}')
                # end if
            if f'local_records={case.expect_local_records}' not in text:
                case.findings.append(f'the tool-local ledger is not {case.expect_local_records}: {text}')
                # end if
            if case.expect_local_records and f'local_verifies={case.expect_local_verifies}' not in text:
                case.findings.append(f"the tool's own ledger does not verify: {text}")
                # end if
            if case.expect_local_records and 'local_anomalies=0' not in text:
                case.findings.append(f"the tool's own ledger holds anomalies: {text}")
                # end if
            # end for
        await session.send_ping()
        # end async with
    # end def


async def main(selectors: Sequence[str]) -> int:
    """Run the selected cases and report what the ledgers showed."""
    chosen = [case for case in CASES if not selectors or any(s in case.name for s in selectors)]
    if any(case.tool == 'typescript' for case in chosen) and not TS_TOOL.exists():
        print(f'skipping the cross-language cases: {TS_TOOL} is not checked out')
        chosen = [case for case in chosen if case.tool != 'typescript']
        # end if
    failures = 0
    for case in chosen:
        with anyio.move_on_after(120) as scope:
            try:
                await _run(case)
            except BaseException as error:  # noqa: BLE001 - a case must report, not end the walk
                case.findings.append(f'the case raised: {type(error).__name__}: {error}'[:200])
                # end try
            # end with
        if scope.cancelled_caught:
            case.findings.append('timed out after 120s')
            # end if
        mark = '  ok  ' if not case.findings else 'FINDING'
        print(f'[{mark}] {case.name}')
        for finding in case.findings:
            print(f'          - {finding}')
            failures += 1
            # end for
        # end for
    print(f'\n{len(chosen)} cases, {failures} findings')
    return 1 if failures else 0
    # end def


if __name__ == '__main__':
    sys.exit(anyio.run(main, sys.argv[1:]))
    # end if
