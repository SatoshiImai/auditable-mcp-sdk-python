"""Drive the auditable tool over a real stdio pipe and check what the ledger holds.

The suite runs everything in one process over memory streams. This does not: the tool is a separate
process, the wire is a real pipe, and the host is the official MCP client with an `McpAuditReceiver`
in front of it. What the walk is for is the failure modes that only exist across that boundary -
framing, back-pressure, process lifetime, and a tool whose operations really are concurrent.

Each case states what it expects of the ledger, not of the SDK's internals, so a case that fails
names a fact about the audit trail. Every case runs under MCP 2026-07-28, where the exchange rides the
call as Multi Round-Trip Requests (§6.4); the cases suffixed `-initialize` run it again under the
`initialize` handshake (§6.5).

    python walk/run.py            # every case
    python walk/run.py degraded   # the cases whose name contains `degraded`

`WALK_TRANSPORT=http` runs the §6.4 cases over Streamable HTTP instead: each tool process serves
`AuditedStreamableHTTP` on a loopback port, and the host is the official Streamable HTTP client. The
`-initialize` cases are not run there (§6.5 over HTTP is outside this binding), and the `http-` cases
run only there: two tool processes behind a router that steers each request, which is the deployment
round affinity exists for (§6.4). A tool under `WALK_TRANSPORT=http` writes one line
`WALK_HTTP_URL=<url>` to stdout once it listens, which is the contract the TypeScript walk tool keeps
too; the cross-language cases run over HTTP with `WALK_TS_HTTP=1`, against the checkout `WALK_TS_REPO`
names. `WALK_INSTANCE` and `WALK_PEERS_FILE` (the instances' URLs, as a JSON object) are read only by
this SDK's tool, which is the one the two-instance cases run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

import anyio
import anyio.abc
import httpx2
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from auditable_mcp import (
    SPEC_VERSION,
    AuditCapability,
    AuditHost,
    Countersign,
    Level,
    RepositoryError,
    SealedRecord,
    verify_ledger,
)
from auditable_mcp.l2 import (
    Ed25519Countersigner,
    EgressObservation,
    KeyRegistry,
    KeyRegistryVerifier,
    KeyRole,
    ToolKey,
    generate_tool_key,
    reconcile,
    tool_key_pkcs8,
)
from auditable_mcp.mcp import AFFINITY_HEADER, ROUND_TOKEN_PREFIX, McpAuditReceiver, capability_of

TOOL = Path(__file__).with_name('tool_server.py')
# `WALK_TS_REPO` points the cross-language cases at another checkout of the TypeScript SDK (a worktree).
TS_REPO = Path(os.environ.get('WALK_TS_REPO') or Path(__file__).resolve().parents[2] / 'auditable-mcp-sdk-ts')
TS_TOOL = TS_REPO / 'walk' / 'tool-server.ts'
HTTP_URL_LINE = 'WALK_HTTP_URL='
OPERATIONS = 4
# How long a tool may take to exit once the host closes the pipe. The MCP client terminates a server
# that has not exited after 2s, so a tool that waits for that is caught below it.
TOOL_EXIT_BOUND = 1.5
HTTP = os.environ.get('WALK_TRANSPORT') == 'http'
TS_HTTP = os.environ.get('WALK_TS_HTTP') == '1'
# How long a tool process may take to listen, and the bound on each HTTP exchange.
HTTP_START_BOUND = 20.0
HTTP_TIMEOUT = 30.0
# How long a tool process is given to stop on SIGTERM before it is killed.
TOOL_STOP_BOUND = 5.0


class _Store:
    """A durable repository whose write yields, which is where §7.1's window opens.

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
    host_countersign: Countersign = Countersign.NONE
    audited: bool = True
    expect_negotiated: bool = True
    expect_records: int = OPERATIONS * 2
    expect_local_records: int = 0
    calls: int = 1
    sequential_calls: int = 1
    host_fails_after: int = 0
    expect_local_verifies: bool = True
    # Restart the host from its persisted chain between calls, the way a deployment restarts (§7.1).
    resume_after_call: int = 0
    # Connections opened at once, each its own tool process sharing one key. §7.4 numbers per session,
    # so they share nothing and need nothing between them.
    concurrent_connections: int = 1
    # Destinations the boundary observed; §7.5 flags any the tool did not report (§7.6).
    observed_egress: tuple[str, ...] = ()
    expect_unreported: int = 0
    expect_call_error: bool = False
    expect_tool_death: bool = False
    # The call ends with an attempt the host accepted and never saw resolved, through no fault of the
    # tool: the host records it `unresolved-attempt` (§6.3), and must.
    expect_unresolved: bool = False
    # MCP 2026-07-28 and §6.4, or the `initialize` handshake and §6.5.
    modern: bool = True
    # Over HTTP: how many tool processes serve the deployment, how the client's requests are routed
    # among them (`misroute` sends every retry to an instance other than the one that opened the call,
    # `affinity` hashes `Auditable-Mcp-Session`), and whether the instances forward to each other.
    instances: int = 1
    route: str = ''
    forward: bool = False
    http_only: bool = False
    death: str = ''
    findings: list[str] = field(default_factory=list)

    # end class


CASES: list[Case] = [
    Case('l1-negotiated', {'WALK_LEVEL': 'L1'}),
    Case(
        # §7.4 across a process boundary: every call is a session numbered from zero, so a tool that
        # restarts has nothing to recover and nothing to collide with.
        'l2-the-tool-restarts-between-calls',
        {'WALK_LEVEL': 'L2', 'WALK_OPERATIONS': '2'},
        host_level=Level.L2,
        sequential_calls=2,
        resume_after_call=1,
        expect_records=8,
    ),
    Case(
        # Two connections at once, each its own tool process, one key, one host: nothing is shared.
        'l2-two-tool-processes-share-one-key',
        {'WALK_LEVEL': 'L2', 'WALK_OPERATIONS': '2'},
        host_level=Level.L2,
        concurrent_connections=2,
        expect_records=8,
    ),
    Case('l2-negotiated', {'WALK_LEVEL': 'L2'}, host_level=Level.L2),
    Case(
        # The official high-level `MCPServer` hands its handlers `str(request_id)`; the seam has to find
        # the call from that, across two concurrent calls, or every call fails before it is audited.
        'l2-high-level-mcpserver',
        {'WALK_LEVEL': 'L2', 'WALK_SERVER': 'high-level'},
        host_level=Level.L2,
        calls=2,
        expect_records=OPERATIONS * 2 * 2,
    ),
    Case(
        'degraded-high-level-mcpserver',
        {'WALK_LEVEL': 'L1', 'WALK_SERVER': 'high-level'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_local_records=OPERATIONS * 2,
    ),
    Case(
        'l2-countersigned',
        {'WALK_LEVEL': 'L2'},
        host_level=Level.L2,
        host_countersign=Countersign.HOST,
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
        # The degraded posture is the default, so this is the case the guard exists for: the tool's
        # own host holds no key a verifier's registry binds to a host, and every action would abort
        # `host-uncountersigned` while the tool went on serving (§5.2, §6.2).
        'a-tool-that-requires-a-countersignature-refuses-to-degrade',
        {'WALK_LEVEL': 'L1', 'WALK_TOOL_COUNTERSIGN': 'host'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_call_error=True,
    ),
    Case(
        'a-tool-that-requires-a-countersignature-may-still-refuse-to-serve',
        {'WALK_LEVEL': 'L1', 'WALK_TOOL_COUNTERSIGN': 'host', 'WALK_POSTURE': 'mandatory'},
        audited=False,
        expect_negotiated=False,
        expect_records=0,
        expect_call_error=True,
    ),
    Case(
        'a-countersigning-host-satisfies-a-tool-that-requires-one',
        {'WALK_LEVEL': 'L1', 'WALK_TOOL_COUNTERSIGN': 'host'},
        host_countersign=Countersign.HOST,
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
    Case(
        'the-host-restarts-mid-connection',
        {'WALK_LEVEL': 'L2'},
        host_level=Level.L2,
        sequential_calls=4,
        resume_after_call=2,
        expect_records=OPERATIONS * 2 * 4,
    ),
    Case(
        'crosslang-ts-tool-the-host-restarts',
        {'WALK_LEVEL': 'L2'},
        tool='typescript',
        host_level=Level.L2,
        sequential_calls=4,
        resume_after_call=2,
        expect_records=OPERATIONS * 2 * 4,
    ),
    Case(
        'the-boundary-sees-what-the-tool-reported',
        {'WALK_LEVEL': 'L1', 'WALK_EGRESS_EVERY': '2'},
        observed_egress=('customers_0', 'customers_2'),
    ),
    Case(
        'the-boundary-sees-an-egress-the-tool-never-reported',
        {'WALK_LEVEL': 'L1', 'WALK_EGRESS_EVERY': '2', 'WALK_UNREPORTED_EGRESS': '1'},
        observed_egress=('customers_0', 'customers_2'),
        expect_unreported=1,
    ),
    Case('crosslang-ts-tool-l1', {'WALK_LEVEL': 'L1'}, tool='typescript'),
    Case('crosslang-ts-tool-l2', {'WALK_LEVEL': 'L2'}, tool='typescript', host_level=Level.L2),
    Case(
        'crosslang-ts-tool-l2-countersigned',
        {'WALK_LEVEL': 'L2'},
        tool='typescript',
        host_level=Level.L2,
        host_countersign=Countersign.HOST,
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

# The same cases under the `initialize` handshake (§6.5). The cross-language ones included: two ports
# have to agree on both bindings, not on one.
CASES += [replace(case, name=f'{case.name}-initialize', modern=False, findings=[]) for case in CASES]

# Round affinity (§6.4), which only a deployment of several instances exercises.
CASES += [
    Case(
        # Every retry lands on the other instance, which forwards it to the one that holds the round.
        'http-a-retry-that-reaches-another-instance-is-forwarded',
        {'WALK_LEVEL': 'L2', 'WALK_OPERATIONS': '2'},
        host_level=Level.L2,
        expect_records=8,
        sequential_calls=2,
        instances=2,
        route='misroute',
        forward=True,
        http_only=True,
    ),
    Case(
        # A router that reads nothing but the affinity header keeps each call on one instance.
        'http-an-intermediary-routes-on-the-affinity-header',
        {'WALK_LEVEL': 'L2', 'WALK_OPERATIONS': '2'},
        host_level=Level.L2,
        expect_records=4 * 6,
        sequential_calls=6,
        instances=2,
        route='affinity',
        http_only=True,
    ),
    Case(
        # Misrouted and not forwarded: the retry is refused and the tool performs nothing (§10.11).
        'http-a-misrouted-retry-without-forwarding-fails-closed',
        {'WALK_LEVEL': 'L1', 'WALK_OPERATIONS': '1'},
        expect_records=1,
        expect_call_error=True,
        expect_unresolved=True,
        instances=2,
        route='misroute',
        http_only=True,
    ),
]


def _onboard() -> tuple[ToolKey, str]:
    """Mint the tool's key here and hand out each half, the way onboarding does (§5.1).

    The private half travels as PKCS#8, the form the SDK pins.
    """
    key = generate_tool_key('walk-tool-key')
    return key, base64.b64encode(tool_key_pkcs8(key)).decode('ascii')
    # end def


def _host(case: Case, tool_key: ToolKey) -> tuple[AuditHost, _Store]:
    """Build the host this case declares, durable and (where asked) countersigning."""
    store = _Store(case.host_fails_after)
    capability = AuditCapability(
        spec_version=SPEC_VERSION, level=case.host_level, attempt='request', countersign=case.host_countersign
    )
    registry = KeyRegistry(KeyRole.TOOL)
    registry.register_tool_key(tool_key)
    verifier = KeyRegistryVerifier(registry) if case.host_level == Level.L2 else None
    countersign_key = generate_tool_key('walk-host-key')
    signer = Ed25519Countersigner(countersign_key.key_id, countersign_key.private_key)
    host = AuditHost(
        'tenant-walk',
        capability,
        verifier=verifier,
        countersigner=signer if case.host_countersign == Countersign.HOST else None,
        repository=store,
    )
    return host, store
    # end def


def _leaves(error: BaseException) -> str:
    """The exceptions that actually failed, flattened out of any groups around them."""
    if isinstance(error, BaseExceptionGroup):
        return '; '.join(_leaves(inner) for inner in error.exceptions)
        # end if
    return f'{type(error).__name__}: {error}'
    # end def


async def _run(case: Case) -> Case:
    """Start the tool, call it, and read the ledger it wrote.

    A case with `resume_after_call` runs two connections against one store: the host is torn down
    after the first and rebuilt from its persisted chain for the second, which is what a restart is.
    The chain has to continue across it - the same `seq` counter, the same tail link - or the walk
    is not watching the thing §7.1's durable lifecycle exists for.
    """
    tool_key, private_key_b64 = _onboard()
    host, store = _host(case, tool_key)
    segments = (
        [case.resume_after_call, case.sequential_calls - case.resume_after_call]
        if case.resume_after_call
        else [case.sequential_calls]
    )
    for index, calls in enumerate(segments):
        if index:
            host = await _resumed(case, host, store, tool_key)
            # end if
        if case.concurrent_connections > 1:
            async with anyio.create_task_group() as connections:
                for _ in range(case.concurrent_connections):
                    connections.start_soon(_connect, case, host, tool_key, private_key_b64, calls)
                    # end for
                # end async with
        else:
            await _connect(case, host, tool_key, private_key_b64, calls)
            # end if
        # end for

    # The chain the walk reads is the persisted one. Falling back to this process's in-memory records
    # when the store is empty would let a host that never wrote anything pass every case.
    records = store.rows
    case.findings.extend(_signer_seq_gaps(store))
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
        # §6.3: the host observes the call's end, here as the connection's, and records what the tool
        # never resolved. That it does so is the point of the case, not a finding against the tool.
        if 'unresolved-attempt' not in {anomaly.kind for anomaly in host.anomalies()}:
            case.findings.append('the host did not record the attempt the tool never resolved (§6.3)')
            # end if
        # end if
    if records:
        report = verify_ledger(records, host.digest())
        if not report.ok:
            case.findings.append(f'ledger does not verify: {[issue.kind for issue in report.issues]}')
            # end if
        # An attempt left unresolved is what the host must record when the tool died, or when the host
        # itself lost the outcome it could not persist (§6.3, §10.8); neither is the tool's doing.
        tolerated = case.expect_tool_death or bool(case.host_fails_after) or case.expect_unresolved
        if case.expect_unresolved and 'unresolved-attempt' not in {anomaly.kind for anomaly in host.anomalies()}:
            case.findings.append('the host did not record the attempt the call left unresolved (§6.3)')
            # end if
        unexpected = [a.kind for a in host.anomalies() if not (tolerated and a.kind == 'unresolved-attempt')]
        if unexpected:
            case.findings.append(f'anomalies against a tool that did nothing wrong: {unexpected}')
            # end if
        seqs = [record.seq for record in records]
        if seqs != sorted(set(seqs)):
            case.findings.append(f'two records share a position (§7.1): {seqs}')
            # end if
        if case.host_countersign == Countersign.HOST and any(r.host_signature is None for r in records):
            case.findings.append('a countersigning host left a record unsigned (§7.1)')
            # end if
        if case.observed_egress:
            # The boundary saw the one call, under the session the host issued for it (§6.3).
            session_id = str(records[0].event['session_id'])
            observations = [EgressObservation(session_id=session_id, destination=ref) for ref in case.observed_egress]
            anomalies = reconcile(records, observations, session_id)
            if len(anomalies) != case.expect_unreported:
                case.findings.append(
                    f'§7.5 reconciliation found {len(anomalies)} unreported egress, expected {case.expect_unreported}'
                )
                # end if
            if anomalies and any(anomaly.kind != 'unreported-egress' for anomaly in anomalies):
                case.findings.append(f'the wrong anomaly kind: {[a.kind for a in anomalies]}')
                # end if
            # end if
        sealed_here = host.records()
        if sealed_here and [row.record_hash for row in records[-len(sealed_here) :]] != [
            record.record_hash for record in sealed_here
        ]:
            case.findings.append('the durable store and the in-memory chain disagree')
            # end if
        # end if
    return case
    # end def


def _signer_seq_gaps(store: _Store) -> list[str]:
    """Report any break in the `signer_seq` the host sealed, per key and session (§7.4).

    Each session's sequence has to be 0, 1, 2, ... with no repeat and no hole: a repeat means two
    writers numbered over each other, and a hole means a number was taken and never emitted.
    """
    by_session: dict[tuple[str, str], list[int]] = {}
    for row in store.rows:
        key_id, session_id, signer_seq = (
            row.event.get('key_id'),
            row.event.get('session_id'),
            row.event.get('signer_seq'),
        )
        if isinstance(key_id, str) and isinstance(session_id, str) and isinstance(signer_seq, int):
            by_session.setdefault((key_id, session_id), []).append(signer_seq)
            # end if
        # end for
    findings = []
    for (key_id, session_id), seen in by_session.items():
        if sorted(seen) != list(range(len(seen))):
            findings.append(f'signer_seq for {key_id} in {session_id} is {sorted(seen)}, not 0..n (§7.4)')
            # end if
        # end for
    return findings
    # end def


async def _session_over(case: Case, read_stream: object, write_stream: object, host: AuditHost, calls: int) -> None:
    """Make the case's calls over a transport's streams, audited when the case says so."""
    if case.audited:
        async with McpAuditReceiver(read_stream, write_stream, host) as receiver:  # type: ignore[arg-type]
            await _call(case, receiver.read_stream, receiver.write_stream, host, calls)
            # end async with
    else:
        await _call(case, read_stream, write_stream, host, calls)
        # end if
    # end def


def _contain(case: Case, error: BaseException) -> None:
    """Keep a failure the case expects as its finding's evidence, and re-raise any other."""
    if not (case.expect_tool_death or case.expect_call_error):
        raise error
        # end if
    case.death = case.death or repr(error)[:120]
    # end def


def _command(case: Case) -> tuple[str, list[str]]:
    """The command that starts the case's tool."""
    if case.tool == 'typescript':
        return 'npx', ['tsx', str(TS_TOOL)]
        # end if
    return sys.executable, [str(TOOL)]
    # end def


def _tool_environment(case: Case, tool_key: ToolKey, secret: str) -> dict[str, str]:
    """The environment every tool process of the case starts with."""
    return {
        **os.environ,
        'WALK_OPERATIONS': str(OPERATIONS),
        'WALK_TOOL_KEY_ID': tool_key.key_id,
        'WALK_TOOL_PRIVATE_KEY': secret,
        **case.environment,
    }
    # end def


class _Router(httpx2.AsyncBaseTransport):
    """The host's HTTP transport, sending each request to the instance `choose` picks, as a router does."""

    def __init__(self, choose: Callable[[httpx2.Request], str]) -> None:
        """Route through `choose`, which returns the endpoint a request goes to."""
        self._choose = choose
        self._inner = httpx2.AsyncHTTPTransport()
        self.sent: list[tuple[bool, str]] = []
        # end def

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        """Send the request where `choose` says, and note where each retry went."""
        target = self._choose(request)
        self.sent.append((_is_retry(request), target))
        request.url = httpx2.URL(target)
        return await self._inner.handle_async_request(request)
        # end def

    async def aclose(self) -> None:
        """Close the pooled connections."""
        await self._inner.aclose()
        # end def

    # end class


def _is_retry(request: httpx2.Request) -> bool:
    """Whether a request is a retry of one of the seam's rounds."""
    if request.method != 'POST' or not request.content:
        return False
        # end if
    params = json.loads(request.content).get('params')
    state = params.get('requestState') if isinstance(params, dict) else None
    return isinstance(state, str) and state.startswith(ROUND_TOKEN_PREFIX)
    # end def


def _chooser(case: Case, urls: list[str]) -> Callable[[httpx2.Request], str]:
    """How the case's router picks an instance for a request."""

    def choose(request: httpx2.Request) -> str:
        if case.route == 'misroute':
            return urls[1] if _is_retry(request) else urls[0]
            # end if
        session = request.headers.get(AFFINITY_HEADER)
        if case.route == 'affinity' and session is not None:
            return urls[hashlib.sha256(session.encode()).digest()[0] % len(urls)]
            # end if
        return urls[0]
        # end def

    return choose
    # end def


async def _listening_at(process: anyio.abc.Process) -> str:
    """The URL a tool process announces on stdout once it listens."""
    if process.stdout is None:
        raise RuntimeError('the tool process has no stdout to announce its URL on')
        # end if
    pending = b''
    async for chunk in process.stdout:
        pending += chunk
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            text = line.decode('utf-8', 'replace').strip()
            if text.startswith(HTTP_URL_LINE):
                return text[len(HTTP_URL_LINE) :]
                # end if
            # end while
        # end for
    raise RuntimeError('the tool process exited before it announced its URL')
    # end def


async def _stop(process: anyio.abc.Process) -> None:
    """Stop a tool process and everything it started, and wait, bounded, until none of them is left.

    Its stdin ends first, then its process group is signalled; the wait is on the whole group, since a
    wrapper (`npx`) can exit before the tool it started does.
    """
    if process.stdin is not None:
        await process.stdin.aclose()
        # end if
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signal_number)
        except ProcessLookupError:
            return
            # end try
        with anyio.move_on_after(TOOL_STOP_BOUND):
            await process.wait()
            while _group_alive(process.pid):
                await anyio.sleep(0.05)
                # end while
            return
            # end with
        # end for
    # end def


def _group_alive(group: int) -> bool:
    """Whether any process of a process group is still running."""
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
        # end try
    return True
    # end def


async def _drain(process: anyio.abc.Process) -> None:
    """Read what a tool process writes to stdout after its URL, so a full pipe never stalls it."""
    if process.stdout is not None:
        async for _chunk in process.stdout:
            continue
            # end for
        # end if
    # end def


async def _start_instances(case: Case, env: dict[str, str], workdir: Path) -> tuple[list[anyio.abc.Process], list[str]]:
    """Start the case's tool processes over HTTP and wait until each one listens."""
    command, args = _command(case)
    processes: list[anyio.abc.Process] = []
    for index in range(case.instances):
        instance_env = {**env, 'WALK_TRANSPORT': 'http', 'WALK_INSTANCE': f'walk-{index}'}
        if case.forward:
            instance_env['WALK_PEERS_FILE'] = str(workdir / 'peers.json')
            # end if
        processes.append(
            await anyio.open_process(
                [command, *args],
                env=instance_env,
                # Held open for the life of the case; a tool stops when it ends, so none outlives its runner.
                stdin=subprocess.PIPE,
                stderr=None,
                cwd=TS_REPO if case.tool == 'typescript' else None,
                # `npx` does not pass a termination on to the tool it starts, so the tool gets a process
                # group of its own and the group is what is stopped.
                start_new_session=True,
            )
        )
        # end for
    with anyio.fail_after(HTTP_START_BOUND):
        urls = [await _listening_at(process) for process in processes]
        # end with
    peers = {f'walk-{index}': url for index, url in enumerate(urls)}
    (workdir / 'peers.json').write_text(json.dumps(peers), encoding='utf-8')
    return processes, urls
    # end def


async def _connect_http(case: Case, host: AuditHost, tool_key: ToolKey, secret: str, calls: int) -> None:
    """Run one client session against the case's tool processes over Streamable HTTP."""
    with tempfile.TemporaryDirectory() as workdir:
        processes, urls = await _start_instances(case, _tool_environment(case, tool_key, secret), Path(workdir))
        router = _Router(_chooser(case, urls)) if case.instances > 1 else None
        try:
            async with anyio.create_task_group() as drains:
                for process in processes:
                    drains.start_soon(_drain, process)
                    # end for
                try:
                    http = httpx2.AsyncClient(transport=router, timeout=httpx2.Timeout(HTTP_TIMEOUT))
                    # A tool that dies fails the POST inside the transport's task group, which cancels the
                    # session; the failure is read once that group has unwound, not inside it.
                    async with http, streamable_http_client(urls[0], http_client=http) as (read_stream, write_stream):
                        await _session_over(case, read_stream, write_stream, host, calls)
                        # end async with
                except BaseException as error:  # noqa: BLE001 - a dying tool takes the session with it
                    _contain(case, error)
                    # end try
                drains.cancel_scope.cancel()
                # end async with
        finally:
            with anyio.CancelScope(shield=True):
                for process in processes:
                    await _stop(process)
                    # end for
                # end with
            # end try
        # end with
    if (
        router is not None
        and case.route == 'misroute'
        and not any(retry and url != urls[0] for retry, url in router.sent)
    ):
        case.findings.append('no retry reached another instance, so the case exercised nothing')
        # end if
    # end def


async def _connect(case: Case, host: AuditHost, tool_key: ToolKey, secret: str, calls: int) -> None:
    """Run one connection to a fresh tool process, making `calls` tool calls over it."""
    if HTTP:
        await _connect_http(case, host, tool_key, secret, calls)
        return
        # end if
    command, args = _command(case)
    parameters = StdioServerParameters(command=command, args=args, env=_tool_environment(case, tool_key, secret))
    async with stdio_client(parameters) as (read_stream, write_stream):
        try:
            await _session_over(case, read_stream, write_stream, host, calls)
        except BaseException as error:  # noqa: BLE001 - a dying tool takes the session with it
            _contain(case, error)
            # end try
        closing = anyio.current_time()
        # end async with
    # The client's exit waits for the tool process: a tool that does not end on EOF holds it until the
    # client terminates it.
    closed_in = anyio.current_time() - closing
    if not case.death and closed_in > TOOL_EXIT_BOUND:
        case.findings.append(f'the tool process did not exit on its own after the host closed ({closed_in:.1f}s)')
        # end if
    # end def


async def _resumed(case: Case, host: AuditHost, store: _Store, tool_key: ToolKey) -> AuditHost:
    """Rebuild the host from its persisted chain, as a restart does (§7.1)."""
    registry = KeyRegistry(KeyRole.TOOL)
    registry.register_tool_key(tool_key)
    countersign_key = generate_tool_key('walk-host-key')
    return await AuditHost.resume(
        'tenant-walk',
        host.capability,
        repository=store,
        verifier=KeyRegistryVerifier(registry) if case.host_level == Level.L2 else None,
        countersigner=Ed25519Countersigner(countersign_key.key_id, countersign_key.private_key)
        if case.host_countersign == Countersign.HOST
        else None,
    )
    # end def


async def _call(case: Case, read_stream: object, write_stream: object, host: AuditHost, calls: int) -> None:
    """Open the session in the case's binding, read the tool's declaration, and call it."""
    async with ClientSession(read_stream, write_stream) as session:  # type: ignore[arg-type]
        result = await (session.discover() if case.modern else session.initialize())
        declared = capability_of(result.capabilities)
        if case.audited and declared is None:
            case.findings.append('the tool declared nothing in the handshake (§6.1)')
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
            del n
            results.append(await session.call_tool('read_customers', {}))
            # end def

        try:
            for _round in range(calls):
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
        if case.expect_call_error and not any(call.is_error for call in results) and not case.death:
            case.findings.append('the call was supposed to fail and it did not')
            # end if
        for call in results:
            text = ''.join(block.text for block in call.content if hasattr(block, 'text'))  # type: ignore[attr-defined]
            if call.is_error:  # type: ignore[attr-defined]
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
        if not case.modern:
            # MCP 2026-07-28 has no `ping`; under the handshake it proves the connection outlived the calls.
            await session.send_ping()
            # end if
        # end async with
    # end def


async def main(selectors: Sequence[str]) -> int:
    """Run the selected cases and report what the ledgers showed."""
    chosen = [case for case in CASES if not selectors or any(s in case.name for s in selectors)]
    if HTTP:
        print('over Streamable HTTP: the §6.4 cases only; §6.5 over HTTP is outside this binding')
        chosen = [case for case in chosen if case.modern]
        if not TS_HTTP and any(case.tool == 'typescript' for case in chosen):
            print('skipping the cross-language cases: set WALK_TS_HTTP=1 once the TypeScript tool serves HTTP')
            chosen = [case for case in chosen if case.tool != 'typescript']
            # end if
    else:
        chosen = [case for case in chosen if not case.http_only]
        # end if
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
                # An ExceptionGroup prints as its own summary, which names no cause. The walk exists to
                # say what went wrong on the wire, so the leaves are what it reports.
                case.findings.append(f'the case raised: {_leaves(error)}'[:400])
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
