# Auditable MCP SDK (Python)

A protocol machine for [Auditable MCP](https://github.com/SatoshiImai/mcp-audit-extension)
(`auditable-mcp/0.3`). It lets an MCP tool self-attest its internal domain operations (SQL queries,
downstream API calls) and lets a host seal those attestations into a tamper-evident, hash-chained
ledger.

This is a real SDK, not a demo. It solves only the protocol problem — canonicalization, hashing,
signing, sequencing, state transitions — and leaves storage, transport, and tool logic to you,
behind explicit injection seams.

## Scope

What this SDK does:

- RFC 8785 (JCS) canonicalization with the strict numeric domain of the spec.
- The record-hash preimage and the per-partition hash chain.
- The audit-before-act tool lifecycle and the host audit subsystem (Level 1 and Level 2).
- Capability negotiation on both axes, and the §6.2 postures for a session that was not negotiated.
- The MCP wire binding, both of §6's: the exchange carried on the `tools/call` itself as Multi
  Round-Trip Requests under MCP 2026-07-28 (§6.4), and `audit/attempt` / `audit/outcome` under the
  `initialize` handshake (§6.5). Which one a call uses is read from the call.
- Audit sessions (§6.3): the host issues one per `tools/call`, and every event of the call carries it.
- The countersign: a host that declares it signs, signing what it sealed, and the tool and verifier
  checking it.
- Ed25519 signing/verification, plus an AWS KMS adapter, behind an injection seam.
- The durable-ledger lifecycle — seal-before-accept, fail-closed on a persistence error, and
  resume-after-restart — over a `LedgerRepository` interface you implement.
- Atomic sealing (§7.1): one lock per partition, so concurrent attempts take distinct positions in
  the chain rather than the same one.
- Atomic numbering (§7.4): `signer_seq` counts from zero in each session, and one section per session
  makes concurrent Level-2 actions reach the host in the order they were numbered rather than the
  order their signing finished in. Nothing about the count outlives the call, so there is nothing to
  store or share between processes.

What it does not do (your concern, via adapters):

- No storage backend. The SDK defines the `LedgerRepository` interface (with an in-memory
  implementation for tests); you implement it over your store. `SealedRecord` carries
  `to_dict`/`from_dict`.
- No transport lock-in. The core defines an abstract transport and bundles the in-process one. The
  MCP wire binding is a separate, optional subpackage (`auditable-mcp-sdk[mcp]`); nothing else in
  the SDK imports the official `mcp` package.
- No tool business logic, and no in-process private keys in production — sign through a KMS/HSM.

## Status

Alpha, tracking `auditable-mcp/0.3`. The public API is unstable while the spec is a pre-1.0 draft.

## Install

```bash
pip install auditable-mcp-sdk            # core
pip install "auditable-mcp-sdk[mcp]"     # + the MCP wire binding (official mcp SDK)
pip install "auditable-mcp-sdk[aws]"     # + AWS KMS adapter (boto3)
```

Requires Python 3.12+.

For development, isolation is pinned to a dedicated pyenv virtualenv and uv is the installer:

```bash
make env/init      # create the 3.14.7-amcp virtualenv and install the project + dev deps
make test          # unit + conformance vectors
make lint          # ruff + mypy --strict
```

## Concepts

- Tool side: an `AmcpSession` wraps each internal operation in `async with session.action(...)`.
  The context manager emits the attempt, waits for the host to accept, and (under Level 2) runs the
  Polluted Stop check before the body runs. If the host does not accept, the body never runs and
  `AmcpAbortedError` is raised.
- Host side: an `AuditHost` validates each event and seals accepted ones into a per-partition,
  hash-chained ledger — in memory, or durably through an injected `LedgerRepository`. It never
  authorizes the domain action; it only protects ledger integrity.
- Transport: the two sides talk over an `AuditTransport`. `InProcessTransport` connects them in the
  same process; a real deployment substitutes a wire transport.
- Sessions: an audit session is one `tools/call` (§6.3). The host issues its id, closes it when the
  call ends, and flags any attempt the call left without an outcome (`unresolved-attempt`).
- Levels: Level 1 is self-reporting; Level 2 adds a detached signature and a per-session sequence.
  The only difference on the tool side is an injected signer, and on the host side an injected
  verifier.
- Countersign: an independent axis (§5.2). The level says how strongly a tool's attestation resists
  forgery; the countersign says who sealed it. A host that declares `countersign: "host"` signs the
  host-assigned fields of every record it seals, together with the `log_id` that names its chain, so
  a verifier can tell a chain a distinct host confirmed from one a tool recorded for itself. Absence
  of a countersignature is a state, not an anomaly.
- Degradation: a tool that speaks this extension stays usable by hosts that do not. Where the
  extension was not negotiated, `transport_for` gives back either an audit host the tool provides
  for itself (degraded) or refuses to serve (mandatory) — and refuses to return anything at all for
  the third, non-conformant posture of serving while recording nothing (§6.2).

## Quickstart

### 1. Level 1, in-process

```python
import asyncio

from auditable_mcp import AmcpSession, AuditHost, InProcessTransport, verify_ledger


async def main() -> None:
    host = AuditHost('tenant-a')  # Level 1 by default
    async with host.session() as session_id:  # one audit session per call (§6.3)
        session = AmcpSession(InProcessTransport(host), session_id)

        async with session.action(
            'db.query',
            {'kind': 'database', 'ref': 'analytics-postgres'},
            mutates=False,
            egress=False,
            disclose={'dialect': 'postgres'},  # optional cleartext context
            commit={'sql': 'SELECT id FROM users'},  # optional hash commitment
        ):
            run_the_query()  # your domain action

    report = verify_ledger(host.records(), host.digest())
    print(report.ok, report.count)  # True 2


asyncio.run(main())
```

`disclose` and `commit` are both optional. Give neither, either, or both, depending on how much of
the internal context you can safely record.

### 2. The decorator

`@auditable_tool` wraps a whole function in an audited action. The session is resolved from a
task-local binding, so the decorated function stays unaware of wiring.

```python
from auditable_mcp import AmcpSession, AuditHost, InProcessTransport, auditable_tool, bound_session


@auditable_tool(
    action_type='db.read',
    mutates=False,
    egress=False,
    target_resource=lambda table: {'kind': 'table', 'ref': table},
)
async def read_table(table: str) -> list[dict]:
    return fetch_rows(table)


async def main() -> None:
    host = AuditHost('tenant-a')
    async with host.session() as session_id:
        session = AmcpSession(InProcessTransport(host), session_id)
        with bound_session(session):
            rows = await read_table('customers')
```

### 3. Handling a refused attempt

When the host rejects the attempt, reports itself unavailable, or the Polluted Stop check fails, the
body is skipped and `AmcpAbortedError` is raised. The tool surfaces it as a `tools/call` error.

The most common refusal is an action in a session the host did not issue. A host accepts events only
in a session it opened (§6.3), so a session it never issued, one it has not opened yet, and one it
has already closed all look the same to it: the attempt is rejected, and the body never runs.

```python
import asyncio

from auditable_mcp import AmcpAbortedError, AmcpSession, AuditHost, InProcessTransport, new_session_id


async def main() -> None:
    host = AuditHost('tenant-a')
    # A session id this host never issued - which is also what a session it has not opened yet, or
    # has already closed, looks like to it.
    session = AmcpSession(InProcessTransport(host), new_session_id())
    try:
        async with session.action('db.write', {'kind': 'table', 'ref': 'orders'}, mutates=True, egress=False):
            raise AssertionError('never runs')
    except AmcpAbortedError as error:
        print(error.reason)  # host-rejected


asyncio.run(main())
```

`error.reason` is one of `host-rejected`, `host-unavailable`, `hash-mismatch`, and, when a
countersignature is required or checked, `host-uncountersigned` and `host-signature-invalid`.

### 4. Level 2 with a local Ed25519 key

Local keys are for development and tests. See the next section for production, and
[Keys](#keys) for keeping and exchanging them.

```python
import asyncio

from auditable_mcp import (
    AmcpSession,
    AuditHost,
    Ed25519Signer,
    InProcessTransport,
    KeyRegistry,
    KeyRegistryVerifier,
    Level,
    generate_tool_key,
    verify_ledger,
)


async def main() -> None:
    tool_key = generate_tool_key('tool-1')

    registry = KeyRegistry()  # the host's out-of-band trust anchor
    registry.register_tool_key(tool_key)  # binds the key_id to Ed25519 (§5.1)

    # The host stamps its own spec_version; you supply only what you override.
    host = AuditHost('tenant-a', {'level': Level.L2}, verifier=KeyRegistryVerifier(registry))
    async with host.session() as session_id:
        session = AmcpSession(InProcessTransport(host), session_id, signer=Ed25519Signer.from_tool_key(tool_key))
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            pass  # your domain action

    report = verify_ledger(host.records(), host.digest(), signature_checker=KeyRegistryVerifier(registry).check)
    print(report.ok, report.count, report.unchecked)  # True 2 ()


asyncio.run(main())
```

### 5. Level 2 with AWS KMS (production)

The private key never leaves KMS. The signer calls `kms:Sign`; the verifier fetches the public key
once at onboarding and verifies locally. An `ECC_NIST_P256` key signs ECDSA P-256 (`ECDSA_SHA_256`,
JOSE `ES256`); an `ECC_NIST_EDWARDS25519` key signs `Ed25519`. `AwsKmsSigner.from_kms`,
`AwsKmsVerifier.from_kms` and, for a countersigning host, `AwsKmsCountersigner.from_kms` read the key
spec from KMS and pick the algorithm, so none of them is configured with it. The `AwsKmsSigner`
constructor, by contrast, defaults to ECDSA P-256, and KMS refuses every signature it asks of an
Ed25519 key. The adapter takes an injected client and never imports boto3, so `[aws]` only supplies
the client.

```python
import asyncio

import boto3

from auditable_mcp import AmcpSession, AuditHost, InProcessTransport, Level
from auditable_mcp.l2.adapters.aws_kms import AwsKmsSigner, AwsKmsVerifier


async def main() -> None:
    kms = boto3.client('kms')
    key_arn = 'arn:aws:kms:ap-northeast-1:123456789012:key/abcd-...'

    signer = await AwsKmsSigner.from_kms(kms, key_arn, event_key_id='tool-1')
    verifier = await AwsKmsVerifier.from_kms(kms, {'tool-1': key_arn})

    host = AuditHost('tenant-a', {'level': Level.L2}, verifier=verifier)
    async with host.session() as session_id:
        session = AmcpSession(InProcessTransport(host), session_id, signer=signer)
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            ...  # your domain action


asyncio.run(main())
```

The signer and verifier are just the `EventSigner` / `SignatureVerifier` seams; a GCP KMS or HSM
adapter drops into the same place.

### 6. A durable host

The host keeps its chain in memory by default. Inject a `LedgerRepository` to persist every accepted
record before it is acknowledged; a persistence failure then fails closed (`unavailable`). The bundled
`InMemoryLedgerRepository` is for tests — implement the protocol over your own store (DynamoDB,
Postgres, …).

The contract a repository keeps:

- `append(partition, record)` is conditional on `record.seq`: a conditional put, a unique
  constraint, or a compare-and-set on the tail, so two writers can never store a record at one
  position (§7.1). When the position is taken, or the write cannot be confirmed, it raises
  `RepositoryError`. The host reads that as "may have landed", re-reads the tail with `load_tail`
  before it seals again, and adopts the record if it is there.
- `load_tail(partition)` returns the last record, or None for an empty partition.
- `read_all(partition)` returns every record in append order.
- Store records as `record.to_dict()` and read them back with `SealedRecord.from_dict(...)`; the
  round trip is exact, which the chain's hashes depend on.

Build the host with `AuditHost.resume` at startup, even on an empty store: it continues the chain
where the store left it (next `seq`, tail link, what makes a repeat recognizable). A restart ends
every call that was in flight, so every attempt stored without a terminal outcome after it is
recorded `unresolved-attempt`, and none of those sessions is open. Anomalies are otherwise held in
memory only: persist `host.anomalies()` if you need them across restarts.

```python
from auditable_mcp import AuditHost, InMemoryLedgerRepository, verify_ledger

repo = InMemoryLedgerRepository()  # swap for your own LedgerRepository
host = await AuditHost.resume('tenant-a', repository=repo)
# ... run audited actions; each sealed record is written to `repo` before it is accepted ...

# audit the full persisted chain, not just this process's records:
report = verify_ledger(await repo.read_all('tenant-a'), host.digest())
```

### 7. Verifying a ledger

`verify_ledger` recomputes the chain from the record bodies, independent of the stored hashes, and
reports tampering, gaps, broken links, uncorrelated outcomes, and (against an out-of-band anchor)
truncation or rewrite. Signatures are checked only against the registries you hand it.

```python
from auditable_mcp import (
    CountersignatureRegistryVerifier,
    ExpectedIdentity,
    KeyRegistryVerifier,
    verify_ledger,
)

report = verify_ledger(
    records,
    anchored_digest=trusted_tail_digest,
    signature_checker=KeyRegistryVerifier(tool_registry).check,  # Level-2 event signatures
    countersignature_checker=CountersignatureRegistryVerifier(host_registry).check,
    countersignature_required=True,  # a record without one is a finding, not a state
    expected_identity=ExpectedIdentity(log_id='log-a', host_key_ids=frozenset({'host-1'})),
)
if not report.ok:
    for issue in report.issues:
        log.error('ledger issue at seq=%s: %s (%s)', issue.seq, issue.kind, issue.detail)
```

Without the checkers, a Level-2 ledger still reports `ok=True`, with
`unchecked=('level-2-signature',)`: the chain holds, and nobody looked at the signatures. Read
`report.complete` (ok and nothing unchecked) where that difference matters.

### Keys

- A tool's Ed25519 key: `generate_tool_key(key_id)`. Keep its private half with
  `tool_key_pkcs8(key)` (unencrypted PKCS#8 DER) and read it back with `load_tool_key(key_id, pkcs8)`.
  In production the private half stays in a KMS instead (§5).
- The public half goes to the peer as a JWK: `public_jwk(key_id, public_key, algorithm, role)`, for
  example `public_jwk('tool-1', key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)`.
  `jwk_thumbprint(jwk)` is its RFC 7638 thumbprint, for comparing out of band. For a KMS key,
  `await kms_registry_entry(kms, key_arn, key_id='tool-1', role=KeyRole.TOOL)` (in
  `auditable_mcp.l2.adapters.aws_kms`) renders the same JWK from the key's public half.
  `load_kms_public_key(kms, key_arn)` returns the bare public key - elliptic-curve for a P-256 key,
  Ed25519 for an Ed25519 one - but binds no algorithm to a `key_id`, so a peer is provisioned from
  `kms_registry_entry` instead.
- The receiving side holds a registry per role: `KeyRegistry(KeyRole.TOOL)` or
  `KeyRegistry(KeyRole.HOST)`, filled with `registry.load_jwks({'keys': [...]})` and published with
  `registry.to_jwks()`.
- `registry.revoke(key_id)` keeps the entry, so the records it signed still verify, and confirms
  nothing new under it (§10.9); a `key_id` never registered is refused with `ValueError`. A revoked
  entry is exported with `amcp_revoked: true` (`REVOKED_MEMBER`) and loads revoked, and loading an
  unrevoked copy of a key already revoked does not lift the revocation.
- A countersigning host has a key of its own: `Ed25519Countersigner(key_id, private_key)`, with an
  Ed25519 private key from wherever you keep it, for example
  `generate_tool_key('host-1').private_key` or `load_tool_key('host-1', pkcs8).private_key`. Its
  public half goes into the verifiers' and tools' `KeyRegistry(KeyRole.HOST)`. The host takes it as
  `AuditHost(..., {'countersign': 'host'}, countersigner=..., log_id='log-a')`.
- Tool and host registries share no key (§10.9); `assert_registries_disjoint` checks it.
- A key persists for as long as its `key_id` does. A key minted per process, or a new key under an
  existing `key_id`, is not caught when it is provisioned but only at verification, where every
  record it signed fails. Rotation is a fresh `key_id`.

### 8. Over a real MCP connection

Neither official MCP SDK can deliver this extension through its own dispatch, and neither has to:
everything it adds is ordinary JSON-RPC on the connection MCP already holds. So the binding sits
between the session and the transport streams and hands the session a pair of its own. Everything
that is not audit traffic passes through untouched, and the session sees exactly the MCP it would
have seen without this extension.

Both bindings are served from the same code. A `tools/call` made under MCP 2026-07-28 carries the
exchange on the call itself (§6.4): the seam ends a round with an `InputRequiredResult` carrying the
events, keeps the handler suspended until the host's retry brings the answers, and puts the handler's
final result on the retry. A call made under the `initialize` handshake uses `audit/attempt` and
`audit/outcome` (§6.5). The handler is written once and never sees the difference.

A tool (an MCP server), complete, on the official SDK's high-level `MCPServer`. `MCPServer` has no
public way to run on streams it is given, so this uses its private `_lowlevel_server` attribute to
run it on the seam's streams:

```python
import logging

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.stdio import stdio_server

from auditable_mcp import (
    SPEC_VERSION,
    AmcpAbortedError,
    AmcpSession,
    AuditCapability,
    AuditHost,
    AuditTransport,
    Countersign,
    InProcessTransport,
    Level,
    Posture,
    transport_for,
)
from auditable_mcp.mcp import McpAuditTransport

log = logging.getLogger('customers-tool')

TOOL_CAPABILITY = AuditCapability(
    spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE
)
# A tool that requires a countersignature cannot degrade: its own host has no host key (§5.2, §6.2).
POSTURE = Posture.MANDATORY if TOOL_CAPABILITY.countersign == Countersign.HOST else Posture.DEGRADED

server = MCPServer('customers-tool')
# The host the tool records into when the caller does not audit (§6.2). Give it a repository to keep it.
self_hosted = AuditHost('customers-tool-local', {'level': Level.L1})
audit: McpAuditTransport | None = None


async def _read(transport: AuditTransport, session_id: str, table: str) -> str:
    session = AmcpSession(transport, session_id)
    async with session.action('db.read', {'kind': 'table', 'ref': table}, mutates=False, egress=False):
        return f'rows of {table}'  # your domain action


@server.tool()
async def read_customers(table: str, ctx: Context) -> str:
    """Read rows from a table, audited."""
    assert audit is not None
    # The raw JSON-RPC id; ctx.request_id is only its string form.
    call = audit.call(ctx.request_context.request_id)
    transport = transport_for(
        call.negotiate(TOOL_CAPABILITY),  # raises UnnegotiatedCallError under MANDATORY, failing the call
        negotiated=call,
        fallback=InProcessTransport(self_hosted),
        posture=POSTURE,
    )
    try:
        if transport is call:
            return await _read(call, call.session_id, table)
        # Degraded: the tool is its own host, and opens the session the call records under (§6.2).
        async with self_hosted.session(call.session_id):
            return await _read(transport, call.session_id, table)
    except AmcpAbortedError as error:
        # The action was not performed. MCPServer turns a raised error into a tool error result.
        log.warning('audit aborted %s: %s', error.action_type, error.reason)
        raise RuntimeError(f'not performed: the audit trail could not record it ({error.reason})') from error


async def main() -> None:
    global audit
    async with stdio_server() as (read_stream, write_stream):
        async with McpAuditTransport(read_stream, write_stream, TOOL_CAPABILITY) as wire:
            audit = wire
            # MCPServer has no public way to run on streams it is given; this reaches its low-level server.
            lowlevel = server._lowlevel_server
            await lowlevel.run(wire.read_stream, wire.write_stream, lowlevel.create_initialization_options())


if __name__ == '__main__':
    anyio.run(main)
```

What it relies on:

- `audit.call(ctx.request_context.request_id)` finds the `tools/call` being served. Pass the raw
  JSON-RPC id: ids are matched by type and value, so `1` and `"1"` are two calls, and
  `ctx.request_id` - its string form - is refused with an `UnknownCallError` that says so. A low-level
  `Server` handler passes `context.request_id`, which is already the raw id.
- `transport_for` decides §6.2. Negotiated, the call itself is the transport. Not negotiated, the
  degraded posture records into a host the tool provides for itself, under a session the tool opens
  with `async with self_hosted.session(call.session_id):`; the mandatory posture raises
  `UnnegotiatedCallError` and the call fails. A tool that requires a countersignature cannot degrade
  (its own host has no host key), so it must pass `posture=Posture.MANDATORY`.
- A tool that requires a countersignature declares `countersign=Countersign.HOST` in its capability
  and also constructs its session with
  `AmcpSession(..., require_countersign=True, countersignature_verifier=CountersignatureRegistryVerifier(host_registry))`.
  The declaration is what the host negotiates against; the session is what aborts an accept that
  carries no valid countersignature. One without the other checks nothing.
- `AmcpAbortedError` means the action was not performed. Return it as a tool error, not a result.

A host (an MCP client) wraps its own streams around its `AuditHost`, and its declaration is the
host's requirement itself — there is no second copy to drift. The receiver issues an audit session
in each outgoing `tools/call`, answers a round that asks the client for nothing else by retrying on
the spot, passes a round that also carries `inputRequests` up to the client with the audit answers
riding its retry, and closes the session when the call ends:

```python
from auditable_mcp.mcp import McpAuditReceiver, capability_of

async with McpAuditReceiver(read_stream, write_stream, host) as audit:
    async with ClientSession(audit.read_stream, audit.write_stream) as session:
        result = await session.discover()  # or session.initialize() for the handshake binding
        tool_capability = capability_of(result.capabilities)  # None = an ordinary MCP tool
```

The host decides whether to call a tool whose declaration does not meet its requirement: check
`capability_of(result.capabilities)` against the requirement (`negotiate(host.capability, declared)`)
and refuse, or accept the call unaudited. The receiver logs a warning once per connection when the
declaration is absent or does not fit, naming the outcome, but it does not refuse for you.

§6 obligations that live in this module and nowhere else: the wait for a decision is bounded and
fails closed when it expires; a round's `requestState` is consumed by its first retry, so a replayed
retry is refused and never runs an operation twice; and nothing at all is sent on a call that was not
audit-negotiated.

On the host's side, `request_timeout` is one deadline for the whole of a §6.4 round, from the moment
the session's queue takes it up: the retry (or the round passed up to the client) goes when it passes
at the latest. An attempt not decided by then is answered `unavailable` - one not yet reached is never
handed to the host, and one in progress completes in the background - and the outcomes not yet sealed
are sealed after the retry. The receiver removes this extension's member from `_meta` (and an empty
`_meta` with it) before it passes a result up to its client. Closing the receiver waits up to
`request_timeout` for the audit work still queued and then closes every session on the connection,
each close bounded as long again; a session whose work did not finish is logged by id. On the tool's
side, a call whose handler concluded while a round was out keeps its final answer until that round's
retry comes, however late, and answers it with them.

Reference:

- `McpAuditTransport(read_stream, write_stream, declares, *, request_timeout=DEFAULT_REQUEST_TIMEOUT)`:
  `DEFAULT_REQUEST_TIMEOUT` is 30.0 seconds, the bound on each wait for a decision.
- `McpAuditCall`, from `audit.call(...)`: `negotiate(offered)` compares the host's declaration with
  the tool's and returns the `NegotiationResult`; `session_id` is the host's audit session once
  negotiated, otherwise one the tool minted; `numbering` is the call's `signer_seq` state, shared by
  every request of the call; `host_capability` is what the host declared, or None.
- `MAX_ROUNDS_PER_CALL` is 256: a §6.4 call that needs more rounds is ended with an error.
- `MAX_IDLE_SESSIONS` is 1024 per connection, and bounds three things separately: a tool's idle
  sessions and its concluded calls waiting on a retry, and a host's rounds waiting on its client's
  retry. Beyond it the least recent one is evicted with a warning; an evicted host round ends its call,
  and its session's accepted attempts are recorded `unresolved-attempt`.
- `AmcpSession(transport, session_id)` refuses a `session_id` that is not a lowercase, non-nil UUID
  with `AmcpUsageError` at construction.

### 9. Over Streamable HTTP, and round affinity

Under MCP 2026-07-28 the official Streamable HTTP handler serves each POST on its own, with no stream
pair that outlives it, so there is nothing for the seam to wrap. `AuditedStreamableHTTP` is an ASGI
app that wraps the official `StreamableHTTPSessionManager` and gives each audited call a connection of
its own: an in-memory stream pair with the tool's server running on it behind `McpAuditTransport`,
built by a factory exactly as it is over stdio. The opening `tools/call` and every retry of the call
are written into that connection, and each POST is answered with what the connection answers on its
request id. It takes only a POST `tools/call` under 2026-07-28 that carries an audit `session_id`,
carries the `Auditable-Mcp-Session` header, or echoes an `amcp.` `requestState`; everything else -
discovery, `tools/list`, unaudited calls, the handshake era - reaches the official handler untouched.

```python
import contextlib

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route

from auditable_mcp.mcp import AuditedStreamableHTTP, HttpForwarder, McpAuditTransport


def build_tool(seam: McpAuditTransport) -> Server:
    """One call's server; its tools/call handler calls `seam.call(context.request_id)` as over stdio."""
    ...


manager = StreamableHTTPSessionManager(official_server, json_response=True)
forwarder = HttpForwarder({'node-a': 'http://10.0.0.1:8000/mcp', 'node-b': 'http://10.0.0.2:8000/mcp'}.get)
entry = AuditedStreamableHTTP(manager, build_tool, TOOL_CAPABILITY, instance='node-a', forward=forwarder)


@contextlib.asynccontextmanager
async def lifespan(app):
    async with forwarder, manager.run(), entry.run():
        yield


app = Starlette(routes=[Route('/mcp', endpoint=entry)], lifespan=lifespan)
```

The official server (`official_server` above) answers `server/discover`, so the entry declares the
tool's capability in its `extensions` at construction (§6.1): it writes it into
`manager.app.extensions`, and raises `ValueError` if the server already declares something else under
the extension's identifier. It also serves every `tools/call` that
carries no audit session; a tool that degrades there gets the §6.1 result from
`negotiate_unaudited(context.params, TOOL_CAPABILITY)`, which is what `McpAuditCall.negotiate` returns
for such a call.

Every POSTed JSON-RPC request whose `_meta` names a protocol version (the 2026-07-28 envelope), of any
method, has its `Auditable-Mcp-Session` header checked against the body's
`params._meta["com.timberlandchapel/auditable-mcp"].session_id`: absent while the body carries one,
present while it carries none, or different (a header sent twice reads as its values joined) is HTTP 400
with JSON-RPC `-32020`, message `Bad Request: the request headers and body disagree: ...` and
`data.mismatch` naming the header and the body path. Handshake-era requests are not checked.

What the entry also applies to the requests it takes, because they bypass the official handler: the
manager's security settings (Host, Origin, Content-Type), its body size limit, the `Accept` check, a
duplicated routing header, `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` against the body, and
`Mcp-Param-*` against the tool's input schema (read from the call's own server with `tools/list`); a
failure is answered at the status the official handler uses for it. Everything the call answers -
results, the tool's errors, and the refusals below - goes in-band with HTTP 200, as a handler's error
does, except an answer carrying `-32020` or `-32021`, which says the request itself was not acceptable
and goes as HTTP 400 while the response is still JSON, as the official handler sends it. The response follows the manager's mode: JSON in JSON-response mode, where a notification the
tool emits has no place and is dropped with a debug log; otherwise as the official modern handler does
it, JSON when the answer comes first, SSE once a notification comes or 15 seconds pass. A notification
goes out with the request of the call in flight. A client that closes a request's response stream
cancels the call, through the seam's cancellation path. A call's connection closes when the call
concludes, when it is cancelled, when it expires, or when it is evicted to make room, by one rule
both SDKs share:

| State of the held call | Evicted to make room | Expires after `idle_timeout` (600 s) with no request in flight |
|---|---|---|
| **running**: a request of it in flight, its handler at work with no round out, or an operation the host accepted with no outcome yet | never | never - the entry never cancels an accepted operation, whose outcome could then never be known; it becomes eligible once it stops running |
| **undelivered**: holds outcomes or a final answer for its next retry | never | yes - the host has had the whole bound to retry; the host's session end records what is missing |
| neither | yes, least recently used first | yes |

The entry holds at most `max_held_calls` (`MAX_IDLE_SESSIONS`, 1024) calls; while none may be evicted
it refuses a new one in-band with `-32603` "this instance holds as many audited calls as it may". Only
calls whose operations the host accepted can keep the registry full, so where untrusted clients can
reach the tool, require a countersignature (§5.2), so that only the host's accepts count, and set
`principal_of`.

Each request reaches the tool's handler in its own context: the `contextvars` of the HTTP request that
carried it - what an authentication middleware or a tracer set there (`get_access_token()` included) -
not those of the request that opened the call. A handler the seam resumes on a retry was invoked by an
earlier request and keeps that request's `contextvars`; what is per request is read from the call:
`call.request` is the Starlette request the call is served under now (the opener's, then each retry's
as it is accepted), and `call.access_token` the `AccessToken` it was authenticated with
(`access_token_of(request)` reads one from any request). The TypeScript SDK's `McpAuditCall.request` /
`.authInfo` / `authInfoOf` are the same accessors. The same holds on the host's side: each request of a
call, the retries the seam builds included, reaches the official client transport in the context of
the caller that made the call.

A tool's own input round (an `InputRequiredResult` its handler returns with a `requestState` of its own)
goes out under a token the entry issues in its place, `amcp.<instance>.<secret>`, and its retry reaches
the handler with the tool's own `requestState` again. Every request of an audited call that carries a
`requestState` is a retry (§6.4): one that carries a value the entry did not issue names no round and
is refused, as is a retry of the tool's own round under another audit session or none, and a request without one for a session the entry already holds is refused with `-32602`
"this session is already open (§6.3)" - neither ever reaches the call.

On the host's side nothing changes in the code: `McpAuditReceiver` over the official
`streamable_http_client` streams puts `Auditable-Mcp-Session` on every request of an audited call and
gives each retry it builds the per-request headers of the request it repeats (`Mcp-Method`,
`Mcp-Name`, every `Mcp-Param-*`); a client's own retry keeps its headers and gains the affinity header.

Round affinity (§6.4). The seam keeps a call's handler suspended in one instance, so a deployment of
several instances must deliver every retry of a call to the instance that holds it. Two ways, which
compose:

- Route on the header. `Auditable-Mcp-Session` is the call's `session_id` on every request of the
  call, so a load balancer that hashes it keeps a call on one instance without reading the body. The
  header authenticates nothing; the entry checks it against the body. Every intermediary between host
  and tool must pass it through unchanged: one that strips it has every audited call refused.
- Forward. Every round token is `amcp.<instance>.<secret>`: the instance that holds the round, and 32
  random bytes, in 43 base64url characters, that find it. Each entry is an instance of its own, named
  at random unless `instance=` names it, and a stdio seam names the process. An entry that receives a
  retry it does not hold calls
  `forward(instance, request)`; `HttpForwarder(resolve)` posts it, with the client's headers and a
  `Auditable-Mcp-Forwarded: 1` marker, to the URL `resolve` returns for that instance, and the response
  is relayed (a JSON answer once it has been read whole, SSE as it arrives). `resolve` is the only
  source of an address: an instance name outside `[A-Za-z0-9_-]{1,64}`, or one `resolve` does not
  know, is refused, redirects are not followed, and a request that carries the marker is never
  forwarded again. Forwarding covers the tool's own rounds as well as the seam's only because the entry
  issues their tokens too (above). The owner answers a forwarded retry once the round's work is done,
  so the forwarder's read timeout must be unbounded or longer than any operation; the default client's
  is unbounded. With DNS-rebinding protection on, the manager's `allowed_hosts` must include the
  internal host names the instances forward to one another under.

What still fails closed: a retry that reaches an instance that neither holds its round nor can
forward it - no `forward`, an unknown instance, the marker already set, the instance itself, a
restarted process, a round released as idle, or a forward that provably never reached the owner
(`resolve` knows no such instance or raises, the connection was never made, a redirect, or a `forward`
that raises `ForwardNotDeliveredError`) - is answered like a replay, `-32602` "this requestState names
no open round (§6.4)", and nothing is performed; the tool's attempt goes unanswered and fails closed,
and the host records the attempt it accepted as `unresolved-attempt`. A forward that fails after the
retry was sent - a read timeout, a reset, a body cut short, or a `forward` that raises anything else -
may have reached the owner, and is answered `-32603` "forwarding failed after the retry was sent; its
outcome is unknown (§6.4)" rather than as a replay.

Give the entry `principal_of(request)` wherever requests are authenticated. A `session_id` travels in
a header, and intermediaries may log it; with `principal_of`, a request that presents a principal other
than the one that opened the call is refused with `-32602` "this round was opened by another principal
(§6.4)", checked before the round token is consumed, so the round stays open for its owner (MRTR
requirement 5). On the host's side, a retry that cannot be handed to the transport
ends the call with `-32603` "the retry of an audit round could not be sent (§6.4)", and a transport
that fails a request inside its own task group cancels the session around the receiver, which still
closes every audit session it held, recording what the tool never resolved (§6.3).

Reference:

- `AuditedStreamableHTTP(manager, factory, declares, *, instance=None, forward=None, principal_of=None,
  request_timeout=DEFAULT_REQUEST_TIMEOUT, idle_timeout=DEFAULT_IDLE_TIMEOUT,
  max_held_calls=MAX_IDLE_SESSIONS)`, an ASGI app; enter `run()` in the lifespan. `principal_of` is
  `(starlette.requests.Request) -> str | None`.
- `HttpForwarder(resolve, *, client=None, timeout=DEFAULT_FORWARD_TIMEOUT)`, an async context manager
  that closes the `httpx2` client it created. Any callable with the `Forward` shape can stand in:
  `forward(instance, ForwardedRequest) -> AbstractAsyncContextManager[ForwardedResponse | None]`. It
  yields None or raises `ForwardNotDeliveredError` for a request that provably never reached the owner,
  and raises `ForwardOutcomeUnknownError` (or anything else) for one that may have.
- `McpAuditTransport(..., instance=PROCESS_INSTANCE)` names the instance in its tokens;
  `round_token_instance(request_state)` reads it back, or None for anything that is not a well-formed
  token; `new_instance_id()` draws a name. `with_affinity_header(headers, session_id)` is what the host
  seam applies to a request's headers. `AFFINITY_HEADER`, `FORWARDED_HEADER`, `INSTANCE_PATTERN`,
  `SESSION_BODY_PATH`, and the refusal messages `NO_OPEN_ROUND_MESSAGE`, `PRINCIPAL_MISMATCH_MESSAGE`,
  `REGISTRY_FULL_MESSAGE`, `CONNECTION_CLOSED_MESSAGE`, `RETRY_NOT_SENT_MESSAGE`,
  `SESSION_ALREADY_OPEN_MESSAGE`, `FORWARD_OUTCOME_UNKNOWN_MESSAGE`.

Limitations of the §6.4 seam:

- It keeps the suspended handler in the process that serves the call, so a call's retries must reach
  that process: stdio, one instance, or a deployment that delivers them by round affinity (above). It
  does not serialize a handler into `requestState`; the specification leaves that mechanism to the
  implementation.
- Every `requestState` it issues for an audit round begins with `amcp.`, and a retry carrying that
  prefix is taken as one of its rounds. A tool's own `requestState` (its own MRTR round) must
  therefore not begin with `amcp.`: its retry would be refused as naming no open round. The seam logs
  an error when a handler returns one.
- A tool's own input round keeps the call's audit session for its retry until the connection closes,
  however long the client takes. Beyond MAX_IDLE_SESSIONS idle sessions per connection the least
  recently idle one is evicted with a warning. A retry of an evicted session starts a fresh record:
  under Level 2 its numbering restarts and the host refuses the repeated values (fail-closed); under
  Level 1 the retry negotiates again under the same session_id.
- In the degraded posture (§6.2, no audit peer), a call whose tool runs its own input rounds reaches
  the tool as several requests, and each gets a session of its own, minted by the tool: nothing on
  the wire ties the requests of an unaudited call together. Its records are complete, but split across
  those sessions rather than kept in one.

## Conformance

The normative JSON Schema and golden vectors are vendored under [`spec/`](spec/) from the
`mcp-audit-extension` spec repo (their single source of truth). A conforming implementation must
reproduce every vector byte-for-byte.

```bash
make spec/check    # fail if the vendored spec drifted from source
make test          # includes the cross-language conformance vectors
make walk          # drive the SDK over a real stdio pipe (see below)
```

### The walk

`walk/` runs the SDK the way a deployment does: the tool is a **separate process**, the wire is a
real pipe, and the host is the official MCP client with an `McpAuditReceiver` in front of it. The
suite cannot see what only exists across that boundary — framing, back-pressure, process lifetime,
and operations that really are concurrent — so the walk covers it, and each case states what it
expects of the ledger rather than of the SDK's internals.

It also drives the **TypeScript** tool from this Python host over the same pipe, which is what makes
the interoperability claim something other than an assertion. Those cases are skipped if the other
port is not checked out beside this one.

Every case runs under both bindings, §6.4 and §6.5. The cases have teeth: removing the §7.1 sealing
lock, the §7.4 numbering section, or either side's handshake declaration turns the walk red in both
ports. Guards against *misuse* of this SDK's own
API are not covered here — nothing across a process boundary can provoke them — and belong to the
suite.

```bash
make walk                 # every case
make walk CASE=crosslang  # the cross-language cases
make walk/http            # the §6.4 cases over Streamable HTTP, and the round-affinity cases
```

`make walk/http` serves each tool process through `AuditedStreamableHTTP` on a loopback port, with
the official Streamable HTTP client as the host's transport, which is the path a deployment takes. It
adds the cases only a deployment of several instances has: every retry forwarded to the instance that
holds its round, a router that routes on `Auditable-Mcp-Session` alone, and a misrouted retry without
forwarding, which fails closed. The `-initialize` cases do not run there. A tool under
`WALK_TRANSPORT=http` writes one line `WALK_HTTP_URL=<url>` to stdout once it listens, in both ports.
The cross-language cases run over HTTP with `WALK_TS_HTTP=1`, against the TypeScript checkout
`WALK_TS_REPO` names (default: the sibling `auditable-mcp-sdk-ts`); the TypeScript walk drives this
port's tool the same way with `WALK_PYTHON_HTTP=1` and `WALK_PY_REPO`.

## Layout

| Path                                  | Role                                                            |
| ------------------------------------- | --------------------------------------------------------------- |
| `src/auditable_mcp/canonical.py`      | RFC 8785 canonicalization + numeric guard + SHA-256             |
| `src/auditable_mcp/hashing.py`        | record-hash preimage + genesis link                             |
| `src/auditable_mcp/models.py`         | typed wire contracts (event, capability, attempt response)      |
| `src/auditable_mcp/fields.py`         | wire field-name registry                                        |
| `src/auditable_mcp/reasons.py`        | reason / anomaly code vocabulary                                |
| `src/auditable_mcp/ledger.py`         | per-partition sealed records + hash chain                       |
| `src/auditable_mcp/verify.py`         | ledger verifier (recompute, tamper/gap/digest detection)        |
| `src/auditable_mcp/storage/`          | `LedgerRepository` interface + in-memory implementation         |
| `src/auditable_mcp/capability.py`     | §6.1 negotiation on both axes, and the undeclared outcome        |
| `src/auditable_mcp/degradation.py`    | §6.2 postures for a session that was not negotiated             |
| `src/auditable_mcp/transport.py`      | tool/host transport seams + response builders                   |
| `src/auditable_mcp/in_process.py`     | in-process transport                                            |
| `src/auditable_mcp/mcp/`              | §6 wire binding over MCP (optional: `[mcp]`)                    |
| `src/auditable_mcp/clock.py`          | ISO-8601 timestamp source (`Clock` protocol)                    |
| `src/auditable_mcp/session.py`        | audit-before-act async session (the tool-side core)             |
| `src/auditable_mcp/decorator.py`      | thin `@auditable_tool` wrapper                                  |
| `src/auditable_mcp/host.py`           | host audit subsystem (validate, seal, flag)                     |
| `src/auditable_mcp/encoding.py`       | strict unpadded base64url, the JOSE form of every signature     |
| `src/auditable_mcp/l2/`               | Ed25519 / ES256 signing and verification, JWK key exchange      |
| `src/auditable_mcp/l2/adapters/`      | external key backends (AWS KMS)                                 |
| `spec/`                               | vendored normative schema + golden vectors (do not edit)        |

## Note on AI Assistance

The core architecture, design decisions, and core implementations in this project are entirely my own. I used AI tools (Claude, Gemini) strictly under my explicit direction for code generation, text formatting, edge-case verification, and polishing my English prose. All outputs were heavily reviewed, corrected, and finalized by me.

## License

MIT (c) Satoshi Imai
