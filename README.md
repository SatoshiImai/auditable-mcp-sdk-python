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
- The witness: a host that declares it signs, signing what it sealed, and the tool and verifier
  checking it.
- Ed25519 signing/verification, plus an AWS KMS adapter, behind an injection seam.
- The durable-ledger lifecycle — seal-before-accept, fail-closed on a persistence error, and
  resume-after-restart — over a `LedgerRepository` interface you implement.

What it does not do (your concern, via adapters):

- No storage backend. The SDK defines the `LedgerRepository` interface (with an in-memory
  implementation for tests); you implement it over your store. `SealedRecord` carries
  `to_dict`/`from_dict`.
- No transport lock-in. The core defines an abstract transport and bundles the in-process one; you
  wire the `AuditTransport` seam over MCP, importing the official `mcp` package alongside this one.
- No tool business logic, and no in-process private keys in production — sign through a KMS/HSM.

## Status

Alpha, tracking `auditable-mcp/0.3`. The public API is unstable while the spec is a pre-1.0 draft.

## Install

```bash
pip install auditable-mcp-sdk            # core
pip install "auditable-mcp-sdk[aws]"     # + AWS KMS adapter (boto3)
```

Requires Python 3.12+.

For development, isolation is pinned to a dedicated pyenv virtualenv and uv is the installer:

```bash
make env/init      # create the 3.14.6-amcp virtualenv and install the project + dev deps
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
- Levels: Level 1 is self-reporting; Level 2 adds a detached signature and a monotonic sequence.
  The only difference on the tool side is an injected signer, and on the host side an injected
  verifier.
- Witness: an independent axis (§5.2). The level says how strongly a tool's attestation resists
  forgery; the witness says who sealed it. A host that declares `witness: "host"` signs the
  host-assigned fields of every record it seals, so a verifier can tell a chain a distinct host
  confirmed from one a tool recorded for itself. Absence of a signature is a state, not an anomaly.
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
    host = AuditHost("tenant-a")  # Level 1 by default
    session = AmcpSession(InProcessTransport(host), "call-1")

    async with session.action(
        "db.query",
        {"kind": "database", "ref": "analytics-postgres"},
        mutates=False,
        egress=False,
        disclose={"dialect": "postgres"},   # optional cleartext context
        commit={"sql": "SELECT id FROM users"},  # optional hash commitment
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
    action_type="db.read",
    mutates=False,
    egress=False,
    target_resource=lambda table: {"kind": "table", "ref": table},
)
async def read_table(table: str) -> list[dict]:
    return fetch_rows(table)


async def main() -> None:
    host = AuditHost("tenant-a")
    session = AmcpSession(InProcessTransport(host), "call-1")
    with bound_session(session):
        rows = await read_table("customers")
```

### 3. Handling a refused attempt

When the host rejects the attempt, reports itself unavailable, or the Polluted Stop check fails, the
body is skipped and `AmcpAbortedError` is raised. The tool surfaces it as a `tools/call` error.

```python
from auditable_mcp import AmcpAbortedError

try:
    async with session.action("db.write", {"kind": "table", "ref": "orders"}, mutates=True, egress=False):
        write_row()
except AmcpAbortedError as error:
    # error.reason is one of: host-rejected, host-unavailable, hash-mismatch
    log.warning("audit aborted: %s", error.reason)
```

### 4. Level 2 with a local Ed25519 key

Local keys are for development and tests. See the next section for production.

```python
from auditable_mcp import (
    AmcpSession,
    AuditHost,
    Ed25519Signer,
    InProcessTransport,
    KeyRegistry,
    KeyRegistryVerifier,
    Level,
    generate_tool_key,
)

tool_key = generate_tool_key("tool-1")

registry = KeyRegistry()          # the host's out-of-band trust anchor
registry.register_tool_key(tool_key)   # binds the key_id to Ed25519 (§5.1)

# The host stamps its own spec_version; you supply only what you override.
host = AuditHost(
    "tenant-a",
    {"level": Level.L2},
    verifier=KeyRegistryVerifier(registry),
)
session = AmcpSession(
    InProcessTransport(host),
    "call-1",
    signer=Ed25519Signer.from_tool_key(tool_key),
)
```

### 5. Level 2 with AWS KMS (production)

The private key never leaves KMS. The signer calls `kms:Sign`; the verifier fetches the public key
once at onboarding and verifies locally. AWS KMS does not offer Ed25519, so this path uses ECDSA
P-256 (`ECDSA_SHA_256`). The adapter takes an injected client and never imports boto3, so `[aws]`
only supplies the client.

```python
import boto3

from auditable_mcp import AmcpSession, AuditHost, InProcessTransport, Level
from auditable_mcp.l2.adapters.aws_kms import AwsKmsSigner, AwsKmsVerifier

kms = boto3.client("kms")
key_arn = "arn:aws:kms:ap-northeast-1:123456789012:key/abcd-..."

signer = AwsKmsSigner(kms, key_arn, event_key_id="tool-1")
verifier = await AwsKmsVerifier.from_kms(kms, {"tool-1": key_arn})

host = AuditHost("tenant-a", {"level": Level.L2}, verifier=verifier)
session = AmcpSession(InProcessTransport(host), "call-1", signer=signer)
```

The signer and verifier are just the `EventSigner` / `SignatureVerifier` seams; a GCP KMS or HSM
adapter drops into the same place.

### 6. A durable host

The host keeps its chain in memory by default. Inject a `LedgerRepository` to persist every accepted
record before it is acknowledged; a persistence failure then fails closed (`unavailable`). The bundled
`InMemoryLedgerRepository` is for tests — implement the protocol over your own store (DynamoDB,
Postgres, …).

```python
from auditable_mcp import AuditHost, InMemoryLedgerRepository, verify_ledger

repo = InMemoryLedgerRepository()  # swap for your own LedgerRepository
host = AuditHost("tenant-a", repository=repo)
# ... run audited actions; each sealed record is written to `repo` before it is accepted ...

# after a restart, resume the same hash chain (seq, tail link, and replay state are rebuilt):
host = await AuditHost.resume("tenant-a", repository=repo)

# audit the full persisted chain, not just this process's records:
report = verify_ledger(await repo.read_all("tenant-a"), host.digest())
```

### 7. Verifying a ledger

`verify_ledger` recomputes the chain from the record bodies, independent of the stored hashes, and
reports tampering, gaps, broken links, uncorrelated outcomes, and (against an out-of-band anchor)
truncation or rewrite.

```python
from auditable_mcp import verify_ledger

report = verify_ledger(host.records(), anchored_digest=trusted_tail_digest)
if not report.ok:
    for issue in report.issues:
        log.error("ledger issue at seq=%s: %s (%s)", issue.seq, issue.kind, issue.detail)
```

## Conformance

The normative JSON Schema and golden vectors are vendored under [`spec/`](spec/) from the
`mcp-audit-extension` spec repo (their single source of truth). A conforming implementation must
reproduce every vector byte-for-byte.

```bash
make spec/check    # fail if the vendored spec drifted from source
make test          # includes the cross-language conformance vectors
```

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
| `src/auditable_mcp/clock.py`          | ISO-8601 timestamp source (`Clock` protocol)                    |
| `src/auditable_mcp/session.py`        | audit-before-act async session (the tool-side core)             |
| `src/auditable_mcp/decorator.py`      | thin `@auditable_tool` wrapper                                  |
| `src/auditable_mcp/host.py`           | host audit subsystem (validate, seal, flag)                     |
| `src/auditable_mcp/l2/`               | Ed25519 signing/verification, key registry, reconciliation      |
| `src/auditable_mcp/l2/adapters/`      | external key backends (AWS KMS)                                 |
| `spec/`                               | vendored normative schema + golden vectors (do not edit)        |

## Note on AI Assistance

The core architecture, design decisions, and core implementations in this project are entirely my own. I used AI tools (Claude, Gemini) strictly under my explicit direction for code generation, text formatting, edge-case verification, and polishing my English prose. All outputs were heavily reviewed, corrected, and finalized by me.

## License

MIT (c) Satoshi Imai
