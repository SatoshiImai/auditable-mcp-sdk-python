# Changelog

Changes to the Auditable MCP Python SDK. The SDK package version is independent of the
`spec_version` it implements (currently `auditable-mcp/0.3`); this file tracks the package.

## 0.3.0

Breaking, tracking spec `auditable-mcp/0.3`.

### Breaking changes

- **Emission moves to `auditable-mcp/0.3`**, so every golden digest changes; the verifier stays
  read-lenient and still accepts records sealed under any published version.
- **`AuditCapability` gains a REQUIRED `witness`** of `none` or `host` (§5.2, §6.1). A capability
  built without it no longer validates.
- **`negotiate(host, tool)` replaces the single-axis fit.** `capability_satisfies` splits into
  `level_satisfies` and `witness_satisfies`, because the axes run in opposite directions, and the
  result carries a `NegotiationOutcome` rather than a boolean `satisfied`: a host that declared
  nothing is an absent negotiation, not a failed one, and §6.2 governs it differently.

### Added

- **The witness axis.** `AuditHost` takes a `WitnessSigner` (`Ed25519WitnessSigner` locally) and
  signs the host-assigned fields of every record it seals, attempts and outcomes alike; an outcome's
  signature is written into the ledger, since `audit/outcome` has no response channel. `AmcpSession`
  takes a `WitnessVerifier` (`WitnessRegistryVerifier`) and enforces §7.2's precedence — status, then
  the witness, then the hash. `SealedRecord` carries `host_signature` / `host_key_id` and omits them
  when absent, so an unwitnessed record persists byte-identically to before.
- **The terminal outcome never replaces the body's error.** `__aexit__` promised not to suppress the
  body's exception and then did, whenever emitting the outcome failed: the caller got the audit
  layer's `ConnectionError` and their own error was demoted to `__context__`. An outcome has no
  response channel (§6), so losing one is a completeness gap the host resolves (§10.8) - it is
  logged, not raised.
- **A tool-side failure is no longer reported as the host's.** Building the attempt signs it under
  Level 2, and that happened inside the transport-fault conversion, so a dead KMS surfaced as
  `AmcpAbortedError(host-unavailable)` - an operator sent to a host that was answering perfectly
  well. It reaches the caller as itself now.
- **Every abort path emits best-effort.** Only the transport-fault path did; on the other four a
  failure while recording the abort replaced the abort, so the caller saw the second failure instead
  of why the tool stopped (§7.2).
- **A registry compares keys, not objects.** Re-registering a `key_id` with the same key read again
  - from disk, from a reloaded registry - was refused as a different key, because the comparison was
  by object identity. §10.9 forbids binding a `key_id` to a *different* key; the same one held twice
  is the idempotent case it permits.
- **`AmcpUsageError`** separates an integrator error from a transport fault. The session's
  fail-closed catch was converting the MCP binding's own refusals - an unnegotiated send, a
  handshake not seen - into `host-unavailable`, filing an `aborted` record that blamed the host for
  the integrator's wiring. It now re-raises them.
- **Atomic numbering (§7.4).** `AmcpSession` holds one section per signer across numbering and
  emission, so concurrent Level-2 actions reach the host in the order they were numbered. Without
  it, a remote signer's uneven latency let a later event overtake an earlier one, the host rejected
  the earlier as a replay, and the ledger recorded `replay-detected` against a tool that had done
  nothing wrong. Level 1 numbers nothing and is not serialized.
- **Atomic sealing (§7.1).** `AuditHost` holds one lock per partition across validation, sealing and
  commit. Without it, concurrent attempts against a durable or witnessing host read the same chain
  tail, take the same `seq` and `previous_hash`, and are all answered `accept` - the tool acts on
  records the ledger cannot hold. The in-memory, unwitnessed host was the only configuration without
  the window, which is why the suite never saw it. `anyio` joins the core dependencies for the lock.
- **`signature_payload` and `first_sealed_validation_error`** are exported from the package root,
  where their counterparts already were (`witness_payload`, `first_validation_error`) and where the
  TypeScript port already had them.
- **`degradation.transport_for`** picks what §6.2 permits for a session that was not negotiated, and
  refuses to return a transport for the third, non-conformant posture.
- **The MCP wire binding** (`auditable_mcp.mcp`, optional extra `[mcp]`). `McpAuditTransport` (tool)
  and `McpAuditReceiver` (host) carry `audit/attempt` and `audit/outcome` on a real MCP connection by
  sitting between the session and the transport streams; neither official SDK dispatches a method
  outside its own request union, and neither has to. The seams also declare this extension on
  `initialize` and read the peer's declaration back, which the Python MCP client has no other way to
  do. Three §6 obligations are enforced only here: an attempt is never batched, the wait for a
  decision is bounded and fails closed, and an unnegotiated session carries no audit message at all.
- **`VerifyReport.unchecked` and `.complete`** (§11.4). A verifier without the out-of-band registry
  performs no witness determination, and saying so is not optional even though the check is.
- `reasons.HOST_UNWITNESSED` / `HOST_SIGNATURE_INVALID`; `hashing.witness_payload`;
  `verification.verify_detached_signature`.

## 0.2.1

Non-breaking. Existing code is unaffected; the new check is off unless a deployment opts in.

### Added

- `RecordAdapter.principal_of` and an `expected_principal` argument on `verify_chain` / `verify_ledger`.
  When an expected principal is supplied, each record's extracted governed identity is compared against
  it (strict equality); an absent or non-matching identity is reported as a `principal-mismatch` anomaly.
  This lets a verifier detect a cross-partition transplant when a-MCP records are sealed inside an outer
  envelope (for example SEP-3004) that binds the principal. Identity binding is the envelope's concern;
  the SDK supplies only the read seam (`principal_of`) and the comparison.
- `principal-mismatch`: a new SDK-defined anomaly kind (in neither a-MCP §7.6 nor SEP-3004), emitted on
  `VerifyIssue.kind`. As with every kind, the public contract is the fixed string value; the
  `PRINCIPAL_MISMATCH` constant lives in `auditable_mcp.reasons` alongside its siblings.

Defaults are inert: `principal_of` returns `None` and `expected_principal` defaults to `None`, so the
comparison runs only when a deployment provides both an adapter that reads its envelope's identity and
the partition's expected principal.

See [docs/expected-principal.md](docs/expected-principal.md) for the background: what a-MCP, SEP-3004, and this check each cover.

### Fixed

- `verify_chain` no longer reports a record whose `RecordAdapter.id_of` returns `None` as an
  `orphaned-outcome`. `None` means the record names no call, so it is exempt from attempt/outcome
  correlation: an envelope that seals records which are not tool calls (a prompt, a model's reasoning, a
  turn boundary) previously had every one flagged as a terminal outcome with a missing attempt, so an
  intact chain verified as broken. The exemption is per record and seeds nothing; a real tool outcome
  whose correlation key is present is still reported. Correlation of records that do name a call is
  unchanged.

## 0.2.0

- Verification is read-lenient on `spec_version`: a verifier accepts records sealed under any published
  version (`auditable-mcp/0.1`, `/0.1.1`, `/0.2`), while emission and ingest stay pinned to the current
  version. Sealed bytes are immutable evidence.
- `RecordAdapter` (`id_of` / `is_attempt` / `event_of`): the verifier can correlate and schema-check
  a-MCP records sealed inside an outer envelope, without the SDK importing any specific envelope shape.
