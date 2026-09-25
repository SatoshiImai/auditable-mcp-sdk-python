# Changelog

Changes to the Auditable MCP Python SDK. The SDK package version is independent of the
`spec_version` it implements (currently `auditable-mcp/0.3`); this file tracks the package.

## 0.3.0

Breaking, tracking spec `auditable-mcp/0.3`.

### Breaking changes

- **Emission moves to `auditable-mcp/0.3`**, so every golden digest changes. The verifier stays
  read-lenient: a record sealed under any published version still verifies, each against the schema of
  its own version.
- **An audit session is one `tools/call` (§6.3).** The event's `call_id` becomes `session_id`, a UUID
  the host issues. `AuditHost.open_session` / `close_session` / `session()` issue and end one, and the
  host refuses events of a session it did not issue. `AmcpSession` takes that id; `new_session_id()`
  mints one for a tool that is its own host.
- **`signer_seq` counts from zero in each session (§7.4).** Nothing about the count outlives the call,
  so there is no store to hold or share it. The host keeps two bounds per session: the replay bound,
  which moves only when a decision is sealed, and the gap bound, which moves on every event whose
  signature verifies.
- **A byte-identical repeat of a sealed attempt gets the original accept (§7.1).** A retry after a
  lost answer is idempotent rather than a replay. `UnavailableResponse.retryable` is removed.
- **`AuditCapability` gains a REQUIRED `countersign`** of `none` or `host` (§5.2, §6.1).
- **`negotiate(host, tool)` replaces `capability_satisfies`.** The two axes run in opposite
  directions, so the fit splits into `level_satisfies` and `countersign_satisfies`, and the result
  carries a `NegotiationOutcome`: a host that declared nothing is an absent negotiation, not a failed
  one, and a call that carries no audit session is `NO_SESSION`.
- **Signatures are JOSE (§12.1).** Every signature is unpadded base64url, and the algorithms are named
  `Ed25519` (RFC 9864) and `ES256`. A JWK that says `EdDSA` is still read; one whose `alg` contradicts
  its key is refused.

### Added

- **The countersignature (§5.2).** `AuditHost` takes a `Countersigner` (`Ed25519Countersigner`
  locally, `AwsKmsCountersigner` through KMS) and signs `{host_ts, log_id, previous_hash, record_hash,
  seq}` of every record it seals. The accept carries `host_signature`, `host_key_id` and `log_id`
  together, and `SealedRecord` stores them. `AmcpSession` takes a `CountersignatureVerifier`
  (`CountersignatureRegistryVerifier`) and enforces §7.2's precedence: status, then the
  countersignature, then the hash.
- **The MCP wire binding** (`auditable_mcp.mcp`, optional extra `[mcp]`), in both of §6's forms. Under
  MCP 2026-07-28 the exchange rides the `tools/call` as Multi Round-Trip Requests (§6.4); under the
  `initialize` handshake it is `audit/attempt` and `audit/outcome` (§6.5). `McpAuditTransport` hands
  the handler one `McpAuditCall` per `tools/call`; `McpAuditReceiver` issues the session, seals what
  comes back, and closes the session when the call ends. The seams declare the extension in whichever
  handshake arrives and read the peer's back. The §6.4 seam keeps the suspended handler in the process,
  so a call's retries must reach that process; it does not serialize a handler into `requestState`.
- **§6.4 over Streamable HTTP, and round affinity.** `AuditedStreamableHTTP` wraps the official
  `StreamableHTTPSessionManager` and serves each audited call on a connection of its own behind the
  §6.4 seam, applying the checks the official modern handler applies. Every request under the
  2026-07-28 envelope has `Auditable-Mcp-Session` checked against the body (`-32020`, HTTP 400). The
  host seam puts `Auditable-Mcp-Session` on every request of an audited call and gives each retry it
  builds the per-request headers of the request it repeats, so the official modern handler no longer
  rejects the retry for a missing `Mcp-Method`. Round tokens are `amcp.<instance>.<secret>`; an instance
  that receives a retry it does not hold forwards it through `forward` (`HttpForwarder` resolves
  instances the deployment knows, marks the request `Auditable-Mcp-Forwarded`, and never forwards a
  marked one) or refuses it in-band and performs nothing. `principal_of` binds each call to the
  principal that opened it. `negotiate_unaudited` gives a tool the §6.1 result for a call the official
  handler serves. The walk runs over HTTP too (`make walk/http`), with two-instance cases.
  A tool's own input rounds go out under entry-issued tokens, so they route and forward like the seam's;
  a request of an audited call that carries a `requestState` is never served as a first request, and a
  first request for a session already held is refused (`this session is already open (§6.3)`). A held
  call with an operation under way is never evicted. A forward that fails after the retry was sent is
  answered `-32603` (`forwarding failed after the retry was sent; its outcome is unknown (§6.4)`), not
  as a replay; `ForwardNotDeliveredError` and `ForwardOutcomeUnknownError` let a custom `forward` say
  which it was. Each request reaches the tool's handler, and each host request the client transport, in
  the `contextvars` of the request or caller it belongs to. Held calls follow one lifetime rule: a
  running call is neither evicted nor expired, one holding undelivered outcomes expires but is not
  evicted. `McpAuditCall.request` and `.access_token` (and `access_token_of`) give a resumed handler the
  request it is served under now. The `mcp` extra is capped at `<2.3`, since the binding imports the
  official SDK's context-carrying streams from private modules.
- **`transport_for`** picks what §6.2 permits for a call that was not negotiated, and refuses to
  return a transport for the third, non-conformant posture. `UnnegotiatedCallError` is what it raises.
- **Atomic sealing (§7.1).** One lock per partition across validation, sealing and commit, so
  concurrent attempts take distinct positions in the chain. `anyio` joins the core dependencies.
- **Atomic numbering (§7.4).** One section per session across numbering and emission, so concurrent
  Level-2 actions reach the host in the order they were numbered, whatever the signer's latency.
- **`unresolved-attempt`.** A session closed with an accepted attempt and no terminal outcome is
  flagged on the host.
- **Key exchange (§5.1).** `public_jwk` / `public_key_of` / `jwk_thumbprint` carry a registry entry as
  a JWK (RFC 7517, 7638) with its role, and `tool_key_pkcs8` / `load_tool_key` carry a tool's private
  key as PKCS#8. `KeyRole` separates tool keys from host keys.
- **AWS KMS signs `ES256` or `Ed25519`**, chosen by the key's spec, and publishes its public keys.
- **`unaccounted_signer_seq`** (§11.4): the verifier's accounting of a session's missing numbers, reported as maximal runs (`first`, `last`) computed from the gaps between sealed values, so a value near 2^53 costs one entry. Sealed aborted refusals account for values.
- **`VerifyReport.unchecked` and `.complete`.** A verifier without the out-of-band registry makes no
  countersignature determination, and says so.
- **`countersignature_required`** on `verify_chain` / `verify_ledger` (§11.4): the out-of-band
  statement that the chain must be countersigned. An uncountersigned record is then
  `host-signature-invalid`, since a countersignature can be stripped though not forged.
- **`ExpectedIdentity`** and `expected_identity` on `verify_chain` / `verify_ledger` (§10.10): the
  `log_id` and the set of `host_key_id`s a partition is expected to be countersigned under. A record
  naming another `log_id`, countersigned under a key outside the set, or not carrying the whole
  countersignature triple is `principal-mismatch`, including a record that cannot otherwise be
  validated. A `log_id` is distinct only among one host's chains, so the key is part of the identity.
- **`AmcpUsageError`** separates an integrator error from a transport fault, so the binding's own
  refusals are not filed as `host-unavailable`.
- `AuditRequestMeta` / `AuditResultMeta` (the §6.4 `_meta` objects); `EarlierSealedAuditEvent`;
  `first_sealed_validation_error`, `signature_payload`, `countersignature_payload` and
  `verify_detached_signature` at the package root; `reasons.UNRESOLVED_ATTEMPT`,
  `HOST_UNCOUNTERSIGNED` and `HOST_SIGNATURE_INVALID`.

- **`AuditHost.resume` records `unresolved-attempt`** for every sealed attempt without a terminal
  outcome, since a restart ends every call that was in flight, and never issues a session id found in
  the ledger again (§6.3).
- **`McpAuditReceiver` warns once per connection** when the tool's declaration is missing or does not
  meet the host's requirement, so a host that requires Level 2 does not get an unaudited call silently.
- **`McpAuditTransport.call` takes the raw JSON-RPC id** and matches it by type and value, so `1` and
  `"1"` are two calls and neither is audited as the other. With the high-level `MCPServer`, pass
  `ctx.request_context.request_id`; its string form `ctx.request_id` is refused with an error that says so.

- **`McpAuditReceiver` bounds its own wait on the endpoint** (`request_timeout`, 30 s by default) and answers
  an attempt the endpoint has not decided by then `unavailable`, and delivers a call's final result to
  the client without waiting on the audit work queued for the session. A stalled audit subsystem no
  longer holds a call's result, or, under §6.4, loses it past the tool's own bound.
- **One deadline per §6.4 round.** The whole of a round's processing - its outcomes and its attempts,
  in array order - runs under one `request_timeout` from the moment the session's queue takes it up,
  and the retry (or the round passed up to the client) goes when it passes at the latest. An attempt
  reached after the deadline is answered `unavailable` without being handed to the endpoint; one in
  progress is answered `unavailable` and its decision completes in the background; outcomes not yet
  sealed are queued behind in the session's lane and sealed after the retry. A round the host stops
  following delivers its error under the same deadline. Before, each attempt had a bound of its own and
  an outcome none, so a round of N attempts cost N bounds and the tool had given up on the call by the
  time its retry came.
- **The host's caller no longer sees the audit.** `McpAuditReceiver` removes this extension's member
  from `_meta` - and an empty `_meta` with it - in every result it passes up, final or a round carrying
  `inputRequests` (§6.4).
- **Closing `McpAuditReceiver` is bounded and closes every session.** It waits up to `request_timeout`
  for the work queued in the lanes of the calls in flight and of the concluding ones, then closes each
  of their sessions, each close bounded as long again. A session whose work did not finish is logged
  at WARNING by id. Before, a concluding call's session was never closed when its seal was still
  queued, and a store that hung held the close forever.
- **Rounds waiting on the client are bounded.** A round passed up with `inputRequests` is held for the
  client's retry under `MAX_IDLE_SESSIONS`, least recently held evicted with a warning; the eviction
  ends the call and closes its session, which records its accepted attempts `unresolved-attempt`. A
  second round held under the same `requestState` evicts the first. The retry is found by a lookup, not
  a scan of every call.
- **A late retry gets the call's final answer (§6.4).** A tool whose handler concluded while a round was
  out keeps its final frame and outcomes until that round's retry arrives, however late, bounded only
  by `MAX_IDLE_SESSIONS` (least recently concluded evicted with a warning) and the connection. The
  retry is answered with the result carrying the trailing outcomes, or with the outcomes-only round and
  then the error; what it answers for attempts the tool already treated as unanswered is ignored.
  Before, the final frame was dropped after `request_timeout` and the retry was refused as a replay.

### Fixed

- **A host seam cancelled by its transport left its task group entered.** Streamable HTTP fails a
  request inside the transport's own task group, which cancels the session around the receiver; the
  receiver now exits its task group whatever interrupts its close, and closes every audit session it
  held under a shielded bound, so the attempts the tool never resolved are still recorded (§6.3). A
  host job once taken up (an outcome seal above all) is no longer cut short by that cancellation, and the
  jobs still queued are done while the connection closes, within `request_timeout`; what is still
  undone then is logged, with the number of outcomes not sealed, and its attempts are recorded
  `unresolved-attempt`. Each job done while closing is held to the close bound itself.
- **An attempt the binding already answered `unavailable` records nothing.** `AuditEndpoint.handle_attempt` takes a `deadline`, the time after
  which the receiver has answered the tool; `AuditHost` answers an attempt it takes up after that
  `unavailable` without recording it. A stalled audit subsystem no longer seals, or refuses as
  `replay-detected` against a closed session, an attempt the tool was told was not recorded; the tool's
  `aborted` refusal is the ledger's record of it.
- **A tool behind `McpAuditTransport` exits when its client closes stdio.** The seam closes the
  transport's write stream once its pumps stop, so the stdio writer ends and the process exits on EOF
  instead of waiting for its client to terminate it.
- **A seal interrupted by cancellation is treated as an ambiguous write.** Any `BaseException` during
  the countersign or the append marks the tail uncertain before it propagates, so the next event
  re-reads the stored tail and adopts a record that landed instead of forking the chain.
- **Revocation survives export and import (§10.9).** `KeyRegistry.to_jwks` writes `amcp_revoked: true`
  (`REVOKED_MEMBER`) on a revoked entry and `public_jwk(..., revoked=True)` renders it; `load_jwks` holds
  such an entry revoked, and an unrevoked copy of a key already revoked does not lift the revocation. A
  non-boolean `amcp_revoked` is refused. `revoke()` of a `key_id` never registered raises `ValueError`
  rather than doing nothing.
- **`load_kms_public_key` reads an Ed25519 KMS key.** It returns the Ed25519 public key for an
  `ECC_NIST_EDWARDS25519` key and the elliptic-curve key for a P-256 one, as before, and refuses any
  other. The README builds the signer with `AwsKmsSigner.from_kms`, and the constructor's docstring
  says it defaults to ECDSA P-256.
- **`AuditedAction.__aexit__` is annotated `-> None`.** It never suppresses, and `-> bool` made a type
  checker read a function that returns inside `async with session.action(...)` as one that may fall
  through (`Missing return statement` under `mypy --strict`).
- **`AwsKmsVerifier.from_kms` reads the key spec**, verifying an `ECC_NIST_EDWARDS25519` key as
  `Ed25519` rather than registering every KMS key as `ES256`.
- **A session id that is not a lowercase UUID is refused when `AmcpSession` is built**, as an
  `AmcpUsageError`, rather than at the first action.
- **An attempt of a concluded operation is refused (§7.1 rule 4).** An attempt whose `session_id` and
  `id` already have a sealed outcome is rejected `replay-detected`, unless it is a byte-identical
  repeat of the sealed attempt, which is answered from the ledger. An attempt answered `unavailable`
  and then concluded by its sealed refusal can no longer be sent again and accepted. The verifier
  correlates an outcome, and accounts for a refusal's `signer_seq`, only against attempts sealed
  before it.
- **The body's error is never replaced by the terminal outcome's.** An outcome has no response channel
  (§6), so losing one is a completeness gap the host resolves (§10.8); it is logged, not raised.
- **A tool-side failure is not reported as the host's.** A signer that fails reaches the caller as
  itself rather than as `AmcpAbortedError(host-unavailable)`.
- **Every abort path emits best-effort**, so a failure while recording the abort does not replace why
  the tool stopped (§7.2).
- **A registry compares keys, not objects.** Re-registering a `key_id` with the same key read again is
  the idempotent case §10.9 permits.
- **The environment installs what the package declares.** `make env/sync` installs `[aws,mcp]`, so the
  binding's tests and the walk run against `mcp>=2.2`.

### Known limit

- `mcp>=2.2` drops an `error` member that arrives beside a `result`, so spec §6's rule that the error
  stands cannot be applied above it. The limit is stated where the decision is read, and a test pins
  the behaviour.

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
