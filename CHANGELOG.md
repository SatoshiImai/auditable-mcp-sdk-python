# Changelog

Changes to the Auditable MCP Python SDK. The SDK package version is independent of the
`spec_version` it implements (currently `auditable-mcp/0.2`); this file tracks the package.

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

## 0.2.0

- Verification is read-lenient on `spec_version`: a verifier accepts records sealed under any published
  version (`auditable-mcp/0.1`, `/0.1.1`, `/0.2`), while emission and ingest stay pinned to the current
  version. Sealed bytes are immutable evidence.
- `RecordAdapter` (`id_of` / `is_attempt` / `event_of`): the verifier can correlate and schema-check
  a-MCP records sealed inside an outer envelope, without the SDK importing any specific envelope shape.
