# Verifying the governed principal (`expected_principal`)

Background for the optional `expected_principal` check added in 0.2.1. It is a factual note on
where each layer's guarantees end, not a critique of any spec.

## What a-MCP and its envelope each establish

An a-MCP audit event is identity-free by design: it records _what_ a tool did internally, not _who_
the governed principal is. A standalone a-MCP chain proves its records were not altered, reordered,
or dropped; it does not attribute them to a tenant or user. Attribution therefore falls to the
transport or storage envelope the host seals a-MCP records into; a-MCP records MAY be sealed under
SEP-3004's contract (a-MCP §9). SEP-3004 is the reference envelope, and its protected core carries a
`principal_id` (SEP-3004 §2.1, a hashed MUST field).

Because `principal_id` sits inside SEP-3004's hashed protected body, SEP-3004's verification (§2.6)
already detects **tampering** of it: recomputing `event_hash` over the protected body catches a
changed `principal_id` exactly as it catches any other altered field, and `previous_hash` threading
catches insertion, deletion, or reordering. The bound identity cannot be altered without detection.

## The comparison outside both verifications' scope

SEP-3004 §2.6 is an **integrity** procedure — `event_hash` recompute plus `previous_hash` threading.
It establishes that each record is unaltered and correctly chained. It does not compare a record's
bound `principal_id` against the principal a given chain or partition is _expected_ to hold, and does
not set out to. a-MCP delegates identity to the envelope and defines no such comparison either.

As a result, a record (or a whole chain) that is **truthfully** labelled for principal A and moved
verbatim into a store or partition meant to hold principal B satisfies both a-MCP's chain integrity
and SEP-3004's §2.6: every hash recomputes, the chain threads, and the bound identity is authentic.
Neither verification compares that authentic identity to B. Where partitions of different principals
share one store, that is the distinction between "these records are intact" and "these records belong
here" - a property orthogonal to integrity. This is the general limit of any integrity-only
verification: identical protected bytes answer "is this intact?", not "does this belong here?".

## What this SDK adds

For deployments that seal a-MCP records inside an identity-binding envelope, this SDK provides that
comparison as an optional verification step:

- `RecordAdapter.principal_of` reads the governed identity out of the envelope - for a SEP-3004
  record, the core `principal_id`.
- `verify_chain` / `verify_ledger` accept an `expected_principal` (the principal the partition is
  provisioned to hold, supplied out-of-band from the audit context). When provided, every record's
  bound identity is compared against it (strict equality); an absent or non-matching identity is
  reported as `principal-mismatch`.

The check is off by default, and both inputs are the caller's to supply. Identity **binding** stays
the envelope's responsibility (SEP-3004's `principal_id`); the **expected** value must come from a
trustworthy, out-of-band source, not from the records being audited. The SDK supplies only the
per-record comparison - the step that sits above both a-MCP's and SEP-3004's integrity verification,
and is only as strong as that verification: if the envelope's seal is forgeable (an unsigned chain an attacker can
re-seal), the bound identity can be rewritten to match the target partition and the comparison will
not catch it. `principal-mismatch` is an SDK-defined anomaly kind, not part of a-MCP's §7.6
vocabulary or of SEP-3004.
