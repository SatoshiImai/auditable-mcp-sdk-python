"""The §7.6 two-tier reason and anomaly vocabulary.

Tier 1 (normative, fixed) codes are the only ones carried on the wire or sealed into the ledger.
They occupy three distinct code spaces — a host reject/unavailable `reason`, a tool abort `reason`,
and a ledger anomaly `kind` — disambiguated by the field they appear in (so `schema-invalid` and
`signature-invalid` legitimately appear in more than one space). Every reject, unavailable, abort,
and anomaly condition this SDK produces maps to exactly one Tier-1 code; finer causes are Tier-2
local diagnostics that MUST NOT reach the wire or ledger.

The constants are `Final` literals so they type-check against the `Literal`-typed model fields.
"""

from typing import Final

# Host reject / unavailable reason codes (§7.6). The tool branches on these.
SCHEMA_INVALID: Final = 'schema-invalid'
REPLAY_DETECTED: Final = 'replay-detected'
SIGNATURE_INVALID: Final = 'signature-invalid'
L2_UNSIGNED: Final = 'l2-unsigned'
UNKNOWN_KEY: Final = 'unknown-key'
INTERNAL_ERROR: Final = 'internal-error'

# Tool abort reason codes, recorded on a fail-closed `aborted` outcome (§7.2, §7.6).
HASH_MISMATCH: Final = 'hash-mismatch'
HOST_REJECTED: Final = 'host-rejected'
HOST_UNAVAILABLE: Final = 'host-unavailable'

# Ledger anomaly kinds a verifier reports (§7.6). SCHEMA_INVALID / SIGNATURE_INVALID above are reused
# here (a distinct code space, disambiguated by the anomaly `kind` field).
RECORD_HASH_MISMATCH: Final = 'record-hash-mismatch'
DIGEST_MISMATCH: Final = 'digest-mismatch'
# SDK-specific: defined by neither a-MCP §7.6 nor SEP-3004. SEP-3004 binds `principal_id` in its
# hashed core and detects tampering of it (§2.6 event_hash recompute), but never compares that identity
# against the principal a partition is expected to hold; a-MCP delegates identity to the envelope
# entirely. This kind flags that comparison - the detection half neither spec defines.
PRINCIPAL_MISMATCH: Final = 'principal-mismatch'
SEQ_GAP: Final = 'seq-gap'
SIGNER_SEQ_GAP: Final = 'signer-seq-gap'
ORPHANED_OUTCOME: Final = 'orphaned-outcome'
UNREPORTED_EGRESS: Final = 'unreported-egress'
