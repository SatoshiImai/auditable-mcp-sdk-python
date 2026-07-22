"""The §8.2 record-hash preimage and chain constants.

The record hash binds a tool-emitted event to the host-assigned ledger fields. The preimage is a
single JSON object — never a delimiter-joined string — so it cannot be forged by canonicalization
tricks (§8.2). Both the host (when sealing) and the tool (when performing Polluted Stop
verification, §7.2) construct it identically and locally; it is never transmitted on the wire.
"""

from auditable_mcp.canonical import canonicalize, sha256_hex

# §8.3: the first record in a partition chains from a genesis link of 64 zeros.
GENESIS_HASH = '0' * 64


def compute_record_hash(event: dict[str, object], seq: int, host_ts: str, previous_hash: str) -> str:
    """Compute the bare-hex SHA-256 record hash over the §8.2 preimage.

    The preimage is ``{event, host_ts, previous_hash, seq}`` serialized via RFC 8785 (JCS) and
    hashed: ``sha256( JCS({event, host_ts, previous_hash, seq}) )``. The `event` must already have
    its absent optional fields omitted, matching the exact bytes the tool emitted.

    Args:
        event: The audit event with absent optionals omitted.
        seq: The partition-monotonic ledger sequence assigned by the host.
        host_ts: The authoritative host timestamp (ISO-8601).
        previous_hash: The preceding record's `record_hash` (genesis for the first record).

    Returns:
        The lowercase hex-encoded SHA-256 record hash.
    """
    preimage = {'event': event, 'host_ts': host_ts, 'previous_hash': previous_hash, 'seq': seq}
    return sha256_hex(canonicalize(preimage))
    # end def
