"""The §8.2 record-hash preimage and chain constants.

The record hash binds a tool-emitted event to the host-assigned ledger fields. The preimage is a
single JSON object — never a delimiter-joined string — so it cannot be forged by canonicalization
tricks (§8.2). Both the host (when sealing) and the tool (when performing Polluted Stop
verification, §7.2) construct it identically and locally; it is never transmitted on the wire.
"""

from auditable_mcp.canonical import canonicalize, sha256_hex

# §8.3: the first record in a partition chains from a genesis link of 64 zeros.
GENESIS_HASH = '0' * 64


def witness_payload(seq: int, host_ts: str, previous_hash: str, record_hash: str) -> bytes:
    """Return the bytes a witness signature covers: canonical host-assigned fields, UTF-8 (§7.1).

    These are the four fields an `accept` already returns. The payload carries no signature field, so
    there is no self-reference, and it is not the §8.2 record-hash preimage: a record sealed with a
    witness signature and the same record sealed without one have the same `record_hash` (§5.2).

    Args:
        seq: The partition-monotonic ledger sequence assigned by the host.
        host_ts: The authoritative host timestamp (ISO-8601).
        previous_hash: The preceding record's `record_hash`.
        record_hash: This record's hash.

    Returns:
        The RFC 8785 canonical form of the four fields, UTF-8 encoded.
    """
    payload = {'host_ts': host_ts, 'previous_hash': previous_hash, 'record_hash': record_hash, 'seq': seq}
    return canonicalize(payload).encode('utf-8')
    # end def


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
