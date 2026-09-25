"""The durable-ledger repository contract.

Persistence is the integrator's concern (§10.1). The SDK defines this interface and the host writes
through it; a concrete adapter maps it onto DynamoDB, Postgres, files, or anything else. No storage
backend is imported by this package. `SealedRecord.to_dict`/`from_dict` provide the serialization.

Partition isolation (§10.5) is the adapter's responsibility: records for one partition MUST NOT be
returned for another. `append` MUST raise `RepositoryError` on any persistence failure so the host
can fail closed with a retryable `unavailable` (§7.1), and is expected to be conditional on the
record's `seq`.
"""

from typing import Protocol

from auditable_mcp.ledger import SealedRecord


class RepositoryError(Exception):
    """A durable-storage operation failed. Adapters raise this so the host can fail closed."""

    # end class


class LedgerRepository(Protocol):
    """A durable, append-only store of sealed records, partitioned per §10.5."""

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Durably append `record` to `partition`, on the condition that its `seq` is not yet taken.

        The append is expected to be conditional on `record.seq` - a conditional put on the key, a
        unique constraint, a compare-and-set on the tail - so that two writers can never both store a
        record at one position (§7.1 atomic sealing). A `RepositoryError` is read as ambiguous: the
        record may have landed and only the acknowledgement been lost, so the host re-reads the tail
        with `load_tail` before it seals again, and adopts the record if it is there.

        Raises:
            RepositoryError: If the record could not be confirmed as durably persisted, including when
                `record.seq` is already taken.
        """
        ...

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Return the last sealed record of `partition`, or None if it is empty (for resume)."""
        ...

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Return every sealed record of `partition` in append order (for resume and verification).

        This may be large; adapters over a real backend should stream internally. It is the input to
        `verify_ledger` for a full-chain audit.
        """
        ...

    # end class
