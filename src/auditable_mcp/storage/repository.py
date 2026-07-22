"""The durable-ledger repository contract.

Persistence is the integrator's concern (§10.1). The SDK defines this interface and the host writes
through it; a concrete adapter maps it onto DynamoDB, Postgres, files, or anything else. No storage
backend is imported by this package. `SealedRecord.to_dict`/`from_dict` provide the serialization.

Partition isolation (§10.5) is the adapter's responsibility: records for one partition MUST NOT be
returned for another. `append` MUST raise `RepositoryError` on any persistence failure so the host
can fail closed with a retryable `unavailable` (§7.1).
"""

from typing import Protocol

from auditable_mcp.ledger import SealedRecord


class RepositoryError(Exception):
    """A durable-storage operation failed. Adapters raise this so the host can fail closed."""

    # end class


class LedgerRepository(Protocol):
    """A durable, append-only store of sealed records, partitioned per §10.5."""

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Durably append `record` to `partition`.

        Raises:
            RepositoryError: If the record could not be durably persisted.
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
