"""An in-memory `LedgerRepository` for tests and single-process use.

It is durable only for the process lifetime. Production integrators supply a real adapter; this one
exists so the persistence path can be exercised without a backend.
"""

from auditable_mcp.ledger import SealedRecord
from auditable_mcp.storage.repository import RepositoryError


class InMemoryLedgerRepository:
    """Holds sealed records per partition in memory (implements `LedgerRepository`)."""

    def __init__(self) -> None:
        """Initialize with no partitions."""
        self._by_partition: dict[str, list[SealedRecord]] = {}
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Append `record` to `partition` if its `seq` is the next free position.

        Raises:
            RepositoryError: `record.seq` is already taken, or skips ahead of the stored chain.
        """
        records = self._by_partition.setdefault(partition, [])
        if record.seq != len(records):
            raise RepositoryError(f'seq {record.seq} is not the next position ({len(records)}) of {partition}')
            # end if
        records.append(record)
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Return the last record of `partition`, or None if empty."""
        records = self._by_partition.get(partition)
        return records[-1] if records else None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Return a copy of every record of `partition` in append order."""
        return list(self._by_partition.get(partition, []))
        # end def

    # end class
