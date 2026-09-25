"""Sealed records and the per-partition tamper-evident hash chain (§8.3, §10.5).

A `Ledger` instance is exactly one partition: an append-only chain with its own `seq` counter and
genesis. Partition isolation (§10.5) is achieved by holding a separate `Ledger` per partition and
never appending a record to the wrong one — records, sequences, and anomalies never cross. This
module is a pure in-memory primitive; durable storage is a separate adapter concern, so `SealedRecord`
carries `to_dict`/`from_dict` for an integrator's repository to round-trip without re-hashing.
"""

from dataclasses import dataclass

from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash


@dataclass(frozen=True)
class SealedRecord:
    """A tool-emitted event plus the host-assigned ledger fields (§7.1, §8.2).

    `event` is the exact wire form (absent optionals omitted); the record hash is bound to those
    bytes. The field set mirrors the sealed-record shape of the golden chain vector.
    """

    event: dict[str, object]
    seq: int
    host_ts: str
    previous_hash: str
    record_hash: str
    # The countersignature (§5.2, §7.1): written by a host that declares `countersign: "host"`, absent
    # otherwise, and omitted from `to_dict` when absent.
    host_signature: str | None = None
    host_key_id: str | None = None
    log_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible dict for persistence (adapters store this)."""
        record: dict[str, object] = {
            'event': self.event,
            'seq': self.seq,
            'host_ts': self.host_ts,
            'previous_hash': self.previous_hash,
            'record_hash': self.record_hash,
        }
        for name, value in (
            ('host_signature', self.host_signature),
            ('host_key_id', self.host_key_id),
            ('log_id', self.log_id),
        ):
            # Written member by member, so a partial triple reaches a verifier as what it is (§11.4).
            if value is not None:
                record[name] = value
                # end if
            # end for
        return record
        # end def

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> 'SealedRecord':
        """Rebuild a record from its persisted dict, without recomputing the hash.

        Args:
            data: A dict previously produced by `to_dict` (or the golden chain vector shape).

        Returns:
            The reconstructed record; use `verify_ledger` to re-validate its integrity.
        """
        return cls(
            event=data['event'],  # type: ignore[arg-type]
            seq=data['seq'],  # type: ignore[arg-type]
            host_ts=data['host_ts'],  # type: ignore[arg-type]
            previous_hash=data['previous_hash'],  # type: ignore[arg-type]
            record_hash=data['record_hash'],  # type: ignore[arg-type]
            host_signature=data.get('host_signature'),  # type: ignore[arg-type]
            host_key_id=data.get('host_key_id'),  # type: ignore[arg-type]
            log_id=data.get('log_id'),  # type: ignore[arg-type]
        )
        # end def

    # end class


class Ledger:
    """An append-only, single-partition, tamper-evident ledger."""

    def __init__(self, partition: str) -> None:
        """Initialize an empty chain for `partition`."""
        self.partition = partition
        # Chain state is tracked independently of the held records so a durable ledger can resume
        # from a persisted tail without loading the whole history into memory.
        self._records: list[SealedRecord] = []
        self._count = 0
        self._tail_hash = GENESIS_HASH
        # end def

    def __len__(self) -> int:
        """Return the number of sealed records in the chain (including any resumed prefix)."""
        return self._count
        # end def

    def seal(self, event: dict[str, object], host_ts: str) -> SealedRecord:
        """Compute the next sealed record without committing it (§8.3).

        Splitting seal from commit lets the host persist the record durably before accepting it, so a
        persistence failure leaves the in-memory chain untouched.

        Args:
            event: The tool-emitted wire event (absent optionals omitted).
            host_ts: The authoritative host timestamp for this record.

        Returns:
            The sealed record at the next sequence, linked to the current tail.
        """
        record_hash = compute_record_hash(event, self._count, host_ts, self._tail_hash)
        return SealedRecord(
            event=event,
            seq=self._count,
            host_ts=host_ts,
            previous_hash=self._tail_hash,
            record_hash=record_hash,
        )
        # end def

    def commit(self, record: SealedRecord) -> None:
        """Append a record produced by `seal`, advancing the chain state and the tail."""
        self._records.append(record)
        self._count += 1
        self._tail_hash = record.record_hash
        # end def

    def append(self, event: dict[str, object], host_ts: str) -> SealedRecord:
        """Seal and commit `event` in one step (the in-memory path)."""
        sealed = self.seal(event, host_ts)
        self.commit(sealed)
        return sealed
        # end def

    def resume_from(self, tail: SealedRecord | None) -> None:
        """Restore the chain state from a persisted tail, holding no history in memory.

        After resume, `records()` returns only records sealed in this process; the full history lives
        in the repository. `seq` and the tail link continue from where the persisted chain left off.
        """
        self._records = []
        if tail is not None:
            self._count = tail.seq + 1
            self._tail_hash = tail.record_hash
        else:
            self._count = 0
            self._tail_hash = GENESIS_HASH
            # end if
        # end def

    def records(self) -> list[SealedRecord]:
        """Return the records held in memory (a copy); a resumed ledger holds only new ones."""
        return list(self._records)
        # end def

    def digest(self) -> str:
        """Return the tail record hash — the anchorable ledger digest (genesis if empty, §8.3)."""
        return self._tail_hash
        # end def

    # end class
