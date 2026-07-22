"""Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).

The chain is recomputed from the record bodies rather than read from the stored hashes, so any
mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
(§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
untrusted storage, so each event is re-validated structurally before it is trusted.
"""

from dataclasses import dataclass

from auditable_mcp import fields, reasons
from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import Outcome, first_validation_error

# Verify issue kinds specific to full-chain audit; the host ingest path uses its own vocabulary.
SEQ_GAP = 'seq-gap'
SEQ_OUT_OF_ORDER = 'seq-out-of-order'
PREV_HASH_MISMATCH = 'prev-hash-mismatch'
RECORD_HASH_MISMATCH = 'record-hash-mismatch'
DIGEST_MISMATCH = 'digest-mismatch'


@dataclass(frozen=True)
class VerifyIssue:
    """A single verification failure. `seq` is None for whole-ledger issues (e.g. digest mismatch)."""

    seq: int | None
    kind: str
    detail: str
    # end class


@dataclass(frozen=True)
class VerifyReport:
    """The result of verifying a ledger; `ok` is True only when `issues` is empty."""

    ok: bool
    count: int
    computed_digest: str
    issues: list[VerifyIssue]
    # end class


def verify_ledger(records: list[SealedRecord], anchored_digest: str | None = None) -> VerifyReport:
    """Verify a sealed ledger for non-tampering and completeness.

    Detects: malformed events, sequence gaps / out-of-order, broken previous-hash links, mutated
    record hashes, outcomes with no correlating attempt, and (with `anchored_digest`) a re-linked
    rewrite or truncation.

    Args:
        records: The sealed records in append order (from a `Ledger` or reloaded storage).
        anchored_digest: An out-of-band anchored tail digest to compare against, if available (§8.3).

    Returns:
        A report; `ok` is True only when no issues were found.
    """
    issues: list[VerifyIssue] = []
    attempted_ids: set[object] = set()
    prev_recomputed = GENESIS_HASH

    for index, record in enumerate(records):
        event = record.event

        structural = first_validation_error(event)
        if structural is not None:
            issues.append(VerifyIssue(seq=record.seq, kind=reasons.SCHEMA_INVALID, detail=structural))
            # end if

        if record.seq != index:
            kind = SEQ_GAP if record.seq > index else SEQ_OUT_OF_ORDER
            issues.append(VerifyIssue(seq=record.seq, kind=kind, detail=f'expected seq {index}, got {record.seq}'))
            # end if

        # Recompute from the record body against the recomputed prior link, not the stored one, so a
        # mutation cannot hide behind its own stored hashes.
        recomputed = compute_record_hash(event, record.seq, record.host_ts, prev_recomputed)
        if record.previous_hash != prev_recomputed:
            issues.append(
                VerifyIssue(
                    seq=record.seq, kind=PREV_HASH_MISMATCH, detail='previous_hash does not link to prior record'
                )
            )
            # end if
        if record.record_hash != recomputed:
            issues.append(
                VerifyIssue(seq=record.seq, kind=RECORD_HASH_MISMATCH, detail='stored record_hash != recomputed')
            )
            # end if

        outcome = event.get(fields.OUTCOME)
        event_id = event.get(fields.ID)
        if outcome == Outcome.ATTEMPTED:
            attempted_ids.add(event_id)
        elif event_id not in attempted_ids:
            issues.append(
                VerifyIssue(
                    seq=record.seq, kind=reasons.OUTCOME_WITHOUT_ATTEMPT, detail=f'outcome={outcome} id={event_id}'
                )
            )
            # end if

        prev_recomputed = recomputed
        # end for

    computed_digest = prev_recomputed
    if anchored_digest is not None and anchored_digest != computed_digest:
        issues.append(
            VerifyIssue(
                seq=None, kind=DIGEST_MISMATCH, detail=f'anchored {anchored_digest} != computed {computed_digest}'
            )
        )
        # end if

    return VerifyReport(ok=len(issues) == 0, count=len(records), computed_digest=computed_digest, issues=issues)
    # end def
