"""Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).

The chain is recomputed from the record bodies rather than read from the stored hashes, so any
mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
(§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
untrusted storage. `verify_chain` checks chain integrity alone (§8.3); `verify_ledger` adds A-MCP
event-schema validation on top (§7.1).
"""

from dataclasses import dataclass

from auditable_mcp import fields, reasons
from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import Outcome, first_validation_error

# A verifier reports only the §7.6 Tier-1 anomaly kinds. Aliased here for convenience; finer causes
# (out-of-order, a broken previous_hash link) go in the issue `detail` as a Tier-2 diagnostic.
SEQ_GAP = reasons.SEQ_GAP
RECORD_HASH_MISMATCH = reasons.RECORD_HASH_MISMATCH
DIGEST_MISMATCH = reasons.DIGEST_MISMATCH
ORPHANED_OUTCOME = reasons.ORPHANED_OUTCOME


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


def verify_chain(records: list[SealedRecord], anchored_digest: str | None = None) -> VerifyReport:
    """Verify chain integrity alone, independent of the event vocabulary (§8.3).

    Checks sequence order, previous-hash linkage, record-hash recomputation, attempt/outcome
    correlation, and (with `anchored_digest`) the anchored-digest compare. This is the tamper-evidence
    guarantee for any events sealed through `Ledger`; it never inspects the event schema.

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

        if record.seq != index:
            # Out-of-order rolls up to seq-gap (Tier-1); the direction is a Tier-2 detail.
            issues.append(VerifyIssue(seq=record.seq, kind=SEQ_GAP, detail=f'expected seq {index}, got {record.seq}'))
            # end if

        # Recompute from the record body against the recomputed prior link, not the stored one, so a
        # mutation cannot hide behind its own stored hashes. A broken previous_hash link surfaces as a
        # record-hash-mismatch (Tier-1); the "link" detail distinguishes it locally.
        recomputed = compute_record_hash(event, record.seq, record.host_ts, prev_recomputed)
        if record.previous_hash != prev_recomputed:
            issues.append(
                VerifyIssue(
                    seq=record.seq, kind=RECORD_HASH_MISMATCH, detail='previous_hash does not link to prior record'
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
            issues.append(VerifyIssue(seq=record.seq, kind=ORPHANED_OUTCOME, detail=f'outcome={outcome} id={event_id}'))
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


def verify_ledger(records: list[SealedRecord], anchored_digest: str | None = None) -> VerifyReport:
    """Verify chain integrity and A-MCP event-schema conformance (§8.3 + §7.1).

    `verify_chain` followed by a per-record schema check: a record that is not a strict A-MCP event is
    flagged `schema-invalid`. For A-MCP events the result is identical to `verify_chain`.

    Args:
        records: The sealed records in append order (from a `Ledger` or reloaded storage).
        anchored_digest: An out-of-band anchored tail digest to compare against, if available (§8.3).

    Returns:
        A report; `ok` is True only when no issues were found.
    """
    report = verify_chain(records, anchored_digest)
    schema_issues = [
        VerifyIssue(seq=record.seq, kind=reasons.SCHEMA_INVALID, detail=error)
        for record in records
        if (error := first_validation_error(record.event)) is not None
    ]
    if not schema_issues:
        return report
        # end if
    return VerifyReport(
        ok=False,
        count=report.count,
        computed_digest=report.computed_digest,
        issues=[*report.issues, *schema_issues],
    )
    # end def
