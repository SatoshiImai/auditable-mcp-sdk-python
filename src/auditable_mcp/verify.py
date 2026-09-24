"""Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).

The chain is recomputed from the record bodies rather than read from the stored hashes, so any
mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
(§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
untrusted storage. `verify_chain` checks chain integrity alone (§8.3); `verify_ledger` adds A-MCP
event-schema validation on top (§7.1).
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from auditable_mcp import fields, reasons
from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash, witness_payload
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import Outcome, first_sealed_validation_error

# A verifier reports only the §7.6 Tier-1 anomaly kinds. Aliased here for convenience; finer causes
# (out-of-order, a broken previous_hash link) go in the issue `detail` as a Tier-2 diagnostic.
SEQ_GAP = reasons.SEQ_GAP
RECORD_HASH_MISMATCH = reasons.RECORD_HASH_MISMATCH
DIGEST_MISMATCH = reasons.DIGEST_MISMATCH
PRINCIPAL_MISMATCH = reasons.PRINCIPAL_MISMATCH
ORPHANED_OUTCOME = reasons.ORPHANED_OUTCOME
SIGNATURE_INVALID = reasons.SIGNATURE_INVALID
SIGNER_SEQ_GAP = reasons.SIGNER_SEQ_GAP
HOST_SIGNATURE_INVALID = reasons.HOST_SIGNATURE_INVALID


# Resolves a `host_key_id` and verifies a detached signature over canonical bytes (§7.1). Synchronous
# because offline ledger verification reads stored records and does no I/O; `WitnessRegistryVerifier.check`
# is the registry-backed implementation.
WitnessChecker = Callable[[str, str, bytes], bool]

# Verifies a sealed Level-2 event's own `signature` against the out-of-band key registry (§7.4).
# Synchronous for the same reason as WitnessChecker; `KeyRegistryVerifier.check` implements it.
SignatureChecker = Callable[[Mapping[str, object]], bool]


@dataclass(frozen=True)
class VerifyIssue:
    """A single verification failure. `seq` is None for whole-ledger issues (e.g. digest mismatch)."""

    seq: int | None
    kind: str
    detail: str
    # end class


@dataclass(frozen=True)
class VerifyReport:
    """The result of verifying a ledger.

    `ok` is True when the checks that ran found nothing. It is not the same as having checked
    everything: witness determination and Level-2 signature re-verification both need an out-of-band
    registry, and a verifier without one performs neither. §11.4 requires that to be reported rather
    than left as an absence of anomalies - an unchecked signature and a valid one are not the same
    finding - so `unchecked` names every check that was applicable and did not run, and `complete`
    is the answer a caller wants when it means "verified".
    """

    ok: bool
    count: int
    computed_digest: str
    issues: list[VerifyIssue]
    unchecked: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """True when nothing was found and nothing applicable was skipped (§11.4)."""
        return self.ok and not self.unchecked
        # end def

    # end class


def _top_level_id(event: Mapping[str, object]) -> object:
    """Default correlation-key accessor: the top-level `id` of a bare a-MCP event."""
    return event.get(fields.ID)
    # end def


def _top_level_is_attempt(event: Mapping[str, object]) -> bool:
    """Default attempt predicate: a bare a-MCP event whose outcome is `attempted`."""
    return event.get(fields.OUTCOME) == Outcome.ATTEMPTED
    # end def


def _identity_event(event: Mapping[str, object]) -> object:
    """Default embedded-event accessor: the sealed event is itself the a-MCP event."""
    return event
    # end def


def _no_principal(event: Mapping[str, object]) -> object:
    """Default principal accessor: a bare a-MCP event binds no governed identity."""
    del event
    return None
    # end def


@dataclass(frozen=True)
class RecordAdapter:
    """How the verifier reads a-MCP correlation fields, the embedded event, and the governed identity.

    The defaults read a bare, top-level a-MCP event. A caller that seals a-MCP records inside another
    envelope (e.g. SEP-3004) injects accessors that reach into it, so the verifier can correlate,
    schema-check, and principal-match the enveloped event without the SDK importing any specific
    envelope shape. Override only the accessors you need; the rest keep the top-level defaults.

    Attributes:
        id_of: Extract the correlation key that pairs an attempt with its terminal outcome. None means
            the record names no call and is exempt from correlation - an envelope that seals records
            which are not tool calls says so here.
        is_attempt: True when the record is an attempt, False for a terminal outcome.
        event_of: Extract the embedded a-MCP event that `verify_ledger` schema-checks.
        principal_of: Extract the governed identity a record is attributed to, compared against
            `expected_principal`. Defaults to None - a bare a-MCP event binds no identity (attributing a
            record to a principal is the envelope's concern, not a-MCP's). A deployment that seals
            records inside an identity-binding envelope (e.g. SEP-3004, whose protected core carries
            `principal_id`) reads that identity here. Normalization (e.g. tenant hierarchy) belongs
            here, so the comparison stays a strict equality.
    """

    id_of: Callable[[Mapping[str, object]], object] = _top_level_id
    is_attempt: Callable[[Mapping[str, object]], bool] = _top_level_is_attempt
    event_of: Callable[[Mapping[str, object]], object] = _identity_event
    principal_of: Callable[[Mapping[str, object]], object] = _no_principal
    # end class


DEFAULT_ADAPTER = RecordAdapter()


def verify_chain(
    records: list[SealedRecord],
    anchored_digest: str | None = None,
    *,
    adapter: RecordAdapter = DEFAULT_ADAPTER,
    expected_principal: object | None = None,
    witness_checker: WitnessChecker | None = None,
    signature_checker: SignatureChecker | None = None,
) -> VerifyReport:
    """Verify chain integrity alone, independent of the event vocabulary (§8.3).

    Checks sequence order, previous-hash linkage, record-hash recomputation, attempt/outcome
    correlation, the principal binding (when `expected_principal` is set), and (with `anchored_digest`)
    the anchored-digest compare. This is the tamper-evidence guarantee for any events sealed through
    `Ledger`; it never inspects the event schema.

    Args:
        records: The sealed records in append order (from a `Ledger` or reloaded storage).
        anchored_digest: An out-of-band anchored tail digest to compare against, if available (§8.3).
        adapter: How to read the correlation key and attempt flag from each sealed record. Defaults to
            a bare top-level a-MCP event; inject accessors to correlate records sealed inside an
            envelope (e.g. SEP-3004). A record whose `id_of` is None names no call and is exempt from
            attempt/outcome correlation.
        expected_principal: When set, every record's `adapter.principal_of` is compared against it
            (strict equality); a mismatch, or an absent identity, is flagged as `principal-mismatch`.
            This is an SDK check, not an a-MCP anomaly: it detects a cross-partition transplant only
            when records are sealed inside an identity-binding envelope. None (default) skips it.
        witness_checker: Resolves a `host_key_id` and verifies a witness signature over the canonical
            host-assigned fields (§7.1). A record carrying no signature is unwitnessed, which is a
            state and not an anomaly (§5.2); one whose signature fails is `host-signature-invalid`.
            Without a checker, records that do carry signatures are counted in `unchecked` (§11.4).
        signature_checker: Verifies a sealed Level-2 event's own `signature` against the key registry
            (§7.4). Optional for a pure ledger auditor (§10.6); without it, records carrying a
            `signature` are counted in `unchecked` rather than reported as verified (§11.4).

    Returns:
        A report; `ok` is True only when no issues were found.
    """
    issues: list[VerifyIssue] = []
    attempted_ids: set[object] = set()
    prev_recomputed = GENESIS_HASH
    witness_unchecked = False
    l2_unchecked = False
    last_signer_seq: dict[str, int] = {}

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

        # A record that names no call is not one half of a pair. An envelope may seal records that are not
        # tool calls at all - a prompt, a model's reasoning, a turn boundary - and their adapter returns
        # None here to say so. Correlating them would report every one of them as an outcome missing its
        # attempt, which is the check crying wolf on a chain that is intact.
        event_id = adapter.id_of(event)
        if event_id is not None:
            if adapter.is_attempt(event):
                attempted_ids.add(event_id)
            elif event_id not in attempted_ids:
                issues.append(
                    VerifyIssue(
                        seq=record.seq,
                        kind=ORPHANED_OUTCOME,
                        detail=f'terminal outcome with no matching attempt, id={event_id}',
                    )
                )
                # end if
            # end if

        # Per-record, fail-closed (an absent identity != the expected one): a valid chain transplanted
        # under the wrong principal passes hash + chain but fails this.
        if expected_principal is not None and adapter.principal_of(event) != expected_principal:
            issues.append(
                VerifyIssue(
                    seq=record.seq,
                    kind=PRINCIPAL_MISMATCH,
                    detail=f'record principal does not match expected {expected_principal!r}',
                )
            )
            # end if

        # §11.4 names the Level-2 re-verification it did not perform as well: this verifier checks the
        # chain, not the event signatures (§10.6 makes that optional), and an unchecked signature must
        # not read as a verified one.
        # Read through the adapter: a record sealed inside an envelope (e.g. SEP-3004) keeps the a-MCP
        # event, and its signature, inside it, so a top-level lookup would miss exactly the deployment
        # §10.10 recommends and report a complete verification of signatures nobody checked.
        inner = adapter.event_of(event)
        signed = isinstance(inner, Mapping) and inner.get(fields.SIGNATURE) is not None
        if signed and signature_checker is None:
            l2_unchecked = True
        elif signed and signature_checker is not None:
            assert isinstance(inner, Mapping)
            if not signature_checker(inner):
                issues.append(
                    VerifyIssue(seq=record.seq, kind=SIGNATURE_INVALID, detail='event signature does not verify')
                )
                # end if
            # end if

        # §7.4 / §11.4: a forward gap in a partition-bound `key_id` may mark a suppressed event. It is
        # computable from the records alone - no registry - so a verifier that omits it is silently
        # dropping the one suppression signal the ledger carries.
        if isinstance(inner, Mapping):
            key_id, signer_seq = inner.get(fields.KEY_ID), inner.get(fields.SIGNER_SEQ)
            if isinstance(key_id, str) and isinstance(signer_seq, int):
                last = last_signer_seq.get(key_id)
                if last is not None and signer_seq > last + 1:
                    issues.append(
                        VerifyIssue(
                            seq=record.seq,
                            kind=SIGNER_SEQ_GAP,
                            detail=f'signer_seq jumped {last} -> {signer_seq} for key_id {key_id!r}',
                        )
                    )
                    # end if
                last_signer_seq[key_id] = signer_seq
                # end if
            # end if

        # Witness determination (§11.4): by the signature alone, never inferred from another field.
        if (record.host_signature is None) != (record.host_key_id is None):
            # §7.1 pairs the two fields, and the response schema enforces it on the wire - but a stored
            # record is not schema-checked, so a half-present pair reaches a verifier and establishes
            # nothing. Silently ignoring it would be neither a check nor a report.
            issues.append(
                VerifyIssue(
                    seq=record.seq,
                    kind=HOST_SIGNATURE_INVALID,
                    detail='host_signature and host_key_id must appear together or not at all',
                )
            )
        elif record.host_signature is not None and record.host_key_id is not None:
            if witness_checker is None:
                witness_unchecked = True
            else:
                payload = witness_payload(record.seq, record.host_ts, record.previous_hash, record.record_hash)
                if not witness_checker(record.host_key_id, record.host_signature, payload):
                    issues.append(
                        VerifyIssue(
                            seq=record.seq,
                            kind=HOST_SIGNATURE_INVALID,
                            detail=f'witness signature does not verify for host_key_id {record.host_key_id!r}',
                        )
                    )
                    # end if
                # end if
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

    unchecked = tuple(
        name for name, applicable in (('witness', witness_unchecked), ('level-2-signature', l2_unchecked)) if applicable
    )
    return VerifyReport(
        ok=len(issues) == 0,
        count=len(records),
        computed_digest=computed_digest,
        issues=issues,
        unchecked=unchecked,
    )
    # end def


def verify_ledger(
    records: list[SealedRecord],
    anchored_digest: str | None = None,
    *,
    adapter: RecordAdapter = DEFAULT_ADAPTER,
    expected_principal: object | None = None,
    witness_checker: WitnessChecker | None = None,
    signature_checker: SignatureChecker | None = None,
) -> VerifyReport:
    """Verify chain integrity and A-MCP event-schema conformance (§8.3 + §7.1).

    `verify_chain` followed by a per-record schema check: a record whose embedded event is not a valid
    A-MCP event is flagged `schema-invalid`. The check is read-lenient on `spec_version` (any published
    version, not only the current one), so a chain sealed under an earlier version still verifies - its
    bytes are immutable evidence. For valid A-MCP events the result is identical to `verify_chain`.

    Args:
        records: The sealed records in append order (from a `Ledger` or reloaded storage).
        anchored_digest: An out-of-band anchored tail digest to compare against, if available (§8.3).
        adapter: How to read the correlation fields and extract the embedded a-MCP event. Defaults to a
            bare top-level a-MCP event; inject `event_of` to schema-check an event sealed inside an
            envelope (e.g. SEP-3004).
        expected_principal: When set, each record's `adapter.principal_of` is compared against it, else
            `principal-mismatch` (an SDK check); forwarded to `verify_chain`.

    Returns:
        A report; `ok` is True only when no issues were found.
    """
    report = verify_chain(
        records,
        anchored_digest,
        adapter=adapter,
        expected_principal=expected_principal,
        witness_checker=witness_checker,
        signature_checker=signature_checker,
    )
    schema_issues = [
        VerifyIssue(seq=record.seq, kind=reasons.SCHEMA_INVALID, detail=error)
        for record in records
        if (error := first_sealed_validation_error(adapter.event_of(record.event))) is not None
    ]
    if not schema_issues:
        return report
        # end if
    return VerifyReport(
        ok=False,
        count=report.count,
        computed_digest=report.computed_digest,
        issues=[*report.issues, *schema_issues],
        unchecked=report.unchecked,
    )
    # end def
