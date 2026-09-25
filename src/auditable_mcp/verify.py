"""Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).

The chain is recomputed from the record bodies rather than read from the stored hashes, so any
mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
(§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
untrusted storage. `verify_chain` checks chain integrity alone (§8.3); `verify_ledger` adds A-MCP
event-schema validation on top (§7.1).
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from auditable_mcp import fields, reasons
from auditable_mcp.canonical import MAX_SAFE_INTEGER, CanonicalizationError, outside_canonical_domain
from auditable_mcp.hashing import GENESIS_HASH, compute_record_hash, countersignature_payload
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.models import KNOWN_SPEC_VERSIONS, Outcome, first_sealed_validation_error

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
REPLAY_DETECTED = reasons.REPLAY_DETECTED
SCHEMA_INVALID = reasons.SCHEMA_INVALID

# Before v0.3 an event named its call by `call_id` rather than by an audit session (§11.4 reads each
# record in its own version's shape).
_EARLIER_CALL_ID = 'call_id'


# Resolves a `host_key_id` and verifies a detached signature over canonical bytes (§7.1). Synchronous
# because offline ledger verification reads stored records and does no I/O; `CountersignatureRegistryVerifier.check`
# is the registry-backed implementation.
CountersignatureChecker = Callable[[str, str, bytes], bool]

# Verifies a sealed Level-2 event's own `signature` against the out-of-band key registry (§7.4).
# Synchronous for the same reason as CountersignatureChecker; `KeyRegistryVerifier.check` implements it.
SignatureChecker = Callable[[Mapping[str, object]], bool]


@dataclass(frozen=True)
class ExpectedIdentity:
    """The identity a partition is expected to hold, supplied out-of-band (§10.10 construction 1).

    A `log_id` is distinct only among one host's chains, so the identity is the `log_id` together with
    the `host_key_id`s that host countersigns the partition under.

    Attributes:
        log_id: The `log_id` every record of the partition is countersigned under.
        host_key_ids: The `host_key_id`s the partition's host countersigns under.
    """

    log_id: str
    host_key_ids: frozenset[str]
    # end class


# The countersignature triple's size: a record binds an identity only when it carries all of it.
_TRIPLE_SIZE = 3

# Published versions in publication order; a chain's versions do not go backwards (§11.4).
_VERSION_RANK = {version: rank for rank, version in enumerate(KNOWN_SPEC_VERSIONS)}


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
    everything: countersignature determination and Level-2 signature re-verification both need an out-of-band
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
    """Default correlation-key accessor: the audit session and the `id` of a bare a-MCP event.

    An outcome correlates to an attempt of its own audit session only (§7.2), so the key is the pair. A
    record sealed before v0.3 names its call by `call_id` instead, which scopes it the same way.
    """
    event_id = event.get(fields.ID)
    if event_id is None:
        return None
        # end if
    scope = event.get(fields.SESSION_ID, event.get(_EARLIER_CALL_ID))
    return (scope, event_id)
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

# The refusals that account for an unsealed attempt's `signer_seq` (§7.2, §11.4): the tool declined to
# act because the host did not accept, so the attempt it numbered is not in the chain.
_REFUSAL_REASONS = frozenset({reasons.HOST_REJECTED, reasons.HOST_UNAVAILABLE})


@dataclass(frozen=True)
class UnaccountedSignerSeq:
    """A maximal run of `signer_seq` values missing from one key's sequence in one audit session.

    No sealed refusal accounts for any value in it (§11.4); `first` and `last` are inclusive.
    """

    key_id: str
    session_id: str
    first: int
    last: int
    # end class


def _count(value: object) -> int | None:
    """A `signer_seq` as the integer it is - an int or an integral float in the §8.1 domain - or None."""
    if isinstance(value, bool):
        return None
        # end if
    if isinstance(value, int):
        return value if 0 <= value <= MAX_SAFE_INTEGER else None
        # end if
    if isinstance(value, float) and value.is_integer() and 0 <= value <= MAX_SAFE_INTEGER:
        return int(value)
        # end if
    return None
    # end def


def _numbered(event: Mapping[str, object]) -> tuple[str, str, int] | None:
    """The (`key_id`, `session_id`, `signer_seq`) an event is numbered under (§7.4), or None."""
    key_id, session_id = event.get(fields.KEY_ID), event.get(fields.SESSION_ID)
    signer_seq = _count(event.get(fields.SIGNER_SEQ))
    if isinstance(key_id, str) and isinstance(session_id, str) and signer_seq is not None:
        return key_id, session_id, signer_seq
        # end if
    return None
    # end def


def _missing_runs(present: set[int]) -> list[list[int]]:
    """The values from 0 to the largest in `present` that are not in it, as `[first, last]` runs.

    Computed from the gaps between present values, so a value near 2^53 costs one run (§11.4).

    Args:
        present: The sealed `signer_seq` values of one key and session.

    Returns:
        The maximal runs of missing values, ascending.
    """
    runs: list[list[int]] = []
    following = 0
    for value in sorted(present):
        if value > following:
            runs.append([following, value - 1])
            # end if
        following = value + 1
        # end for
    return runs
    # end def


def unaccounted_signer_seq(events: Iterable[Mapping[str, object]]) -> list[UnaccountedSignerSeq]:
    """Run §11.4's accounting over the sealed a-MCP events of one partition.

    A verifier does not see the events a host rejected, so a rejected attempt leaves its `signer_seq`
    missing from the sealed sequence; the sealed refusal of that attempt accounts for it. The procedure
    is pinned so that two verifiers report the same values for one ledger:

    1. Per key and session, the missing values are those from 0 to the largest sealed value that are
       not sealed.
    2. The refusals are the sealed `aborted` outcomes with `host-rejected` or `host-unavailable` to
       which no sealed attempt correlates - none with the same `session_id` and `id` sealed before
       it - in ascending `signer_seq`.
    3. Each refusal accounts for the smallest missing value below its own not yet accounted for.
    4. What is left is unaccounted, one entry per maximal run.

    Events that carry no `session_id` were sealed before v0.3, when the sequence was per key; they are
    not numbered this way and are left out.

    Args:
        events: The embedded a-MCP events of the partition's sealed records, in chain order.

    Returns:
        One entry per maximal run of unaccounted values, per key and session in order of first
        appearance, ascending.
    """
    sealed_attempts: set[tuple[object, object]] = set()
    groups: dict[tuple[str, str], list[tuple[int, Mapping[str, object], bool]]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
            # end if
        # An outcome correlates only with an attempt sealed before it (§7.2).
        correlation_key = (event.get(fields.SESSION_ID), event.get(fields.ID))
        correlated = correlation_key in sealed_attempts
        if event.get(fields.OUTCOME) == Outcome.ATTEMPTED:
            sealed_attempts.add(correlation_key)
            # end if
        numbered = _numbered(event)
        if numbered is not None:
            key_id, session_id, signer_seq = numbered
            groups.setdefault((key_id, session_id), []).append((signer_seq, event, correlated))
            # end if
        # end for
    unaccounted: list[UnaccountedSignerSeq] = []
    for (key_id, session_id), group in groups.items():
        missing = _missing_runs({signer_seq for signer_seq, _event, _correlated in group})
        refusals = sorted(
            signer_seq
            for signer_seq, event, correlated in group
            if event.get(fields.OUTCOME) == Outcome.ABORTED
            and event.get(fields.REASON) in _REFUSAL_REASONS
            and not correlated
        )
        # The smallest value still missing below a refusal is always the first of the first run.
        for refusal in refusals:
            if not missing or missing[0][0] >= refusal:
                continue
                # end if
            missing[0][0] += 1
            if missing[0][0] > missing[0][1]:
                missing.pop(0)
                # end if
            # end for
        unaccounted.extend(
            UnaccountedSignerSeq(key_id=key_id, session_id=session_id, first=first, last=last)
            for first, last in missing
        )
        # end for
    return unaccounted
    # end def


def verify_chain(
    records: list[SealedRecord],
    anchored_digest: str | None = None,
    *,
    adapter: RecordAdapter = DEFAULT_ADAPTER,
    expected_principal: object | None = None,
    countersignature_checker: CountersignatureChecker | None = None,
    signature_checker: SignatureChecker | None = None,
    expected_identity: ExpectedIdentity | None = None,
    countersignature_required: bool = False,
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
            as a value (§11.4); a mismatch, or an absent identity, is flagged as `principal-mismatch`.
            This is an SDK check, not an a-MCP anomaly: it detects a cross-partition transplant only
            when records are sealed inside an identity-binding envelope. None (default) skips it.
        countersignature_checker: Resolves a `host_key_id` and verifies a countersignature over the
            canonical host-assigned fields and `log_id` (§7.1). A record carrying none of the triple is
            uncountersigned, which is a state and not an anomaly (§5.2); one whose signature fails, or
            that carries part of the triple, is `host-signature-invalid`. Without a checker, records
            that do carry one are counted in `unchecked` (§11.4).
        signature_checker: Verifies a sealed Level-2 event's own `signature` against the key registry
            (§7.4). Optional for a pure ledger auditor (§10.6); without it, records carrying a
            `signature` are counted in `unchecked` rather than reported as verified (§11.4).
        expected_identity: The identity this partition is expected to hold, supplied out-of-band, for a
            deployment that binds identity by the countersignature (§10.10). A record whose `log_id`
            differs, whose `host_key_id` is outside the set, or which does not carry the whole triple
            is `principal-mismatch`, whether or not it can otherwise be validated. None skips the check.
        countersignature_required: The chain must be countersigned, supplied out-of-band (§11.4). An
            uncountersigned record is then `host-signature-invalid`: a storage-level attacker can strip
            a countersignature it cannot forge.

    Returns:
        A report; `ok` is True only when no issues were found. A record that cannot be canonicalized is
        reported `schema-invalid` and the chain is checked on either side of it; nothing raises.
    """
    # §11.4 compares the expectation and the bound identity as values. A structured expectation would
    # be compared by value here and by identity in the TypeScript port, so two conforming verifiers
    # would return opposite verdicts on one ledger; §10.10 binds a single primitive, so it is refused.
    if expected_principal is not None and not isinstance(expected_principal, str | int | float | bool):
        raise ValueError(
            'the expected principal is compared as a value; reduce a structured identity to a primitive (§10.10, §11.4)'
        )
        # end if
    issues: list[VerifyIssue] = []
    attempted_ids: set[object] = set()
    numbered: set[tuple[str, str, int]] = set()
    prev_recomputed = GENESIS_HASH
    countersignature_unchecked = False
    l2_unchecked = False

    for index, record in enumerate(records):
        event = record.event

        if record.seq != index:
            # Out-of-order rolls up to seq-gap (Tier-1); the direction is a Tier-2 detail.
            issues.append(VerifyIssue(seq=record.seq, kind=SEQ_GAP, detail=f'expected seq {index}, got {record.seq}'))
            # end if

        # Recompute from the record body against the recomputed prior link, not the stored one, so a
        # mutation cannot hide behind its own stored hashes. A broken previous_hash link surfaces as a
        # record-hash-mismatch (Tier-1); the "link" detail distinguishes it locally.
        hashable = True
        try:
            recomputed = compute_record_hash(event, record.seq, record.host_ts, prev_recomputed)
        except CanonicalizationError as error:
            # §11.4: a record that cannot be canonicalized is a finding, not a failure to verify. Its
            # stored hash is the only link the next record can be checked against, and the checks that
            # do not need its hash - the identity binding among them - still run on it.
            issues.append(VerifyIssue(seq=record.seq, kind=SCHEMA_INVALID, detail=f'not canonicalizable: {error}'))
            hashable = False
            recomputed = record.record_hash if isinstance(record.record_hash, str) else prev_recomputed
            # end try
        if hashable and record.previous_hash != prev_recomputed:
            issues.append(
                VerifyIssue(
                    seq=record.seq, kind=RECORD_HASH_MISMATCH, detail='previous_hash does not link to prior record'
                )
            )
            # end if
        if hashable and record.record_hash != recomputed:
            issues.append(
                VerifyIssue(seq=record.seq, kind=RECORD_HASH_MISMATCH, detail='stored record_hash != recomputed')
            )
            # end if

        # A record that names no call is not one half of a pair. An envelope may seal records that are not
        # tool calls at all - a prompt, a model's reasoning, a turn boundary - and their adapter returns
        # None here to say so. Correlating them would report every one of them as an outcome missing its
        # attempt, which is the check crying wolf on a chain that is intact.
        # An aborted outcome with no attempt before it is a sealed refusal, not an orphan (§7.2).
        inner = adapter.event_of(event)
        refusal = isinstance(inner, Mapping) and inner.get(fields.OUTCOME) == Outcome.ABORTED
        event_id = adapter.id_of(event)
        if event_id is not None:
            if adapter.is_attempt(event):
                attempted_ids.add(event_id)
            elif event_id not in attempted_ids and not refusal:
                issues.append(
                    VerifyIssue(
                        seq=record.seq,
                        kind=ORPHANED_OUTCOME,
                        detail=f'terminal outcome with no matching attempt, id={event_id}',
                    )
                )
                # end if
            # end if

        # §11.4: two sealed records numbered alike within one key and session - a replay the chain holds.
        inner_numbered = _numbered(inner) if isinstance(inner, Mapping) else None
        if inner_numbered is not None:
            if inner_numbered in numbered:
                key_id, session_id, signer_seq = inner_numbered
                issues.append(
                    VerifyIssue(
                        seq=record.seq,
                        kind=REPLAY_DETECTED,
                        detail=f'signer_seq {signer_seq} of key {key_id!r} in session {session_id} is sealed twice',
                    )
                )
                # end if
            numbered.add(inner_numbered)
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
        signed = hashable and isinstance(inner, Mapping) and inner.get(fields.SIGNATURE) is not None
        if signed and signature_checker is None:
            l2_unchecked = True
        elif isinstance(inner, Mapping) and signed and signature_checker is not None:
            if outside_canonical_domain(inner) or not signature_checker(inner):
                issues.append(
                    VerifyIssue(seq=record.seq, kind=SIGNATURE_INVALID, detail='event signature does not verify')
                )
                # end if
            # end if

        # Countersignature determination (§11.4): by the signature alone, never inferred from another field.
        triple = (record.host_signature, record.host_key_id, record.log_id)
        present = sum(value is not None for value in triple)
        if present == 0 and countersignature_required:
            issues.append(
                VerifyIssue(
                    seq=record.seq,
                    kind=HOST_SIGNATURE_INVALID,
                    detail='uncountersigned, where the chain must be countersigned',
                )
            )
        elif present not in (0, _TRIPLE_SIZE):
            # §7.1 keeps the three together, and the response schema enforces it on the wire - but a
            # stored record is not schema-checked, so a partial triple reaches a verifier and
            # establishes nothing. Silently ignoring it would be neither a check nor a report.
            issues.append(
                VerifyIssue(
                    seq=record.seq,
                    kind=HOST_SIGNATURE_INVALID,
                    detail='host_signature, host_key_id, and log_id must appear together or not at all',
                )
            )
        elif (
            hashable
            and record.host_signature is not None
            and record.host_key_id is not None
            and record.log_id is not None
        ):
            if countersignature_checker is None:
                countersignature_unchecked = True
            else:
                try:
                    payload: bytes | None = countersignature_payload(
                        record.seq, record.host_ts, record.log_id, record.previous_hash, record.record_hash
                    )
                except CanonicalizationError:
                    payload = None
                    # end try
                if payload is None or not countersignature_checker(record.host_key_id, record.host_signature, payload):
                    issues.append(
                        VerifyIssue(
                            seq=record.seq,
                            kind=HOST_SIGNATURE_INVALID,
                            detail=f'countersignature does not verify for host_key_id {record.host_key_id!r}',
                        )
                    )
                    # end if
                # end if
            # end if

        # §10.10: identity bound by the countersignature's `log_id` and key, against an out-of-band
        # expectation. A record without the whole triple carries no binding, and fails closed.
        if expected_identity is not None:
            mismatch = _identity_mismatch(record, present, expected_identity)
            if mismatch is not None:
                issues.append(VerifyIssue(seq=record.seq, kind=PRINCIPAL_MISMATCH, detail=mismatch))
                # end if
            # end if

        prev_recomputed = recomputed
        # end for

    # §11.4: a `signer_seq` missing within one key's sequence in one session, and not accounted for by
    # a sealed refusal, may mark a suppressed event. It is computable from the records alone - no
    # registry - so a verifier that omits it is silently dropping the one suppression signal the ledger
    # carries.
    for gap in unaccounted_signer_seq(adapter.event_of(record.event) for record in records):  # type: ignore[misc]
        issues.append(
            VerifyIssue(
                seq=None,
                kind=SIGNER_SEQ_GAP,
                detail=(
                    f'signer_seq {gap.first}..{gap.last} of key {gap.key_id!r} in session {gap.session_id} is missing'
                ),
            )
        )
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
        name
        for name, applicable in (('countersignature', countersignature_unchecked), ('level-2-signature', l2_unchecked))
        if applicable
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
    countersignature_checker: CountersignatureChecker | None = None,
    signature_checker: SignatureChecker | None = None,
    expected_identity: ExpectedIdentity | None = None,
    countersignature_required: bool = False,
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
        countersignature_checker: Forwarded to `verify_chain`.
        signature_checker: Forwarded to `verify_chain`.
        expected_identity: Forwarded to `verify_chain`.
        countersignature_required: Forwarded to `verify_chain`.

    Returns:
        A report; `ok` is True only when no issues were found.
    """
    report = verify_chain(
        records,
        anchored_digest,
        adapter=adapter,
        expected_principal=expected_principal,
        countersignature_checker=countersignature_checker,
        signature_checker=signature_checker,
        expected_identity=expected_identity,
        countersignature_required=countersignature_required,
    )
    already = [issue.seq for issue in report.issues if issue.kind == SCHEMA_INVALID]
    schema_issues = [
        VerifyIssue(seq=record.seq, kind=SCHEMA_INVALID, detail=error)
        for record in records
        if record.seq not in already and (error := _sealed_error(adapter.event_of(record.event))) is not None
    ]
    schema_issues.extend(_version_regressions(records, adapter))
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


def _version_regressions(records: list[SealedRecord], adapter: RecordAdapter) -> list[VerifyIssue]:
    """Report each record of an earlier `spec_version` sealed after one of a later version (§11.4).

    No conforming host seals it (§4 pins `spec_version`), so only a rewrite places it there.

    Args:
        records: The sealed records in append order.
        adapter: Extracts the embedded a-MCP event of each record.

    Returns:
        One `schema-invalid` issue per record whose version goes backwards.
    """
    issues: list[VerifyIssue] = []
    latest = -1
    latest_version = ''
    for record in records:
        inner = adapter.event_of(record.event)
        version = inner.get(fields.SPEC_VERSION) if isinstance(inner, Mapping) else None
        rank = _VERSION_RANK.get(version) if isinstance(version, str) else None
        if rank is None:
            continue
            # end if
        if rank < latest:
            issues.append(
                VerifyIssue(
                    seq=record.seq,
                    kind=SCHEMA_INVALID,
                    detail=f'{version} sealed after a record of {latest_version} (versions do not go backwards)',
                )
            )
        else:
            latest, latest_version = rank, str(version)
            # end if
        # end for
    return issues
    # end def


def _identity_mismatch(record: SealedRecord, present: int, expected: ExpectedIdentity) -> str | None:
    """Why a record's bound identity does not match the expectation, or None when it does (§10.10).

    Args:
        record: The sealed record.
        present: How many members of the countersignature triple it carries.
        expected: The out-of-band expectation.

    Returns:
        A diagnostic detail, or None.
    """
    wanted = f'{expected.log_id!r} under {sorted(expected.host_key_ids)}'
    if present != _TRIPLE_SIZE:
        return f'no countersignature binds the record; expected {wanted}'
        # end if
    if record.log_id != expected.log_id:
        return f'record log_id {record.log_id!r} does not bind the expected {wanted}'
        # end if
    if record.host_key_id not in expected.host_key_ids:
        return f'record host_key_id {record.host_key_id!r} does not bind the expected {wanted}'
        # end if
    return None
    # end def


def _sealed_error(event: object) -> str | None:
    """The first reason a sealed event is not a valid event of its own version, or None (§11.4)."""
    error = first_sealed_validation_error(event)
    if error is None and outside_canonical_domain(event):
        return 'a value is outside the canonicalization domain (§8.1)'
        # end if
    return error
    # end def
