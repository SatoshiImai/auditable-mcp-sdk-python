"""The host-side audit subsystem — a deterministic recording engine (§7).

`AuditHost` implements `AuditEndpoint` for exactly one partition (§10.5): it owns one `Ledger`, one
`seq` counter, and one anomaly set, and there is no code path that crosses partitions. Multi-tenant
deployments instantiate one host per partition and route by connection; that routing is the
integrator's concern, above this SDK.

The host issues an audit session for each call it audits and closes it when the call ends (§6.3);
`signer_seq` is tracked within a session (§7.4). It validates ledger-integrity requirements before
sealing (§7.1) and never authorizes the tool's domain action (§2). Under Level 2 it defers signature
checking to an injected `SignatureVerifier` (the concrete registry-backed verifier lives in the `l2`
layer), while sequence tracking and anomaly flagging are host logic. A persistence failure answers
`unavailable`, which decides nothing (§7.1).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Final, Protocol
from uuid import uuid4

import anyio

from auditable_mcp import fields, reasons
from auditable_mcp.canonical import MAX_SAFE_INTEGER, canonicalize, outside_canonical_domain
from auditable_mcp.clock import Clock, SystemClock
from auditable_mcp.hashing import countersignature_payload
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import (
    SPEC_VERSION,
    AttemptResponse,
    AuditCapability,
    AuditCapabilityInput,
    Countersign,
    Level,
    Outcome,
    RejectReason,
    first_validation_error,
)
from auditable_mcp.storage.repository import LedgerRepository, RepositoryError
from auditable_mcp.transport import accept, reject, unavailable

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IntegrityAnomaly:
    """A detected integrity violation or inconsistency in the audit stream (flagged, not always fatal)."""

    id: str
    kind: str
    detail: str
    # end class


class SignatureVerifier(Protocol):
    """Verifies a Level-2 detached signature over canonical(event − signature) (§8.2).

    The concrete verifiers (with their key registries) live in the `l2` layer, keeping the host free
    of any cryptography dependency. `verify` is async because a production verifier may call a network
    KMS; a local verifier just returns synchronously under the async signature.
    """

    async def verify(self, event: dict[str, object]) -> RejectReason | None:
        """Return a Tier-1 reject reason (`unknown-key` / `signature-invalid`), or None if it verifies (§7.6)."""
        ...

    # end class


# The host's own capability defaults, used only to complete a partial self-declaration. These are the
# SDK declaring the version/level/attempt it ships — not a parser fallback. An incoming peer capability
# is validated by the strict AuditCapability model (all fields REQUIRED, §6.1), which rejects a missing
# field rather than defaulting it, so version negotiation cannot be bypassed by omission.
_HOST_CAPABILITY_DEFAULTS: Final[dict[str, object]] = {
    'spec_version': SPEC_VERSION,
    'level': Level.L1,
    'attempt': 'request',
    'countersign': Countersign.NONE,
}


class Countersigner(Protocol):
    """Countersigns a record this host sealed (§5.2, §7.1).

    `sign` is async for the same reason `EventSigner.sign` is: a production host signs through a
    network HSM or KMS. The payload is already canonical (`countersignature_payload`), so a signer does
    cryptography only - the preimage is built in one place, by the host.
    """

    @property
    def key_id(self) -> str:
        """The `host_key_id` a verifier's registry binds to this host."""
        ...

    async def sign(self, payload: bytes) -> str:
        """Return the base64url detached signature, without padding, over `payload`."""
        ...

    # end class


@dataclass
class _Session:
    """One audit session: one tools/call (§6.3).

    Per key, `decided` is the set of `signer_seq` values the host reached a decision on (the replay
    window, which is the whole session) and `received` the highest it received with a verifying
    signature (the gap bound) (§7.4). `outcomes` holds, per operation `id`, the digest of the outcome
    sealed for it, since an operation has one terminal record (§7.2).
    """

    decided: dict[str, set[int]] = field(default_factory=dict)
    received: dict[str, int] = field(default_factory=dict)
    accepted: set[str] = field(default_factory=set)
    resolved: set[str] = field(default_factory=set)
    outcomes: dict[str, str] = field(default_factory=dict)
    # end class


# §7.6 has one anomaly kind for every signature failure of an event the host dropped: a missing
# signature and an unknown key are reject reasons, not anomaly kinds.
_ANOMALY_KIND_OF: Final[dict[str, str]] = {
    reasons.L2_UNSIGNED: reasons.SIGNATURE_INVALID,
    reasons.UNKNOWN_KEY: reasons.SIGNATURE_INVALID,
}


def _resolve_capability(capability: AuditCapability | AuditCapabilityInput | None) -> AuditCapability:
    """Build the host's own required capability, filling unset fields from the SDK's defaults (§6.1)."""
    if isinstance(capability, AuditCapability):
        return capability
        # end if
    overrides = capability if capability is not None else {}
    return AuditCapability.model_validate({**_HOST_CAPABILITY_DEFAULTS, **overrides})
    # end def


class AuditHost:
    """Receives self-attested events and seals valid ones into one partition's tamper-evident ledger."""

    def __init__(
        self,
        partition: str,
        capability: AuditCapability | AuditCapabilityInput | None = None,
        *,
        verifier: SignatureVerifier | None = None,
        countersigner: Countersigner | None = None,
        log_id: str | None = None,
        repository: LedgerRepository | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Initialize the host for `partition` under a capability, with optional verifier and store.

        With a `repository`, every accepted record is durably persisted before it is committed and
        acknowledged; a persistence failure fails closed (§7.1). Use `AuditHost.resume` to restart a
        host from a persisted chain.

        `log_id` is the name every countersignature gives this partition's chain (§7.1). It must be
        stable for the chain's lifetime and distinct from every other chain the host keeps; it
        defaults to `partition`.

        Raises:
            ValueError: If the required level is Level 2 but no `verifier` was provided, or the host
                declares `countersign: "host"` but no `countersigner` was provided.
        """
        self._capability = _resolve_capability(capability)
        if self._capability.level == Level.L2 and verifier is None:
            raise ValueError('an L2 host requires a SignatureVerifier')
            # end if
        # A host that declares it countersigns and then does not would leave every record
        # uncountersigned while its peers expect otherwise; the declaration is refused at construction.
        if self._capability.countersign == Countersign.HOST and countersigner is None:
            raise ValueError('a host declaring countersign "host" requires a Countersigner')
            # end if
        # §7.1: a host that declares `none` MUST NOT return the countersignature. Holding a signer while
        # declaring `none` is the only way to violate that, so it is refused here rather than silently
        # ignored at seal time.
        if self._capability.countersign == Countersign.NONE and countersigner is not None:
            raise ValueError('a host declaring countersign "none" must not hold a Countersigner')
            # end if
        self._partition = partition
        self._log_id = log_id if log_id is not None else partition
        self._ledger = Ledger(partition)
        self._verifier = verifier
        self._countersigner = countersigner
        self._repository = repository
        self._clock = clock if clock is not None else SystemClock()
        # One lock per host is one lock per partition (§10.5); §7.1 constrains nothing across them.
        self._lock = anyio.Lock()
        # Set False by the integrator when persistence is known to be down; also fail closed.
        self.persistence_available = True
        self._sessions: dict[str, _Session] = {}
        # Every session id this host ever issued, open or closed: §6.3 never issues one twice.
        self._issued: set[str] = set()
        # Set when an append failed in a way that may still have landed; the next event re-reads the
        # stored tail before it seals anything (see `_settle_tail`).
        self._tail_uncertain = False
        # The partition's sealed attempts by id, so a byte-identical repeat is answered from the
        # ledger (§7.1), and a digest of every sealed event, so none is sealed twice (§8.3).
        self._sealed_attempts: dict[str, SealedRecord] = {}
        self._sealed_digests: set[str] = set()
        self._rejected_ids: set[str] = set()
        self._anomalies: list[IntegrityAnomaly] = []
        # end def

    @classmethod
    async def resume(
        cls,
        partition: str,
        capability: AuditCapability | AuditCapabilityInput | None = None,
        *,
        repository: LedgerRepository,
        verifier: SignatureVerifier | None = None,
        countersigner: Countersigner | None = None,
        log_id: str | None = None,
        clock: Clock | None = None,
    ) -> AuditHost:
        """Build a host that continues `partition`'s persisted chain.

        The chain state (next `seq`, tail link) and what makes a repeat recognizable - the sealed
        attempts, and a digest of every sealed event - are reconstructed from the stored records, so
        post-restart appends link correctly and a repeat is still answered from the ledger. Audit
        sessions are not: a call in flight across the restart has ended as far as this host knows,
        and its events are refused (§6.3). Reject memory is not persisted either, so an outcome for a
        pre-restart rejected id is flagged `orphaned-outcome`, as a never-accepted one.

        A restart ends every call that was in flight, so each sealed attempt with no sealed terminal
        outcome of the same session and id after it is recorded `unresolved-attempt`, as closing its
        session would have (§6.3), and its session is not open. Anomalies are held in memory only; an
        integrator who needs them across restarts persists `anomalies()`.
        """
        host = cls(
            partition,
            capability,
            verifier=verifier,
            countersigner=countersigner,
            log_id=log_id,
            repository=repository,
            clock=clock,
        )
        records = await repository.read_all(partition)
        host._ledger.resume_from(records[-1] if records else None)
        for record in records:
            host._remember(record)
            session_id = record.event.get(fields.SESSION_ID)
            if isinstance(session_id, str):
                # Every session in the ledger was issued before, so none is issued again (§6.3).
                host._issued.add(session_id)
                # end if
            # end for
        host._flag_unresolved(records)
        return host
        # end def

    def _flag_unresolved(self, records: list[SealedRecord]) -> None:
        """Record every persisted attempt left without a terminal outcome as unresolved (§6.3)."""
        open_attempts: dict[tuple[str, str], str] = {}
        for record in records:
            event = record.event
            session_id = event.get(fields.SESSION_ID)
            if not isinstance(session_id, str) or event.get(fields.SPEC_VERSION) != SPEC_VERSION:
                continue
                # end if
            event_id = _event_id(event)
            if event.get(fields.OUTCOME) == Outcome.ATTEMPTED:
                open_attempts[(session_id, event_id)] = event_id
            else:
                open_attempts.pop((session_id, event_id), None)
                # end if
            # end for
        for event_id in open_attempts.values():
            self._flag(event_id, reasons.UNRESOLVED_ATTEMPT, f'host restarted with attempt {event_id} unresolved')
            # end for
        # end def

    def _remember(self, record: SealedRecord) -> None:
        """Note a sealed record so that a repeat of it is recognized (§7.1, §8.3)."""
        self._sealed_digests.add(_digest(record.event))
        if record.event.get(fields.OUTCOME) == Outcome.ATTEMPTED:
            self._sealed_attempts[_event_id(record.event)] = record
            # end if
        # end def

    async def _settle_tail(self) -> bool:
        """Re-read the stored tail after an append whose failure was ambiguous; False if it cannot be read.

        A `RepositoryError` from `append` does not say whether the record landed: a store can commit and
        then lose the acknowledgement. Sealing the next record on the in-memory tail would then give two
        records one `seq`. So the next event first reads the tail back and adopts a record that did land
        (§7.1 atomic sealing). A record adopted this way is one the tool was told `unavailable` for; the
        byte-identical attempt it may send again is answered from the ledger (§7.1).
        """
        if not self._tail_uncertain or self._repository is None:
            return True
            # end if
        try:
            tail = await self._repository.load_tail(self._partition)
        except RepositoryError:
            _logger.exception('could not re-read the tail of partition %s; failing closed', self._partition)
            return False
            # end try
        expected_seq = len(self._ledger)
        if tail is not None and tail.seq == expected_seq and tail.previous_hash == self._ledger.digest():
            self._ledger.commit(tail)
            self._remember(tail)
            self._adopt(tail)
        elif tail is not None and tail.seq > expected_seq:
            # Someone else extended the chain; §7.1 atomic sealing was already lost elsewhere, and the
            # best this host can do is continue from what is stored rather than fork it.
            _logger.error('partition %s was extended by another writer; continuing from its tail', self._partition)
            self._ledger.resume_from(tail)
            # end if
        self._tail_uncertain = False
        return True
        # end def

    def _adopt(self, record: SealedRecord) -> None:
        """Account an adopted record to its open session, as sealing it here would have (§6.3, §7.4)."""
        event = record.event
        session_id = event.get(fields.SESSION_ID)
        session = self._sessions.get(session_id) if isinstance(session_id, str) else None
        if session is None:
            return
            # end if
        event_id = _event_id(event)
        self._decide(event, session)
        if event.get(fields.OUTCOME) == Outcome.ATTEMPTED:
            session.accepted.add(event_id)
        else:
            session.outcomes[event_id] = _digest(event)
            if event_id in session.accepted:
                session.resolved.add(event_id)
                # end if
            # end if
        # end def

    async def _seal(self, event: dict[str, object], host_ts: str) -> SealedRecord | None:
        """Seal `event`, persist it if a repository is configured, then commit; None on persistence failure."""
        sealed = self._ledger.seal(event, host_ts)
        if self._countersigner is not None:
            payload = countersignature_payload(
                sealed.seq, sealed.host_ts, self._log_id, sealed.previous_hash, sealed.record_hash
            )
            try:
                signature = await self._countersigner.sign(payload)
            except Exception:
                # A host that declared it countersigns cannot record conformantly without the
                # countersignature, so a signer failure is a host-internal failure and fails closed as
                # `unavailable` (§7.1, §7.6 `internal-error`) - never an exception through the audit
                # path. The catch is broad on purpose: the signer is injected third-party code (an HSM
                # or KMS client) whose error types this SDK does not know, and letting any of them
                # escape would leave the tool with no fail-closed signal at all.
                _logger.exception('countersigning failed for partition %s; failing closed', self._partition)
                return None
            except BaseException:
                # A cancellation mid-seal is treated as an ambiguous write, as one during the append
                # is: the next event re-reads the stored tail before it seals anything.
                self._tail_uncertain = True
                raise
                # end try
            sealed = replace(
                sealed, host_signature=signature, host_key_id=self._countersigner.key_id, log_id=self._log_id
            )
            # end if
        if self._repository is not None:
            try:
                await self._repository.append(self._partition, sealed)
            except RepositoryError:
                self._tail_uncertain = True
                return None
            except BaseException:
                # A cancellation (or any other interruption) during the append leaves the write as
                # ambiguous as a failed acknowledgement: the store may hold the record already (§7.1).
                self._tail_uncertain = True
                raise
                # end try
            # end if
        self._ledger.commit(sealed)
        self._remember(sealed)
        return sealed
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The audit capability this host requires (§6.1)."""
        return self._capability
        # end def

    @property
    def log_id(self) -> str:
        """The name this host's countersignatures give the partition's chain (§7.1)."""
        return self._log_id
        # end def

    def anomalies(self) -> list[IntegrityAnomaly]:
        """Return the detected integrity anomalies."""
        return list(self._anomalies)
        # end def

    def records(self) -> list[SealedRecord]:
        """Return the sealed ledger records for this partition."""
        return self._ledger.records()
        # end def

    def digest(self) -> str:
        """Return this partition's anchorable tail digest (§8.3)."""
        return self._ledger.digest()
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Issue a fresh audit session for a call this host audits (§6.3).

        Args:
            session_id: The id to issue. A host mints its own when None; a tool acting as its own host
                in the degraded posture (§6.2) passes the one it minted for the call.

        Returns:
            The session id, to send with the call.

        Raises:
            ValueError: The id was already issued, even for a session that has since ended. §6.3
                requires one that was never issued before, and reusing one would let one call's events
                stand for another's.
        """
        issued = session_id if session_id is not None else str(uuid4())
        if issued in self._issued:
            raise ValueError(f'audit session {issued} was already issued (§6.3)')
            # end if
        self._issued.add(issued)
        self._sessions[issued] = _Session()
        return issued
        # end def

    async def close_session(self, session_id: str) -> None:
        """Close an audit session because its call ended (§6.3).

        Every outcome of the session has been delivered by then (§6), so an attempt this host accepted
        that has no sealed terminal outcome was never resolved; it is recorded `unresolved-attempt`.
        The session accepts nothing further.
        """
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return
                # end if
            for event_id in sorted(session.accepted - session.resolved):
                self._flag(event_id, reasons.UNRESOLVED_ATTEMPT, f'call ended with attempt {event_id} unresolved')
                # end for
            # end async with
        # end def

    @asynccontextmanager
    async def session(self, session_id: str | None = None) -> AsyncIterator[str]:
        """Hold an audit session open for the span of one call (§6.3)."""
        issued = self.open_session(session_id)
        try:
            yield issued
        finally:
            await self.close_session(issued)
            # end try
        # end def

    def _flag(self, event_id: str, kind: str, detail: str) -> None:
        """Record an integrity anomaly under its Tier-1 anomaly kind (§7.6)."""
        self._anomalies.append(IntegrityAnomaly(id=event_id, kind=_ANOMALY_KIND_OF.get(kind, kind), detail=detail))
        # end def

    def _session_of(self, event: dict[str, object], expected: str | None) -> _Session | None:
        """The open audit session the event names, if it is the one it arrived on (§6.3)."""
        session_id = event.get(fields.SESSION_ID)
        session = self._sessions.get(session_id) if isinstance(session_id, str) else None
        if session is None or (expected is not None and session_id != expected):
            self._flag(
                _event_id(event),
                reasons.REPLAY_DETECTED,
                f'session {session_id!r} is not the one this call carries (§6.3)',
            )
            return None
            # end if
        return session
        # end def

    async def _verify_signature(self, event: dict[str, object], session: _Session) -> RejectReason | None:
        """Verify an L2 signature (§7.1 step 3); return a reject reason, or None (no-op under L1).

        Once the signature verifies, the event counts as received: a value more than one past the
        highest received - or a first value other than 0 - is flagged, and not rejected (§7.4).
        """
        if self._capability.level != Level.L2:
            return None
            # end if
        key_id = event.get(fields.KEY_ID)
        signature = event.get(fields.SIGNATURE)
        signer_seq = _signer_seq(event)
        if not signature or not isinstance(key_id, str) or signer_seq is None:
            self._flag(_event_id(event), reasons.L2_UNSIGNED, 'L2 requires signature, key_id, and signer_seq')
            return reasons.L2_UNSIGNED
            # end if
        if self._verifier is None:
            raise RuntimeError('a Level-2 host holds no SignatureVerifier')
            # end if
        reason = await self._verifier.verify(event)
        if reason is not None:
            self._flag(_event_id(event), reason, 'signature verification failed')
            return reason
            # end if
        received = session.received.get(key_id)
        expected = 0 if received is None else received + 1
        if signer_seq > expected:
            self._flag(_event_id(event), reasons.SIGNER_SEQ_GAP, f'expected signer_seq {expected}, got {signer_seq}')
            # end if
        if received is None or signer_seq > received:
            session.received[key_id] = signer_seq
            # end if
        return None
        # end def

    def _check_replay(self, event: dict[str, object], session: _Session) -> RejectReason | None:
        """Reject a `signer_seq` the host already decided for its key in this session (§7.1 step 5, §7.4).

        A value not yet decided is not a replay, even below one that was: it is an attempt sent again
        after `unavailable` while other operations of the session went ahead (§7.1).
        """
        key_id = event.get(fields.KEY_ID)
        signer_seq = _signer_seq(event)
        if self._capability.level != Level.L2 or not isinstance(key_id, str) or signer_seq is None:
            return None
            # end if
        if signer_seq in session.decided.get(key_id, set()):
            self._flag(_event_id(event), reasons.REPLAY_DETECTED, f'signer_seq {signer_seq} was already decided')
            return reasons.REPLAY_DETECTED
            # end if
        return None
        # end def

    def _decide(self, event: dict[str, object], session: _Session) -> None:
        """Record a decision on the event's `signer_seq`: sealed, or refused after it verified (§7.4)."""
        key_id = event.get(fields.KEY_ID)
        signer_seq = _signer_seq(event)
        if self._capability.level != Level.L2 or not isinstance(key_id, str) or signer_seq is None:
            return
            # end if
        session.decided.setdefault(key_id, set()).add(signer_seq)
        # end def

    def _admit(
        self, event: dict[str, object], expected_session: str | None, *, attempt: bool
    ) -> _Session | RejectReason:
        """Structure, the canonicalization domain, and the session (§7.1 steps 1 and 2)."""
        error = first_validation_error(event)
        if error is not None:
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, error)
            return reasons.SCHEMA_INVALID
            # end if
        # An attempt carries `attempted` and an outcome does not (§6); either way round is structural,
        # which §7.1 checks before the session. Tier-2 detail, Tier-1 `schema-invalid` (§7.6).
        if (event.get(fields.OUTCOME) == Outcome.ATTEMPTED) != attempt:
            detail = (
                'an attempt must carry outcome=attempted' if attempt else 'an outcome carried outcome=attempted (§6)'
            )
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, detail)
            return reasons.SCHEMA_INVALID
            # end if
        # Not canonicalizable (§8.1): reject gracefully (rolls up to schema-invalid) instead of raising.
        if outside_canonical_domain(event):
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, 'a value is not canonicalizable (§8.1)')
            return reasons.SCHEMA_INVALID
            # end if
        session = self._session_of(event, expected_session)
        return session if session is not None else reasons.REPLAY_DETECTED
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject or fail closed (§7.1).

        Held under the partition's lock: §7.1 requires the assignment of `seq` and `previous_hash`, the
        seal, and the commit to be atomic with respect to every other record being sealed into the same
        partition. Signing and persistence sit between those steps, so without the lock two attempts
        read the same chain tail and take the same position - and the host answers `accept` to both.
        The attempt `id`-uniqueness check (§7.1) is inside the same section for the same reason.

        Args:
            event: The attempt, as the tool emitted it.
            session_id: The audit session of the call the attempt arrived on, when the binding knows
                it; the event must carry it (§6.3). A binding that received the attempt on no call
                passes an id no session has, such as the empty string, and the attempt is refused
                `replay-detected` after its structural checks.
            deadline: A time on the event loop's clock after which the binding has already answered
                the tool `unavailable` (§6.4). Taken up after it, the attempt is answered `unavailable`
                and nothing is recorded: the call it belongs to may have ended, and deciding it then
                would seal an operation the tool was told was not recorded, or refuse it against a
                session that closed while it waited. A decision already under way is not undone.
        """
        async with self._lock:
            if deadline is not None and anyio.current_time() >= deadline:
                return unavailable()
                # end if
            if not await self._settle_tail():
                return unavailable()
                # end if
            return await self._handle_attempt(event, session_id)
            # end async with
        # end def

    async def _handle_attempt(self, event: dict[str, object], expected_session: str | None) -> AttemptResponse:
        """The attempt path proper. The caller holds the lock."""
        admitted = self._admit(event, expected_session, attempt=True)
        if isinstance(admitted, str):
            return reject(admitted)
            # end if
        session = admitted
        event_id = _event_id(event)
        reason = await self._verify_signature(event, session)
        if reason is not None:
            self._rejected_ids.add(event_id)
            return reject(reason)
            # end if
        # §7.1 step 4: a sealed id answers a byte-identical repeat from the ledger, and is a replay
        # otherwise. The repeat is what makes an attempt safe to send again.
        sealed = self._sealed_attempts.get(event_id)
        if sealed is not None:
            if canonicalize(sealed.event) == canonicalize(event):
                # Nothing new is decided (§7.4), but the operation is this session's accepted one: it
                # may be a record adopted after an ambiguous append, which the tool was told nothing of.
                if sealed.event.get(fields.SESSION_ID) == event.get(fields.SESSION_ID):
                    session.accepted.add(event_id)
                    # end if
                return _accept_of(sealed)
                # end if
            self._rejected_ids.add(event_id)
            self._decide(event, session)
            self._flag(event_id, reasons.REPLAY_DETECTED, 'attempt id already sealed with a different event')
            return reject(reasons.REPLAY_DETECTED)
            # end if
        # §7.1 step 4: an operation with a sealed outcome has concluded, whether or not its attempt was
        # accepted, and no attempt is sealed after its own terminal record.
        if event_id in session.outcomes:
            self._rejected_ids.add(event_id)
            self._decide(event, session)
            self._flag(event_id, reasons.REPLAY_DETECTED, 'the operation already has a sealed outcome')
            return reject(reasons.REPLAY_DETECTED)
            # end if
        reason = self._check_replay(event, session)
        if reason is not None:
            self._rejected_ids.add(event_id)
            self._decide(event, session)
            return reject(reason)
            # end if
        if not self.persistence_available:
            # Nothing is decided, so the identical attempt may come again (§7.1).
            return unavailable()
            # end if
        record = await self._seal(event, self._clock.now())
        if record is None:
            # Persistence failed after validation: nothing is decided, and the tool must not act.
            return unavailable()
            # end if
        self._decide(event, session)
        session.accepted.add(event_id)
        # Verifiable Accept (§7.1): the host-assigned fields the tool needs for Polluted Stop, and the
        # countersignature where the host countersigns.
        return _accept_of(record)
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Seal an outcome, or drop and record it (§7.2). An outcome has no response (§6).

        Held under the same lock as `handle_attempt`: an outcome seals into the same chain (§8.3).
        """
        async with self._lock:
            if not await self._settle_tail():
                _logger.error(
                    'could not settle the tail; outcome id=%s lost (completeness gap, §10.8)', _event_id(event)
                )
                return
                # end if
            await self._handle_outcome(event, session_id)
            # end async with
        # end def

    async def _handle_outcome(self, event: dict[str, object], expected_session: str | None) -> None:
        """The outcome path proper. The caller holds the lock.

        Validated in the order an attempt is - structure, session, signature, uniqueness, sequence -
        and only then correlated (§7.2). Each drop is recorded under its Tier-1 anomaly kind (§6).
        """
        admitted = self._admit(event, expected_session, attempt=False)
        if isinstance(admitted, str):
            return
            # end if
        session = admitted
        event_id = _event_id(event)
        outcome = event.get(fields.OUTCOME)
        if await self._verify_signature(event, session) is not None:
            return
            # end if
        # §7.2, §8.3: an operation has one terminal record. A byte-identical repeat does nothing; a
        # different outcome for an operation that already has one is a replay.
        digest = _digest(event)
        sealed_outcome = session.outcomes.get(event_id)
        if sealed_outcome == digest or digest in self._sealed_digests:
            return
            # end if
        if sealed_outcome is not None:
            self._decide(event, session)
            self._flag(event_id, reasons.REPLAY_DETECTED, 'a second, different outcome for one operation (§7.2)')
            return
            # end if
        if self._check_replay(event, session) is not None:
            return
            # end if
        correlated = event_id in session.accepted
        # §7.2: a success or failed outcome with no accepted attempt is not sealed. Both never-accepted
        # and post-reject orphans roll up to orphaned-outcome; the distinction is a Tier-2 detail.
        if not correlated and outcome != Outcome.ABORTED:
            sub = 'for a rejected id' if event_id in self._rejected_ids else 'without an accepted attempt'
            self._decide(event, session)
            self._flag(event_id, reasons.ORPHANED_OUTCOME, f'outcome={outcome} {sub}')
            return
            # end if
        # A correlated outcome is its operation's terminal record; an aborted outcome of an attempt the
        # host did not accept is the record of an operation the tool declined to perform (§7.2, §10.4).
        record = await self._seal(event, self._clock.now()) if self.persistence_available else None
        if record is None:
            # An outcome has no response, so a persistence failure cannot be returned. It is a completeness
            # gap (§10.8), not a ledger integrity anomaly, and `internal-error` is not a Tier-1 anomaly
            # kind (§7.6): log it instead of flagging the anomaly set with an out-of-space code.
            _logger.error('could not persist outcome id=%s; outcome lost (completeness gap, §10.8)', event_id)
            return
            # end if
        self._decide(event, session)
        session.outcomes[event_id] = digest
        if correlated:
            session.resolved.add(event_id)
            # end if
        # end def

    # end class


def _accept_of(record: SealedRecord) -> AttemptResponse:
    """The Verifiable Accept for a sealed attempt (§7.1)."""
    return accept(
        record.seq,
        record.record_hash,
        record.host_ts,
        record.previous_hash,
        host_signature=record.host_signature,
        host_key_id=record.host_key_id,
        log_id=record.log_id,
    )
    # end def


def _digest(event: dict[str, object]) -> str:
    """A digest of an event's canonical form: two events with one digest are the same bytes (§8.3)."""
    return hashlib.sha256(canonicalize(event).encode('utf-8')).hexdigest()
    # end def


def _signer_seq(event: dict[str, object]) -> int | None:
    """The event's `signer_seq` as an integer, or None when it has none.

    An integral number written as a float (`1.0`) is the integer JSON Schema admits (§8.1); the event
    has already passed structural validation, which bounds it.
    """
    value = event.get(fields.SIGNER_SEQ)
    if isinstance(value, bool):
        return None
        # end if
    if isinstance(value, int):
        return value
        # end if
    if isinstance(value, float) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
        # end if
    return None
    # end def


def _event_id(event: dict[str, object]) -> str:
    """Best-effort id extraction for anomaly logging."""
    event_id = event.get(fields.ID)
    return event_id if isinstance(event_id, str) else '<unknown>'
    # end def
