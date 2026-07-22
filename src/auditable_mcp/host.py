"""The host-side audit subsystem — a deterministic recording engine (§7).

`AuditHost` implements `AuditEndpoint` for exactly one partition (§10.5): it owns one `Ledger`, one
`seq` counter, one per-`key_id` sequence tracker, and one anomaly set, and there is no code path that
crosses partitions. Multi-tenant deployments instantiate one host per partition and route by
connection; that routing is the integrator's concern, above this SDK.

The host validates ledger-integrity requirements before sealing (§7.1); it never authorizes the
tool's domain action (§2). Under Level 2 it defers signature checking to an injected
`SignatureVerifier` (the concrete Ed25519 verifier lives in the `l2` layer), while sequence tracking
and anomaly flagging are host logic. A persistence failure fails closed with a retryable
`unavailable` (§7.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from auditable_mcp import fields, reasons
from auditable_mcp.canonical import has_unsafe_number
from auditable_mcp.clock import Clock, SystemClock
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import AttemptResponse, AuditCapability, Level, Outcome, first_validation_error
from auditable_mcp.storage.repository import LedgerRepository, RepositoryError
from auditable_mcp.transport import accept, reject, unavailable


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

    async def verify(self, event: dict[str, object]) -> str | None:
        """Return a reject reason (e.g. `unknown-key`, `signature-invalid`), or None if the signature verifies."""
        ...

    # end class


class AuditHost:
    """Receives self-attested events and seals valid ones into one partition's tamper-evident ledger."""

    def __init__(
        self,
        partition: str,
        capability: AuditCapability | None = None,
        *,
        verifier: SignatureVerifier | None = None,
        repository: LedgerRepository | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Initialize the host for `partition` under a capability, with optional verifier and store.

        With a `repository`, every accepted record is durably persisted before it is committed and
        acknowledged; a persistence failure fails closed (§7.1). Use `AuditHost.resume` to restart a
        host from a persisted chain.

        Raises:
            ValueError: If the required level is Level 2 but no `verifier` was provided.
        """
        self._capability = capability if capability is not None else AuditCapability()
        if self._capability.level == Level.L2 and verifier is None:
            raise ValueError('an L2 host requires a SignatureVerifier')
            # end if
        self._partition = partition
        self._ledger = Ledger(partition)
        self._verifier = verifier
        self._repository = repository
        self._clock = clock if clock is not None else SystemClock()
        # Set False by the integrator when persistence is known to be down; also fail closed.
        self.persistence_available = True
        self._accepted_attempts: set[str] = set()
        self._rejected_ids: set[str] = set()
        self._last_seq_by_key: dict[str, int] = {}
        self._anomalies: list[IntegrityAnomaly] = []
        # end def

    @classmethod
    async def resume(
        cls,
        partition: str,
        capability: AuditCapability | None = None,
        *,
        repository: LedgerRepository,
        verifier: SignatureVerifier | None = None,
        clock: Clock | None = None,
    ) -> AuditHost:
        """Build a host that continues `partition`'s persisted chain.

        The chain state (next `seq`, tail link) and the L2 replay/sequence state are reconstructed
        from the stored records, so post-restart appends link correctly and replays are still caught.
        Reject memory (`outcome-after-reject`) is not persisted, so an outcome for a pre-restart
        rejected id degrades to `outcome-without-attempt`.
        """
        host = cls(partition, capability, verifier=verifier, repository=repository, clock=clock)
        records = await repository.read_all(partition)
        host._ledger.resume_from(records[-1] if records else None)
        for record in records:
            if record.event.get(fields.OUTCOME) == Outcome.ATTEMPTED:
                host._accepted_attempts.add(_event_id(record.event))
                # end if
            host._advance_seq(record.event)
            # end for
        return host
        # end def

    async def _seal(self, event: dict[str, object], host_ts: str) -> SealedRecord | None:
        """Seal `event`, persist it if a repository is configured, then commit; None on persistence failure."""
        sealed = self._ledger.seal(event, host_ts)
        if self._repository is not None:
            try:
                await self._repository.append(self._partition, sealed)
            except RepositoryError:
                return None
                # end try
            # end if
        self._ledger.commit(sealed)
        return sealed
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The audit capability this host requires (§6.1)."""
        return self._capability
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

    def _flag(self, event_id: str, kind: str, detail: str) -> None:
        """Record an integrity anomaly."""
        self._anomalies.append(IntegrityAnomaly(id=event_id, kind=kind, detail=detail))
        # end def

    async def _check_l2(self, event: dict[str, object]) -> str | None:
        """Verify the L2 signature and per-key sequence; return a reject reason, or None (no-op under L1).

        Unsigned / unknown-key / forged / replayed records are rejected. A forward sequence gap is
        flagged but not rejected — the missing event cannot be recovered (§7.4).
        """
        if self._capability.level != Level.L2:
            return None
            # end if
        key_id = event.get(fields.KEY_ID)
        signature = event.get(fields.SIGNATURE)
        sequence = event.get(fields.SEQUENCE)
        if not signature or not isinstance(key_id, str) or not isinstance(sequence, int):
            self._flag(_event_id(event), reasons.L2_UNSIGNED, 'L2 requires signature, key_id, and sequence')
            return reasons.L2_UNSIGNED
            # end if
        # A verifier is guaranteed present under L2 (enforced in __init__).
        assert self._verifier is not None
        reason = await self._verifier.verify(event)
        if reason is not None:
            self._flag(_event_id(event), reason, 'signature verification failed')
            return reason
            # end if
        # The first event from a key only establishes the baseline: with no prior observation there is
        # nothing to have skipped, so neither replay nor gap applies (a tool's per-key start is arbitrary,
        # and cross-partition interleaving makes it unknowable from one partition, §10.5).
        last = self._last_seq_by_key.get(key_id)
        if last is not None:
            if sequence <= last:
                self._flag(_event_id(event), reasons.SIGNER_SEQUENCE_REPLAY, f'sequence {sequence} <= last {last}')
                return reasons.SIGNER_SEQUENCE_REPLAY
                # end if
            if sequence > last + 1:
                self._flag(
                    _event_id(event),
                    reasons.SIGNER_SEQUENCE_GAP,
                    f'expected {last + 1}, got {sequence} (suppressed event)',
                )
                # end if
            # end if
        return None
        # end def

    def _advance_seq(self, event: dict[str, object]) -> None:
        """Advance the per-key sequence tracker after a record is sealed (follows accepted, not seen)."""
        key_id = event.get(fields.KEY_ID)
        sequence = event.get(fields.SEQUENCE)
        if isinstance(key_id, str) and isinstance(sequence, int):
            self._last_seq_by_key[key_id] = sequence
            # end if
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject or fail closed (§7.1)."""
        error = first_validation_error(event)
        if error is not None:
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, error)
            return reject(reasons.SCHEMA_INVALID)
            # end if
        if event.get(fields.OUTCOME) != Outcome.ATTEMPTED:
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, 'an attempt must carry outcome=attempted')
            return reject(reasons.ATTEMPT_MUST_BE_ATTEMPTED)
            # end if
        # Not canonicalizable (§8.1): reject gracefully instead of raising at seal time.
        if has_unsafe_number(event):
            self._flag(_event_id(event), reasons.NUMERIC_DOMAIN, 'a numeric value is not canonicalizable (§8.1)')
            return reject(reasons.NUMERIC_DOMAIN)
            # end if
        l2_reason = await self._check_l2(event)
        if l2_reason is not None:
            self._rejected_ids.add(_event_id(event))
            return reject(l2_reason)
            # end if
        if not self.persistence_available:
            # Fail closed: the tool must not act on an unpersisted record.
            return unavailable(reasons.PERSISTENCE_FAILURE)
            # end if
        event_id = _event_id(event)
        if event_id in self._accepted_attempts:
            self._rejected_ids.add(event_id)
            self._flag(event_id, reasons.ATTEMPT_REPLAY, 'duplicate attempt id')
            return reject(reasons.ATTEMPT_REPLAY)
            # end if
        sealed = await self._seal(event, self._clock.now())
        if sealed is None:
            # Persistence failed after validation: fail closed so the tool retries (not accepted).
            return unavailable(reasons.PERSISTENCE_FAILURE)
            # end if
        self._accepted_attempts.add(event_id)
        self._advance_seq(event)
        # Verifiable Accept (§7.1): return the host-assigned fields the tool needs for Polluted Stop.
        return accept(sealed.seq, sealed.record_hash, sealed.host_ts, sealed.previous_hash)
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Seal a correlated outcome, or flag an uncorrelated one; drop invalid records (§7.2)."""
        error = first_validation_error(event)
        if error is not None:
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, error)
            return
            # end if
        if has_unsafe_number(event):
            self._flag(_event_id(event), reasons.NUMERIC_DOMAIN, 'a numeric value is not canonicalizable (§8.1)')
            return
            # end if
        event_id = _event_id(event)
        outcome = event.get(fields.OUTCOME)
        # §10.4: a fail-closed aborted outcome for a never-accepted attempt is the honest refused-action
        # signal, not a tampering anomaly. Exempt it before _check_l2 so a fresh signer sequence that
        # outran the unsealed attempt is not flagged as a suppression gap.
        if outcome == Outcome.ABORTED and event_id not in self._accepted_attempts:
            return
            # end if
        if await self._check_l2(event) is not None:
            return
            # end if
        if event_id in self._accepted_attempts:
            # Correlated outcomes are sealed, not de-duplicated (§8.3). An outcome is a notification
            # with no response channel, so a persistence failure is flagged, not returned.
            sealed = await self._seal(event, self._clock.now())
            if sealed is None:
                self._flag(event_id, reasons.PERSISTENCE_FAILURE, 'could not persist outcome')
                return
                # end if
            self._advance_seq(event)
            return
            # end if
        if event_id in self._rejected_ids:
            self._flag(event_id, reasons.OUTCOME_AFTER_REJECT, f'outcome={outcome} for rejected id')
        else:
            self._flag(event_id, reasons.OUTCOME_WITHOUT_ATTEMPT, f'outcome={outcome} without accepted attempt')
            # end if
        # end def

    # end class


def _event_id(event: dict[str, object]) -> str:
    """Best-effort id extraction for anomaly logging."""
    event_id = event.get(fields.ID)
    return event_id if isinstance(event_id, str) else '<unknown>'
    # end def
