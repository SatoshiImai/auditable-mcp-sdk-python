"""The host-side audit subsystem — a deterministic recording engine (§7).

`AuditHost` implements `AuditEndpoint` for exactly one partition (§10.5): it owns one `Ledger`, one
`seq` counter, one per-`key_id` sequence tracker, and one anomaly set, and there is no code path that
crosses partitions. Multi-tenant deployments instantiate one host per partition and route by
connection; that routing is the integrator's concern, above this SDK.

The host validates ledger-integrity requirements before sealing (§7.1); it never authorizes the
tool's domain action (§2). Under Level 2 it defers signature checking to an injected
`SignatureVerifier` (the concrete registry-backed verifier lives in the `l2` layer), while sequence tracking
and anomaly flagging are host logic. A persistence failure fails closed with a retryable
`unavailable` (§7.1).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Final, Protocol

from auditable_mcp import fields, reasons
from auditable_mcp.canonical import has_unsafe_number
from auditable_mcp.clock import Clock, SystemClock
from auditable_mcp.hashing import witness_payload
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.models import (
    SPEC_VERSION,
    AttemptResponse,
    AuditCapability,
    AuditCapabilityInput,
    Level,
    Outcome,
    RejectReason,
    Witness,
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
    'witness': Witness.NONE,
}


class WitnessSigner(Protocol):
    """Signs the host-assigned fields of a record this host sealed (§5.2, §7.1).

    `sign` is async for the same reason `EventSigner.sign` is: a production host signs through a
    network HSM or KMS. The payload is already canonical (`witness_payload`), so a signer does
    cryptography only - the preimage is built in one place, by the host.
    """

    @property
    def key_id(self) -> str:
        """The `host_key_id` a verifier's registry binds to this host."""
        ...

    async def sign(self, payload: bytes) -> str:
        """Return the standard-base64 detached signature over `payload`."""
        ...

    # end class


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
        witness_signer: WitnessSigner | None = None,
        repository: LedgerRepository | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Initialize the host for `partition` under a capability, with optional verifier and store.

        With a `repository`, every accepted record is durably persisted before it is committed and
        acknowledged; a persistence failure fails closed (§7.1). Use `AuditHost.resume` to restart a
        host from a persisted chain.

        Raises:
            ValueError: If the required level is Level 2 but no `verifier` was provided, or the host
                declares `witness: "host"` but no `witness_signer` was provided.
        """
        self._capability = _resolve_capability(capability)
        if self._capability.level == Level.L2 and verifier is None:
            raise ValueError('an L2 host requires a SignatureVerifier')
            # end if
        # A host that declares it signs and then does not would leave every record unwitnessed while
        # its peers expect otherwise; the declaration is refused at construction instead (§11.2).
        if self._capability.witness == Witness.HOST and witness_signer is None:
            raise ValueError('a host declaring witness "host" requires a WitnessSigner')
            # end if
        self._partition = partition
        self._ledger = Ledger(partition)
        self._verifier = verifier
        self._witness_signer = witness_signer
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
        capability: AuditCapability | AuditCapabilityInput | None = None,
        *,
        repository: LedgerRepository,
        verifier: SignatureVerifier | None = None,
        witness_signer: WitnessSigner | None = None,
        clock: Clock | None = None,
    ) -> AuditHost:
        """Build a host that continues `partition`'s persisted chain.

        The chain state (next `seq`, tail link) and the L2 replay/sequence state are reconstructed
        from the stored records, so post-restart appends link correctly and replays are still caught.
        Reject memory is not persisted, so an outcome for a pre-restart rejected id is still flagged
        `orphaned-outcome`, as a never-accepted one.
        """
        host = cls(
            partition,
            capability,
            verifier=verifier,
            witness_signer=witness_signer,
            repository=repository,
            clock=clock,
        )
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
        if self._witness_signer is not None:
            payload = witness_payload(sealed.seq, sealed.host_ts, sealed.previous_hash, sealed.record_hash)
            sealed = replace(
                sealed,
                host_signature=await self._witness_signer.sign(payload),
                host_key_id=self._witness_signer.key_id,
            )
            # end if
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

    async def _check_l2(self, event: dict[str, object]) -> RejectReason | None:
        """Verify the L2 signature and per-key signer_seq; return a reject reason, or None (no-op under L1).

        Unsigned / unknown-key / forged records and a replayed signer_seq are rejected. A forward gap
        is flagged but not rejected — the missing event cannot be recovered (§7.4, §7.6).
        """
        if self._capability.level != Level.L2:
            return None
            # end if
        key_id = event.get(fields.KEY_ID)
        signature = event.get(fields.SIGNATURE)
        signer_seq = event.get(fields.SIGNER_SEQ)
        if not signature or not isinstance(key_id, str) or not isinstance(signer_seq, int):
            self._flag(_event_id(event), reasons.L2_UNSIGNED, 'L2 requires signature, key_id, and signer_seq')
            return reasons.L2_UNSIGNED
            # end if
        # A verifier is guaranteed present under L2 (enforced in __init__).
        assert self._verifier is not None
        reason = await self._verifier.verify(event)
        if reason is not None:
            self._flag(_event_id(event), reason, 'signature verification failed')
            return reason
            # end if
        # The first signer_seq from a key only establishes the baseline: with no prior observation
        # there is nothing to have skipped, so neither replay nor gap applies (a tool's per-key start is
        # arbitrary, and cross-partition interleaving makes it unknowable from one partition, §7.4, §10.5).
        last = self._last_seq_by_key.get(key_id)
        if last is not None:
            # A replay (signer_seq at or below the last accepted) is a hard reject (§7.6).
            if signer_seq <= last:
                self._flag(_event_id(event), reasons.REPLAY_DETECTED, f'signer_seq {signer_seq} <= last {last}')
                return reasons.REPLAY_DETECTED
                # end if
            # A forward gap is flagged as an advisory anomaly, not rejected (the missing event is lost).
            if signer_seq > last + 1:
                self._flag(
                    _event_id(event),
                    reasons.SIGNER_SEQ_GAP,
                    f'expected {last + 1}, got {signer_seq} (suppressed event)',
                )
                # end if
            # end if
        return None
        # end def

    def _advance_seq(self, event: dict[str, object]) -> None:
        """Advance the per-key signer_seq tracker after a record is sealed (follows accepted, not seen)."""
        key_id = event.get(fields.KEY_ID)
        signer_seq = event.get(fields.SIGNER_SEQ)
        if isinstance(key_id, str) and isinstance(signer_seq, int):
            self._last_seq_by_key[key_id] = signer_seq
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
            # Tier-2 (an attempt must carry outcome=attempted) rolls up to schema-invalid (§7.6).
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, 'an attempt must carry outcome=attempted')
            return reject(reasons.SCHEMA_INVALID)
            # end if
        # Not canonicalizable (§8.1): reject gracefully (rolls up to schema-invalid) instead of raising.
        if has_unsafe_number(event):
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, 'a numeric value is not canonicalizable (§8.1)')
            return reject(reasons.SCHEMA_INVALID)
            # end if
        l2_reason = await self._check_l2(event)
        if l2_reason is not None:
            self._rejected_ids.add(_event_id(event))
            return reject(l2_reason)
            # end if
        if not self.persistence_available:
            # Fail closed: the tool must not act on an unpersisted record.
            return unavailable()
            # end if
        event_id = _event_id(event)
        if event_id in self._accepted_attempts:
            self._rejected_ids.add(event_id)
            self._flag(event_id, reasons.REPLAY_DETECTED, 'duplicate attempt id')
            return reject(reasons.REPLAY_DETECTED)
            # end if
        sealed = await self._seal(event, self._clock.now())
        if sealed is None:
            # Persistence failed after validation: fail closed so the tool retries (not accepted).
            return unavailable()
            # end if
        self._accepted_attempts.add(event_id)
        self._advance_seq(event)
        # Verifiable Accept (§7.1): return the host-assigned fields the tool needs for Polluted Stop.
        return accept(
            sealed.seq,
            sealed.record_hash,
            sealed.host_ts,
            sealed.previous_hash,
            host_signature=sealed.host_signature,
            host_key_id=sealed.host_key_id,
        )
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Seal a correlated outcome, or flag an uncorrelated one; drop invalid records (§7.2)."""
        error = first_validation_error(event)
        if error is not None:
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, error)
            return
            # end if
        if has_unsafe_number(event):
            self._flag(_event_id(event), reasons.SCHEMA_INVALID, 'a numeric value is not canonicalizable (§8.1)')
            return
            # end if
        event_id = _event_id(event)
        outcome = event.get(fields.OUTCOME)
        # §6: an `attempted` outcome on the audit/outcome channel is invalid; drop and flag it rather than
        # sealing a second attempt record for the id (§7.1 uniqueness).
        if outcome == Outcome.ATTEMPTED:
            self._flag(event_id, reasons.SCHEMA_INVALID, 'attempted outcome on the audit/outcome channel (§6)')
            return
            # end if
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
                # A lost outcome is a completeness gap (§10.8), not a ledger integrity anomaly, and
                # `internal-error` is not a Tier-1 anomaly kind (§7.6): log it locally instead of
                # flagging the anomaly set with an out-of-space code.
                _logger.error(
                    'could not persist correlated outcome id=%s; outcome lost (completeness gap, §10.8)', event_id
                )
                return
                # end if
            self._advance_seq(event)
            return
            # end if
        # Both never-accepted and post-reject orphans roll up to the orphaned-outcome anomaly (§7.6); the
        # finer distinction is a Tier-2 local detail.
        if event_id in self._rejected_ids:
            self._flag(event_id, reasons.ORPHANED_OUTCOME, f'outcome={outcome} for rejected id')
        else:
            self._flag(event_id, reasons.ORPHANED_OUTCOME, f'outcome={outcome} without accepted attempt')
            # end if
        # end def

    # end class


def _event_id(event: dict[str, object]) -> str:
    """Best-effort id extraction for anomaly logging."""
    event_id = event.get(fields.ID)
    return event_id if isinstance(event_id, str) else '<unknown>'
    # end def
