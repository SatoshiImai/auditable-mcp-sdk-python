"""Reconciliation: boundary-observed egress vs self-reported events (§7.5, §10.2).

Cryptographic checks catch falsified or lost records, but not an egress a tool never reports at all
(suppression by omission). Comparing independent boundary observations (e.g. from a gateway) against
the tool's self-reported audit stream detects that omission — the one class of misbehaviour signatures
cannot reach.
"""

from dataclasses import dataclass

from auditable_mcp import fields
from auditable_mcp.ledger import SealedRecord

# Reconcile anomaly kind, local to this module.
UNREPORTED_EGRESS = 'unreported-egress'


@dataclass(frozen=True)
class EgressObservation:
    """An egress the host observed independently at the boundary."""

    call_id: str
    destination: str
    # end class


class BoundaryObserver:
    """Records egress facts the host sees independently (e.g. a network gateway)."""

    def __init__(self) -> None:
        """Initialize with no observations."""
        self._observations: list[EgressObservation] = []
        # end def

    def observe_egress(self, call_id: str, destination: str) -> None:
        """Record an observed egress for a call."""
        self._observations.append(EgressObservation(call_id=call_id, destination=destination))
        # end def

    def for_call(self, call_id: str) -> list[EgressObservation]:
        """Return the observations recorded for a given call."""
        return [observation for observation in self._observations if observation.call_id == call_id]
        # end def

    # end class


@dataclass(frozen=True)
class ReconcileAnomaly:
    """A mismatch between self-reports and boundary observations."""

    call_id: str
    kind: str
    destination: str
    detail: str
    # end class


def reconcile(
    records: list[SealedRecord],
    observations: list[EgressObservation],
    call_id: str,
) -> list[ReconcileAnomaly]:
    """Compare self-reported egress against boundary observations for one call.

    Detects suppression by omission only (§7.5): an egress the boundary observed but the tool never
    self-reported. The reverse (self-reported but boundary-unobserved) is not an anomaly — a boundary
    is not omniscient, so its blind spots are not tool misbehaviour.

    Args:
        records: The sealed records to scan.
        observations: The boundary egress observations.
        call_id: The call to reconcile.

    Returns:
        The unreported-egress anomalies, ordered by destination for determinism.
    """
    reported = {
        _target_ref(record)
        for record in records
        if record.event.get(fields.CALL_ID) == call_id and record.event.get(fields.EGRESS)
    }
    observed = {observation.destination for observation in observations if observation.call_id == call_id}

    anomalies = [
        ReconcileAnomaly(
            call_id=call_id,
            kind=UNREPORTED_EGRESS,
            destination=destination,
            detail='observed egress with no self-report',
        )
        for destination in observed
        if destination not in reported
    ]
    anomalies.sort(key=lambda anomaly: anomaly.destination)
    return anomalies
    # end def


def _target_ref(record: SealedRecord) -> object:
    """Return the target_resource ref of a record's event, if present."""
    target = record.event.get(fields.TARGET_RESOURCE)
    return target.get(fields.REF) if isinstance(target, dict) else None
    # end def
