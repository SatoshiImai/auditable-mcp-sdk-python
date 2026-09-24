"""Unit tests for the §6.2 degradation postures: what a tool does with an unnegotiated session."""

import pytest

from auditable_mcp.capability import NegotiationOutcome, negotiate
from auditable_mcp.degradation import Posture, UnnegotiatedSessionError, transport_for
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Level, TargetResource, Witness
from auditable_mcp.session import AmcpSession
from auditable_mcp.verify import verify_ledger


class _Clock:
    """A deterministic host clock."""

    def __init__(self) -> None:
        """Start the counter at the first tick."""
        self._tick = 0
        # end def

    def now(self) -> str:
        """Return the next fixed timestamp."""
        self._tick += 1
        return f'2026-07-15T00:00:{self._tick:02d}.000Z'
        # end def

    # end class


class _FixedDeps:
    """Deterministic id/time source."""

    def __init__(self) -> None:
        """Start the id counter at zero."""
        self._n = 0
        # end def

    def new_id(self) -> str:
        """Return the next deterministic UUID-shaped id."""
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'
        # end def

    def now(self) -> str:
        """Return a fixed valid ISO-8601 timestamp."""
        return '2026-07-15T00:00:01.000Z'
        # end def

    # end class


def _cap(*, level: Level = Level.L1, witness: Witness = Witness.NONE, version: str = SPEC_VERSION) -> AuditCapability:
    """A capability varying only the axis under test."""
    return AuditCapability(spec_version=version, level=level, attempt='request', witness=witness)
    # end def


def _self_hosted() -> InProcessTransport:
    """A transport over an audit host the tool provides for itself (the degraded posture)."""
    return InProcessTransport(AuditHost('tool-local', _cap(), clock=_Clock()))
    # end def


def _wire() -> InProcessTransport:
    """A stand-in for the transport to a host that did negotiate."""
    return InProcessTransport(AuditHost('tenant-a', _cap(), clock=_Clock()))
    # end def


def test_a_negotiated_session_uses_the_host() -> None:
    """Nothing degrades when the comparison succeeded (§6.1)."""
    wire, fallback = _wire(), _self_hosted()
    chosen = transport_for(negotiate(_cap(), _cap()), negotiated=wire, fallback=fallback)
    assert chosen is wire
    # end def


def test_an_undeclared_host_degrades_to_the_tool_s_own() -> None:
    """A host that declared nothing is the common case, and the tool stays usable (§6.2)."""
    wire, fallback = _wire(), _self_hosted()
    negotiation = negotiate(None, _cap())
    assert negotiation.outcome is NegotiationOutcome.UNDECLARED
    assert transport_for(negotiation, negotiated=wire, fallback=fallback) is fallback
    # end def


def test_a_mismatched_host_degrades_the_same_way() -> None:
    """A declaration that does not fit leaves the session unnegotiated, like an absent one (§6.2)."""
    wire, fallback = _wire(), _self_hosted()
    negotiation = negotiate(_cap(version='auditable-mcp/0.1'), _cap())
    assert negotiation.outcome is NegotiationOutcome.MISMATCH
    assert transport_for(negotiation, negotiated=wire, fallback=fallback) is fallback
    # end def


def test_the_mandatory_posture_declines_to_serve() -> None:
    """[SEP-2133] permits refusing where an unwitnessed record has no value (§6.2)."""
    with pytest.raises(UnnegotiatedSessionError) as caught:
        transport_for(negotiate(None, _cap()), negotiated=_wire(), fallback=_self_hosted(), posture=Posture.MANDATORY)
        # end with
    assert caught.value.negotiation.outcome is NegotiationOutcome.UNDECLARED
    # end def


def test_the_third_posture_is_not_available() -> None:
    """Serving while neither recording nor reporting is not conformant, so it cannot be chosen (§6.2)."""
    with pytest.raises(ValueError, match='fallback'):
        transport_for(negotiate(None, _cap()), negotiated=_wire())
        # end with
    # end def


def test_a_mandatory_tool_never_needs_a_fallback() -> None:
    """Refusing to serve records nothing, so the posture stands without one (§6.2)."""
    with pytest.raises(UnnegotiatedSessionError):
        transport_for(negotiate(None, _cap()), negotiated=_wire(), posture=Posture.MANDATORY)
        # end with
    # end def


@pytest.mark.asyncio
async def test_a_degraded_session_keeps_recording_and_the_chain_is_unwitnessed() -> None:
    """The recording does not stop; the host's witness does, and the records say so (§5.2, §6.2)."""
    host = AuditHost('tool-local', _cap(), clock=_Clock())
    fallback = InProcessTransport(host)
    transport = transport_for(negotiate(None, _cap()), negotiated=_wire(), fallback=fallback)
    session = AmcpSession(transport, 'call-1', deps=_FixedDeps())
    async with session.action('db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False):
        pass
        # end async with
    records = host.records()
    assert records, 'the degraded posture must still record'
    assert all(record.host_signature is None for record in records)
    report = verify_ledger(records)
    assert report.complete, 'nothing was applicable and skipped, so the chain is fully checked'
    # end def
