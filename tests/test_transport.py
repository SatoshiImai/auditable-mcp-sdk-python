"""Unit tests for capability negotiation and the in-process transport."""

import pytest
from pydantic import ValidationError

from auditable_mcp.capability import NegotiationOutcome, negotiate
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.models import (
    SPEC_VERSION,
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    Countersign,
    Level,
    UnavailableResponse,
)
from auditable_mcp.transport import AuditEndpoint, AuditTransport, accept, reject, unavailable


class _RecordingEndpoint:
    """A minimal AuditEndpoint that returns a fixed response and records what it received."""

    def __init__(self, level: Level = Level.L1, response: AttemptResponse | None = None) -> None:
        """Configure the required level and the canned attempt response."""
        self._capability = AuditCapability(
            spec_version=SPEC_VERSION, level=level, attempt='request', countersign=Countersign.NONE
        )
        self._response = response or accept(0, 'a' * 64, '2026-07-15T00:00:01.000Z', '0' * 64)
        self.attempts: list[dict[str, object]] = []
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The required capability."""
        return self._capability
        # end def

    def open_session(self, session_id: str | None = None) -> str:
        """Issue the one session this endpoint serves."""
        return session_id or '0198f3a2-5c1e-7000-8000-00000000abc0'
        # end def

    async def close_session(self, session_id: str) -> None:
        """Nothing to close."""
        # end def

    async def handle_attempt(
        self, event: dict[str, object], *, session_id: str | None = None, deadline: float | None = None
    ) -> AttemptResponse:
        """Record and answer an attempt."""
        self.attempts.append(event)
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object], *, session_id: str | None = None) -> None:
        """Record an outcome."""
        self.outcomes.append(event)
        # end def


def test_l2_tool_satisfies_an_l1_host() -> None:
    """An L2 offer is a safe downgrade for an L1 requirement."""
    result = negotiate(
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE),
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
    )
    assert result.negotiated
    # end def


def test_l1_tool_does_not_satisfy_an_l2_host() -> None:
    """An L1-only tool cannot meet an L2 requirement."""
    result = negotiate(
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE),
    )
    assert not result.negotiated
    # end def


def test_equal_levels_are_satisfied() -> None:
    """Matching levels negotiate successfully."""
    assert negotiate(
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE),
    ).negotiated
    # end def


def test_response_builders_produce_the_correct_variants() -> None:
    """The helper factories build the tagged-union response models."""
    acc = accept(3, 'b' * 64, '2026-07-15T00:00:03.000Z', 'a' * 64)
    assert isinstance(acc, AcceptResponse)
    assert acc.seq == 3
    assert reject('schema-invalid').reason == 'schema-invalid'
    un = unavailable()
    assert isinstance(un, UnavailableResponse)
    # end def


def test_in_process_transport_negotiates_against_the_endpoint() -> None:
    """The transport uses the endpoint's required capability for negotiation."""
    transport = InProcessTransport(_RecordingEndpoint(level=Level.L2))
    assert not transport.negotiate(
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE)
    ).negotiated
    # end def


def test_capability_missing_spec_version_is_rejected() -> None:
    """spec_version is REQUIRED on the wire; an omitted version is an error, not defaulted (§6.1)."""
    with pytest.raises(ValidationError):
        AuditCapability.model_validate({'level': 'L2', 'attempt': 'request'})
        # end with
    # end def


def test_version_mismatch_is_not_satisfied() -> None:
    """A spec_version mismatch withholds satisfaction even at a compatible level (§6.1)."""
    offered = AuditCapability(
        spec_version='auditable-mcp/0.1', level=Level.L1, attempt='request', countersign=Countersign.NONE
    )
    result = negotiate(
        AuditCapability(spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE),
        offered,
    )
    assert result.version_match is False
    assert result.negotiated is False
    # end def


async def test_in_process_transport_forwards_attempt_and_returns_response() -> None:
    """send_attempt delivers the event unchanged and returns the endpoint's response."""
    endpoint = _RecordingEndpoint(response=accept(7, 'c' * 64, '2026-07-15T00:00:07.000Z', 'a' * 64))
    transport = InProcessTransport(endpoint)
    event = {'id': '00000000-0000-4000-8000-000000000001', 'outcome': 'attempted'}
    response = await transport.send_attempt(event)
    assert endpoint.attempts == [event]
    assert isinstance(response, AcceptResponse)
    assert response.seq == 7
    # end def


async def test_in_process_transport_forwards_outcome() -> None:
    """send_outcome delivers the outcome event to the endpoint."""
    endpoint = _RecordingEndpoint()
    transport = InProcessTransport(endpoint)
    event = {'id': '00000000-0000-4000-8000-000000000001', 'outcome': 'success'}
    await transport.send_outcome(event)
    assert endpoint.outcomes == [event]
    # end def


def test_structural_conformance_to_the_protocols() -> None:
    """The concrete transport and fake endpoint satisfy their runtime-checkable protocols."""
    endpoint = _RecordingEndpoint()
    assert isinstance(endpoint, AuditEndpoint)
    assert isinstance(InProcessTransport(endpoint), AuditTransport)
    # end def


def _cap(level: Level = Level.L1, countersign: Countersign = Countersign.NONE) -> AuditCapability:
    """A capability at the current spec version, varying only the axis under test."""
    return AuditCapability(spec_version=SPEC_VERSION, level=level, attempt='request', countersign=countersign)
    # end def


def test_a_signing_host_satisfies_a_tool_that_requires_a_countersign() -> None:
    """The host produces on this axis, so its `host` meets a tool requiring `host` (§5.2, §6.1)."""
    assert negotiate(_cap(countersign=Countersign.HOST), _cap(countersign=Countersign.HOST)).negotiated
    # end def


def test_a_non_signing_host_cannot_satisfy_a_tool_that_requires_a_countersign() -> None:
    """A countersign shortfall fails the comparison at initialize rather than aborting every call (§6.1)."""
    result = negotiate(_cap(countersign=Countersign.NONE), _cap(countersign=Countersign.HOST))
    assert result.outcome is NegotiationOutcome.MISMATCH
    assert result.countersign_fit is False
    assert result.level_fit is True
    # end def


def test_a_signing_host_satisfies_a_tool_that_requires_nothing() -> None:
    """The countersignature axis runs opposite to level: the surplus is on the host side, and it is safe."""
    result = negotiate(_cap(countersign=Countersign.HOST), _cap(countersign=Countersign.NONE))
    assert result.negotiated
    # end def


def test_the_axes_run_in_opposite_directions() -> None:
    """A surplus satisfies on each axis only from the side that produces it (§6.1)."""
    # Level: the tool produces, so a tool surplus is safe and a host surplus is not.
    assert negotiate(_cap(level=Level.L1), _cap(level=Level.L2)).negotiated
    assert not negotiate(_cap(level=Level.L2), _cap(level=Level.L1)).negotiated
    # Countersign: the host produces, so the surplus that is safe sits on the other side.
    assert negotiate(_cap(countersign=Countersign.HOST), _cap(countersign=Countersign.NONE)).negotiated
    assert not negotiate(_cap(countersign=Countersign.NONE), _cap(countersign=Countersign.HOST)).negotiated
    # end def


def test_an_undeclared_host_is_not_a_mismatch() -> None:
    """A host that declared nothing is an absent negotiation, which §6.2 governs differently."""
    result = negotiate(None, _cap())
    assert result.outcome is NegotiationOutcome.UNDECLARED
    assert result.negotiated is False
    assert result.host is None
    # end def


def test_every_unnegotiated_outcome_is_distinguishable() -> None:
    """A caller that collapsed undeclared into mismatch would brick the tool against ordinary hosts."""
    undeclared = negotiate(None, _cap())
    mismatch = negotiate(
        _cap(),
        AuditCapability(
            spec_version='auditable-mcp/0.1', level=Level.L1, attempt='request', countersign=Countersign.NONE
        ),
    )
    assert not undeclared.negotiated and not mismatch.negotiated
    assert undeclared.outcome is not mismatch.outcome
    # end def
