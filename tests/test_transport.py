"""Unit tests for capability negotiation and the in-process transport."""

from auditable_mcp.capability import negotiate
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.models import (
    AcceptResponse,
    AttemptResponse,
    AuditCapability,
    Level,
    UnavailableResponse,
)
from auditable_mcp.transport import AuditEndpoint, AuditTransport, accept, reject, unavailable


class _RecordingEndpoint:
    """A minimal AuditEndpoint that returns a fixed response and records what it received."""

    def __init__(self, level: Level = Level.L1, response: AttemptResponse | None = None) -> None:
        """Configure the required level and the canned attempt response."""
        self._capability = AuditCapability(level=level)
        self._response = response or accept(0, 'a' * 64, '2026-07-15T00:00:01.000Z', '0' * 64)
        self.attempts: list[dict[str, object]] = []
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The required capability."""
        return self._capability
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Record and answer an attempt."""
        self.attempts.append(event)
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Record an outcome."""
        self.outcomes.append(event)
        # end def


def test_l2_tool_satisfies_an_l1_host() -> None:
    """An L2 offer is a safe downgrade for an L1 requirement."""
    result = negotiate(AuditCapability(level=Level.L1), AuditCapability(level=Level.L2))
    assert result.satisfied
    # end def


def test_l1_tool_does_not_satisfy_an_l2_host() -> None:
    """An L1-only tool cannot meet an L2 requirement."""
    result = negotiate(AuditCapability(level=Level.L2), AuditCapability(level=Level.L1))
    assert not result.satisfied
    # end def


def test_equal_levels_are_satisfied() -> None:
    """Matching levels negotiate successfully."""
    assert negotiate(AuditCapability(level=Level.L2), AuditCapability(level=Level.L2)).satisfied
    # end def


def test_response_builders_produce_the_correct_variants() -> None:
    """The helper factories build the tagged-union response models."""
    acc = accept(3, 'b' * 64, '2026-07-15T00:00:03.000Z', 'a' * 64)
    assert isinstance(acc, AcceptResponse)
    assert acc.seq == 3
    assert reject('schema-invalid').reason == 'schema-invalid'
    un = unavailable('persistence-failure')
    assert isinstance(un, UnavailableResponse)
    assert un.retryable is True
    # end def


def test_in_process_transport_negotiates_against_the_endpoint() -> None:
    """The transport uses the endpoint's required capability for negotiation."""
    transport = InProcessTransport(_RecordingEndpoint(level=Level.L2))
    assert not transport.negotiate(AuditCapability(level=Level.L1)).satisfied
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
