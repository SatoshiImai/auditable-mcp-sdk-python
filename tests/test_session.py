"""Unit tests for the audit-before-act session core and the decorator."""

import pytest

from auditable_mcp.decorator import auditable_tool, bound_session, current_session
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.ledger import Ledger
from auditable_mcp.models import SPEC_VERSION, AttemptResponse, AuditCapability, Countersign, Level, TargetResource
from auditable_mcp.session import AmcpAbortedError, AmcpSession
from auditable_mcp.transport import AmcpUsageError, accept, reject, unavailable
from auditable_mcp.verify import verify_ledger

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


class _FixedDeps:
    """Deterministic id/time source for reproducible tests."""

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


class _StubSigner:
    """A non-cryptographic signer that stamps L2 fields so the session's L2 path can be exercised."""

    key_id = 'k1'

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Stamp key_id, the number the session's section holds, and a placeholder signature."""
        return {**event, 'key_id': self.key_id, 'signer_seq': signer_seq, 'signature': 'stub'}
        # end def


class _SealingEndpoint:
    """A minimal host that seals every event into a ledger and returns a Verifiable Accept."""

    def __init__(self, level: Level = Level.L1) -> None:
        """Initialize an empty ledger and a monotonic host clock."""
        self._capability = AuditCapability(
            spec_version=SPEC_VERSION, level=level, attempt='request', countersign=Countersign.NONE
        )
        self.ledger = Ledger('test')
        self._clock = 0
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The required capability."""
        return self._capability
        # end def

    def _next_ts(self) -> str:
        """Return the next monotonic host timestamp."""
        self._clock += 1
        return f'2026-07-15T00:00:{self._clock:02d}.000Z'
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Seal the attempt and return the sealed fields."""
        sealed = self.ledger.append(event, self._next_ts())
        return accept(sealed.seq, sealed.record_hash, sealed.host_ts, sealed.previous_hash)
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Seal the outcome."""
        self.outcomes.append(event)
        self.ledger.append(event, self._next_ts())
        # end def


class _CannedEndpoint:
    """A host that answers attempts with a fixed response and records outcomes (no sealing)."""

    def __init__(self, response: AttemptResponse, level: Level = Level.L1) -> None:
        """Configure the canned attempt response."""
        self._capability = AuditCapability(
            spec_version=SPEC_VERSION, level=level, attempt='request', countersign=Countersign.NONE
        )
        self._response = response
        self.outcomes: list[dict[str, object]] = []
        # end def

    @property
    def capability(self) -> AuditCapability:
        """The required capability."""
        return self._capability
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Return the canned response."""
        return self._response
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Record the outcome."""
        self.outcomes.append(event)
        # end def


def _session(endpoint: object, **kwargs: object) -> AmcpSession:
    """Build a session over an in-process transport to `endpoint`."""
    return AmcpSession(InProcessTransport(endpoint), SESSION, deps=_FixedDeps(), **kwargs)  # type: ignore[arg-type]


async def test_happy_path_seals_attempt_then_success() -> None:
    """A clean action seals a correlated attempt + success that verify as a valid chain."""
    endpoint = _SealingEndpoint()
    session = _session(endpoint)
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False) as action:
        assert action.accept is not None
        assert action.accept.seq == 0
        # end with
    records = endpoint.ledger.records()
    assert [r.event['outcome'] for r in records] == ['attempted', 'success']
    assert records[0].event['id'] == records[1].event['id']  # shared correlation id
    assert verify_ledger(records, endpoint.ledger.digest()).ok
    # end def


async def test_disclose_and_commit_are_recorded() -> None:
    """disclose becomes action_context; commit becomes a sha256 action_context_hash (§4.3)."""
    endpoint = _SealingEndpoint()
    session = _session(endpoint)
    async with session.action(
        'db.query',
        {'kind': 'database', 'ref': 'pg'},
        mutates=False,
        egress=True,
        disclose={'dialect': 'postgres'},
        commit={'sql': 'select 1'},
    ):
        pass
        # end with
    attempt = endpoint.ledger.records()[0].event
    assert attempt['action_context'] == {'dialect': 'postgres'}
    assert isinstance(attempt['action_context_hash'], str)
    assert attempt['action_context_hash'].startswith('sha256:')
    # end def


async def test_body_exception_seals_failed_and_propagates() -> None:
    """A raising body seals a failed outcome and does not suppress the exception."""
    endpoint = _SealingEndpoint()
    session = _session(endpoint)
    with pytest.raises(ValueError):
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            raise ValueError('boom')
            # end with
    assert endpoint.ledger.records()[-1].event['outcome'] == 'failed'
    # end def


async def test_reject_aborts_before_the_body_runs() -> None:
    """A rejected attempt aborts fail-closed: the body never runs and an aborted outcome is emitted."""
    endpoint = _CannedEndpoint(reject('schema-invalid'))
    session = _session(endpoint)
    with pytest.raises(AmcpAbortedError) as excinfo:
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            pytest.fail('body must not run after a rejected attempt')
            # end with
    assert excinfo.value.reason == 'host-rejected'
    assert endpoint.outcomes[-1]['outcome'] == 'aborted'
    assert endpoint.outcomes[-1]['reason'] == 'host-rejected'
    # end def


async def test_unavailable_aborts_fail_closed() -> None:
    """An unavailable host aborts with host-unavailable."""
    endpoint = _CannedEndpoint(unavailable())
    session = _session(endpoint)
    with pytest.raises(AmcpAbortedError) as excinfo:
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            pytest.fail('body must not run when the host is unavailable')
            # end with
    assert excinfo.value.reason == 'host-unavailable'
    # end def


async def test_l2_polluted_stop_passes_and_seals() -> None:
    """Under L2, a faithfully-sealing host clears Polluted Stop and the action completes."""
    endpoint = _SealingEndpoint(level=Level.L2)
    session = _session(endpoint, signer=_StubSigner())
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    records = endpoint.ledger.records()
    assert records[0].event['signature'] == 'stub'
    assert verify_ledger(records, endpoint.ledger.digest()).ok
    # end def


async def test_l2_polluted_stop_detects_a_polluted_seal() -> None:
    """Under L2, a host that returns a record hash over different bytes triggers a hash-mismatch abort."""
    endpoint = _CannedEndpoint(accept(0, 'f' * 64, '2026-07-15T00:00:01.000Z', '0' * 64), level=Level.L2)
    session = _session(endpoint, signer=_StubSigner())
    with pytest.raises(AmcpAbortedError) as excinfo:
        async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
            pytest.fail('body must not run when Polluted Stop fails')
            # end with
    assert excinfo.value.reason == 'hash-mismatch'
    assert endpoint.outcomes[-1]['reason'] == 'hash-mismatch'
    # end def


async def test_l1_skips_polluted_stop_by_default() -> None:
    """Under L1 with no signer, a mismatching record hash is not verified and the action proceeds."""
    endpoint = _CannedEndpoint(accept(0, 'f' * 64, '2026-07-15T00:00:01.000Z', '0' * 64))
    session = _session(endpoint)
    async with session.action('db.read', {'kind': 'table', 'ref': 'customers'}, mutates=False, egress=False):
        pass
        # end with
    assert endpoint.outcomes[-1]['outcome'] == 'success'
    # end def


async def test_decorator_runs_the_body_inside_the_lifecycle() -> None:
    """@auditable_tool wraps the whole function in an audited action using the bound session."""
    endpoint = _SealingEndpoint()
    session = _session(endpoint)

    @auditable_tool(
        action_type='db.read',
        mutates=False,
        egress=False,
        target_resource={'kind': 'table', 'ref': 'customers'},
    )
    async def read_customers(multiplier: int) -> int:
        return multiplier * 2
        # end def

    with bound_session(session):
        result = await read_customers(21)
        # end with
    assert result == 42
    assert [r.event['outcome'] for r in endpoint.ledger.records()] == ['attempted', 'success']
    # end def


async def test_decorator_derives_target_from_call_arguments() -> None:
    """A callable target_resource receives the wrapped call's arguments."""
    endpoint = _SealingEndpoint()
    session = _session(endpoint)

    @auditable_tool(
        action_type='db.read',
        mutates=False,
        egress=False,
        target_resource=lambda table: {'kind': 'table', 'ref': table},
    )
    async def read_table(table: str) -> str:
        return table
        # end def

    with bound_session(session):
        await read_table('orders')
        # end with
    assert endpoint.ledger.records()[0].event['target_resource'] == {'kind': 'table', 'ref': 'orders'}
    # end def


async def test_decorator_without_a_bound_session_raises() -> None:
    """Calling a decorated tool with no bound session is a clear lookup error."""

    @auditable_tool(action_type='db.read', mutates=False, egress=False, target_resource={'kind': 'table', 'ref': 'c'})
    async def tool() -> None:
        pytest.fail('body must not run without a session')
        # end def

    with pytest.raises(LookupError):
        await tool()
        # end with
    # end def


def test_current_session_requires_binding() -> None:
    """current_session raises when nothing is bound."""
    with pytest.raises(LookupError):
        current_session()
        # end with
    # end def


class _FaultyTransport:
    """A transport whose send raises, as a wire transport can (§11.3)."""

    def __init__(self, *, outcome_also_fails: bool = False) -> None:
        """Record what was attempted, and choose whether the outcome channel fails too."""
        self.outcomes: list[dict[str, object]] = []
        self._outcome_also_fails = outcome_also_fails
        # end def

    def negotiate(self, offered: AuditCapability) -> object:
        """Never used by these tests."""
        raise NotImplementedError
        # end def

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Fail the way a broken wire does, with an error this SDK does not define."""
        raise ConnectionResetError('the wire went away')
        # end def

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Record the outcome, or fail again if the test asked for it."""
        if self._outcome_also_fails:
            raise ConnectionResetError('the wire is still gone')
            # end if
        self.outcomes.append(event)
        # end def

    # end class


class TestATransportFault:
    """§6/§11.3: a throw is a failure to record and is handled exactly as `unavailable`."""

    @pytest.mark.asyncio
    async def test_it_aborts_rather_than_escaping_as_the_transport_s_own_error(self) -> None:
        """A caller branching on the audit outcome would never see a ConnectionResetError."""
        transport = _FaultyTransport()
        session = AmcpSession(transport, SESSION, deps=_FixedDeps())
        with pytest.raises(AmcpAbortedError) as aborted:
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pytest.fail('the action ran although nothing recorded it')
                # end async with
            # end with
        assert aborted.value.reason == 'host-unavailable'
        # end def

    @pytest.mark.asyncio
    async def test_it_leaves_an_aborted_record_of_the_action_that_did_not_happen(self) -> None:
        """§11.3 Abort Signaling: the aborted outcome carries the Tier-1 reason (§7.6)."""
        transport = _FaultyTransport()
        session = AmcpSession(transport, SESSION, deps=_FixedDeps())
        with pytest.raises(AmcpAbortedError):
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pass
                # end async with
            # end with
        assert [event['outcome'] for event in transport.outcomes] == ['aborted']
        assert transport.outcomes[0]['reason'] == 'host-unavailable'
        # end def

    @pytest.mark.asyncio
    async def test_a_transport_that_fails_twice_does_not_mask_the_abort(self) -> None:
        """The abort is what the caller must see; the second failure is not its replacement."""
        session = AmcpSession(_FaultyTransport(outcome_also_fails=True), SESSION, deps=_FixedDeps())
        with pytest.raises(AmcpAbortedError):
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pass
                # end async with
            # end with
        # end def

    # end class


class _MisusedTransport(_FaultyTransport):
    """A transport that refuses because the SDK's own contract was broken, not because the wire is."""

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Refuse the way the MCP binding refuses an unnegotiated session (§6.2)."""
        raise AmcpUsageError('this session is not audit-negotiated')
        # end def

    # end class


class TestMisuseIsNotATransportFault:
    """§6.2, §11.3: an integrator error is not an audit outcome and must not be filed as one."""

    @pytest.mark.asyncio
    async def test_it_reaches_the_caller_instead_of_becoming_host_unavailable(self) -> None:
        """Blaming the host for the integrator's wiring buries the one thing they need to see."""
        transport = _MisusedTransport()
        session = AmcpSession(transport, SESSION, deps=_FixedDeps())
        with pytest.raises(AmcpUsageError):
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pytest.fail('the action ran although nothing recorded it')
                # end async with
            # end with
        assert not transport.outcomes, 'an aborted record was filed for a wiring error'
        # end def

    # end class


class _DeadSigner:
    """The tool's own signer is down. The host is fine."""

    key_id = 'k1'

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Fail the way a KMS client does when it cannot reach the service."""
        raise ConnectionError('KMS unreachable')
        # end def

    # end class


class _RefusingHost:
    """A host that rejects every attempt, so the abort path runs."""

    def __init__(self) -> None:
        """Declare an ordinary L1 capability."""
        self.capability = AuditCapability(
            spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE
        )
        self.outcomes = 0
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Refuse."""
        return reject('schema-invalid')
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Fail while recording the abort, which must not replace the abort."""
        self.outcomes += 1
        raise ConnectionError('the wire went away mid-abort')
        # end def

    # end class


class _AcceptsThenDies:
    """Accepts the attempt, then the wire dies before the outcome can be sent."""

    def __init__(self) -> None:
        """Declare an ordinary L1 capability."""
        self.capability = AuditCapability(
            spec_version=SPEC_VERSION, level=Level.L1, attempt='request', countersign=Countersign.NONE
        )
        # end def

    async def handle_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Accept, so the body runs."""
        return accept(0, '0' * 64, '2026-07-15T00:00:01.000Z', '0' * 64)
        # end def

    async def handle_outcome(self, event: dict[str, object]) -> None:
        """Fail, so the terminal emission is the thing that breaks."""
        raise ConnectionError('the wire went away')
        # end def

    # end class


class TestTheTerminalOutcomeNeverReplacesTheBodySError:
    """§6, §10.8: an outcome has no response channel, and the body's error is the caller's."""

    @pytest.mark.asyncio
    async def test_the_body_s_exception_reaches_the_caller(self) -> None:
        """`__aexit__` promises not to suppress it, and a failed emission must not substitute for it."""
        session = AmcpSession(InProcessTransport(_AcceptsThenDies()), SESSION, deps=_FixedDeps())
        with pytest.raises(ValueError, match='the real problem'):
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                raise ValueError('the real problem')
                # end async with
            # end with
        # end def

    @pytest.mark.asyncio
    async def test_a_successful_body_does_not_fail_on_a_lost_outcome(self) -> None:
        """The operation already happened; the gap is the host's to resolve (§10.8), not an error here."""
        session = AmcpSession(InProcessTransport(_AcceptsThenDies()), SESSION, deps=_FixedDeps())
        async with session.action(
            'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
        ):
            pass
            # end async with
        # end def

    # end class


class TestAToolSideFailureIsNotTheHostSFailure:
    """§7.2, §7.6: the Tier-1 abort reasons name the host, and a dead signer is not one of them."""

    @pytest.mark.asyncio
    async def test_a_dead_signer_reaches_the_caller_as_itself(self) -> None:
        """`host-unavailable` would send an operator to a host that is answering perfectly well."""
        host = AuditHost('tenant-a')
        session = AmcpSession(InProcessTransport(host), host.open_session(), signer=_DeadSigner(), deps=_FixedDeps())
        with pytest.raises(ConnectionError):
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pytest.fail('the action ran although nothing recorded it')
                # end async with
            # end with
        assert not host.records(), 'nothing may be sealed when the event could not be built'
        # end def

    @pytest.mark.asyncio
    async def test_a_failure_to_record_the_abort_does_not_replace_the_abort(self) -> None:
        """Every abort path, not only the transport-fault one: the caller must see why it stopped."""
        endpoint = _RefusingHost()
        session = AmcpSession(InProcessTransport(endpoint), SESSION, deps=_FixedDeps())
        with pytest.raises(AmcpAbortedError) as aborted:
            async with session.action(
                'db.read', TargetResource(kind='table', ref='customers'), mutates=False, egress=False
            ):
                pass
                # end async with
            # end with
        assert aborted.value.reason == 'host-rejected'
        assert endpoint.outcomes == 1, 'the abort was never even attempted'
        # end def

    # end class


@pytest.mark.asyncio
async def test_the_decorator_audits_a_synchronous_function() -> None:
    """A tool's operation need not be async; the wrapper awaits only what is awaitable."""
    host = AuditHost('tenant-a')
    session = AmcpSession(InProcessTransport(host), host.open_session(), deps=_FixedDeps())

    @auditable_tool(
        action_type='db.read',
        target_resource={'kind': 'table', 'ref': 'customers'},
        mutates=False,
        egress=False,
    )
    def read_rows() -> int:
        """A synchronous domain operation."""
        return 7
        # end def

    with bound_session(session):
        assert await read_rows() == 7
        # end with
    assert [record.event['outcome'] for record in host.records()] == ['attempted', 'success']
    # end def


@pytest.mark.parametrize(
    'session_id',
    ['tenant-a-call-1', '0198F3A2-5C1E-7000-8000-00000000ABC0', '00000000-0000-0000-0000-000000000000', ''],
)
def test_a_session_id_that_is_not_a_lowercase_uuid_is_refused_at_construction(session_id: str) -> None:
    """The mistake surfaces where it is made, naming the rule, not as a schema error at the first action."""
    host = AuditHost('tenant-a')
    with pytest.raises(AmcpUsageError, match='lowercase, non-nil UUID'):
        AmcpSession(InProcessTransport(host), session_id)
        # end with
    # end def
