"""§7.4: one key shared across hosts and calls leaves a complete sequence in every session.

The deployment this covers: a stdio tool with one key, two agents each with its own host, connections
alternating. `signer_seq` counts within an audit session (§6.3), and a session is one call recorded by
one host, so neither host sees a hole and neither has to be told the key is shared.
"""

from auditable_mcp import AmcpSession, verify_ledger
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2 import Ed25519Signer, KeyRegistry, KeyRegistryVerifier, generate_tool_key
from auditable_mcp.models import SPEC_VERSION, AuditCapability, Countersign, Level, TargetResource

_L2 = AuditCapability(spec_version=SPEC_VERSION, level=Level.L2, attempt='request', countersign=Countersign.NONE)


async def _two_hosts_one_key() -> tuple[AuditHost, AuditHost]:
    """Alternate six calls between two hosts that share one tool key."""
    key = generate_tool_key('janus:menu:ed25519:2026-09-25')
    registry = KeyRegistry()
    registry.register_tool_key(key)
    hosts = [AuditHost(f'agent-{n}', _L2, verifier=KeyRegistryVerifier(registry)) for n in ('x', 'y')]
    for n in range(6):
        host = hosts[n % 2]
        async with host.session() as session_id:
            session = AmcpSession(InProcessTransport(host), session_id, signer=Ed25519Signer.from_tool_key(key))
            async with session.action('db.read', TargetResource(kind='table', ref='t'), mutates=False, egress=False):
                pass
                # end async with
            # end async with
        # end for
    return hosts[0], hosts[1]
    # end def


async def test_every_session_numbers_from_zero() -> None:
    """Each call's attempt and outcome are 0 and 1, whichever host recorded it."""
    host_x, host_y = await _two_hosts_one_key()
    for host in (host_x, host_y):
        assert [record.event['signer_seq'] for record in host.records()] == [0, 1] * 3
        # end for
    # end def


async def test_neither_host_records_an_anomaly() -> None:
    """No gap, no replay, nothing unresolved: the key is shared and nothing is missing."""
    host_x, host_y = await _two_hosts_one_key()
    assert host_x.anomalies() == []
    assert host_y.anomalies() == []
    # end def


async def test_both_ledgers_verify_without_being_told_the_key_is_shared() -> None:
    """A verifier reads each session's sequence on its own (§11.4)."""
    host_x, host_y = await _two_hosts_one_key()
    for host in (host_x, host_y):
        report = verify_ledger(host.records())
        assert report.ok, report.issues
        # end for
    # end def
