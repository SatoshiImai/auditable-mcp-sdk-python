"""Conformance: every event in error-cases.json must be rejected (attempt channel) or dropped and
flagged (outcome channel) with the pinned Tier-1 reason / anomaly kind (§7.6)."""

from typing import Any

from auditable_mcp.host import AuditHost
from auditable_mcp.models import RejectResponse

_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


class _Clock:
    """A monotonic host clock producing valid timestamps."""

    def __init__(self) -> None:
        """Start at zero."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-07-15T00:00:{self._n:02d}.000Z'
        # end def


async def test_error_cases_reject_or_flag_with_tier1_codes(error_cases: list[dict[str, Any]]) -> None:
    """A host rejects or flags each golden error case with its Tier-1 code."""
    for case in error_cases:
        # The call these events arrive on is the vectors' session, so a session refusal is the event's own.
        host = AuditHost('tenant-a', clock=_Clock())
        host.open_session(_SESSION)
        expected = case['expect']

        if case['channel'] == 'attempt':
            response = await host.handle_attempt(case['event'], session_id=_SESSION)
            assert response.status == expected['status'], case['name']
            if isinstance(response, RejectResponse):
                assert response.reason == expected['reason'], case['name']
                # end if
        else:
            await host.handle_outcome(case['event'], session_id=_SESSION)
            assert host.records() == [], case['name']
            if 'anomaly_kind' in expected:
                assert any(a.kind == expected['anomaly_kind'] for a in host.anomalies()), case['name']
                # end if
            # end if
        # end for
    # end def
