"""Timestamp source for the spec's `ts` (tool-observed) and `host_ts` (authoritative) times.

`now_iso` is the single formatter for both (ISO-8601 to milliseconds, `Z` suffix). `Clock` is the
injection protocol used by the host; the session's `Deps` (session.py) extends it with id minting so
time is deterministic in tests.
"""

from datetime import UTC, datetime
from typing import Protocol


def now_iso() -> str:
    """Return the current UTC time as `YYYY-MM-DDThh:mm:ss.sssZ`."""
    return datetime.now(UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    # end def


class Clock(Protocol):
    """A source of ISO-8601 timestamps, injected so time can be made deterministic."""

    def now(self) -> str:
        """Return the current time as an ISO-8601 string."""
        ...

    # end class


class SystemClock:
    """A `Clock` backed by the system wall clock."""

    def now(self) -> str:
        """Return the current system time (via `now_iso`)."""
        return now_iso()
        # end def

    # end class
