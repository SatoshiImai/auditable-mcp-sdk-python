"""A thin decorator over the audit-before-act core (syntax sugar, no lifecycle logic).

`@auditable_tool(...)` wraps a tool function so its whole body runs inside `async with
session.action(...)`. All of the protocol logic lives in `AuditedAction` (session.py); this module
only resolves the session and target, then delegates. Power users that need per-call `disclose` /
`commit` context should call `session.action(...)` directly.

The session is resolved from a task-local `ContextVar` so the decorated function stays unaware of
wiring; bind it with `with bound_session(session):` around the call.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from auditable_mcp.models import TargetResource
from auditable_mcp.session import AmcpSession

_current_session: ContextVar[AmcpSession | None] = ContextVar('amcp_current_session', default=None)

# A target resource that is fixed, or derived from the call's own arguments.
TargetResourceSpec = TargetResource | dict[str, object] | Callable[..., TargetResource | dict[str, object]]


@contextmanager
def bound_session(session: AmcpSession) -> Generator[AmcpSession, None, None]:
    """Bind `session` for the duration of the block so decorated tools can find it."""
    token = _current_session.set(session)
    try:
        yield session
    finally:
        _current_session.reset(token)
        # end try
    # end def


def current_session() -> AmcpSession:
    """Return the task-local bound session, or raise if none is bound."""
    session = _current_session.get()
    if session is None:
        raise LookupError('no AmcpSession is bound; wrap the call in `with bound_session(session):`')
        # end if
    return session
    # end def


def auditable_tool(
    *,
    action_type: str,
    mutates: bool,
    egress: bool,
    target_resource: TargetResourceSpec,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a tool function in the audit-before-act lifecycle for `action_type`.

    Args:
        action_type: The operation's opaque action type (§4.1).
        mutates: Whether the operation changes state (§4.2).
        egress: Whether the operation crosses the trust boundary (§4.2).
        target_resource: The domain target — a fixed value, or a callable receiving the wrapped
            function's own arguments and returning one.

    Returns:
        A decorator that runs the function inside `async with session.action(...)`.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            session = current_session()
            resolved = target_resource(*args, **kwargs) if callable(target_resource) else target_resource
            async with session.action(action_type, resolved, mutates=mutates, egress=egress):
                result = func(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
                    # end if
                return result
                # end with
            # end def

        return wrapper
        # end def

    return decorator
    # end def
