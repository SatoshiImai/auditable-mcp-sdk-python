"""The tool-side audit-before-act session — the async context-manager core.

`AuditedAction` is the source of truth for the tool lifecycle, enforced at the language level:

- `__aenter__` emits `audit/attempt`, awaits the host response, and (under Level 2) performs the
  Polluted Stop check (§7.2). If the host does not `accept`, or the recomputed record hash does not
  match, it emits an `aborted` outcome and raises `AmcpAbortedError` — so the `async with` body (the
  domain action) never runs. This is the audit-before-act guarantee (§11.3).
- `__aexit__` emits the terminal outcome: `success` if the body completed, `failed` if it raised.
  It never suppresses the body's exception.

`AmcpSession` binds a transport, a parent `call_id`, id/time sources, and an optional Level-2 signer.
Level 1 and Level 2 emission are identical; Level 2 only adds the signer.
"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol
from uuid import uuid4

from auditable_mcp import reasons
from auditable_mcp.canonical import hash_canonical
from auditable_mcp.clock import Clock, now_iso
from auditable_mcp.hashing import compute_record_hash
from auditable_mcp.models import (
    SPEC_VERSION,
    AbortReason,
    AcceptResponse,
    AuditEvent,
    Outcome,
    RejectResponse,
    TargetResource,
)
from auditable_mcp.transport import AuditTransport


class EventSigner(Protocol):
    """Stamps an event with `key_id`, `signer_seq`, and `signature` (Level 2, §5, §8.2).

    `sign` is async because a production signer typically calls a network HSM/KMS; a local signer
    just returns synchronously under the async signature.
    """

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Return the signed event."""
        ...

    # end class


class Deps(Clock, Protocol):
    """A `Clock` that also mints event ids (the session's tool-side id/time source)."""

    def new_id(self) -> str:
        """Return a fresh UUID-shaped event id."""
        ...

    # end class


class SystemDeps:
    """Production id/time source: `uuid4` and the system clock."""

    def new_id(self) -> str:
        """Return a random UUIDv4 string."""
        return str(uuid4())
        # end def

    def now(self) -> str:
        """Return the current system time (via `now_iso`)."""
        return now_iso()
        # end def

    # end class


class AmcpAbortedError(Exception):
    """The tool's own fail-closed halt: the domain action was not performed (outcome=aborted).

    Named for the tool's abort, not host "blocking" — the host never prevents a domain action (§2).
    A tool surfaces this as a `tools/call` error result.
    """

    def __init__(self, action_type: str, target_ref: str, reason: str) -> None:
        """Capture the aborted action for the caller."""
        super().__init__(f'auditable-mcp aborted {action_type} on {target_ref}: {reason}')
        self.action_type = action_type
        self.target_ref = target_ref
        self.reason = reason
        # end def

    # end class


class AmcpSession:
    """Wraps internal operations in the audit-before-act lifecycle (± a Level-2 signer)."""

    def __init__(
        self,
        transport: AuditTransport,
        call_id: str,
        *,
        signer: EventSigner | None = None,
        deps: Deps | None = None,
        polluted_stop: bool | None = None,
    ) -> None:
        """Bind the session to a transport, parent call id, id/time deps, and optional L2 signer.

        Polluted Stop runs whenever a signer is present (Level 2 MUST, §11.3); under Level 1 it is
        optional and off by default. Pass `polluted_stop=True` to opt an L1 tool into the check.
        """
        self._transport = transport
        self._call_id = call_id
        self._signer = signer
        self._deps = deps if deps is not None else SystemDeps()
        self._polluted_stop = signer is not None if polluted_stop is None else polluted_stop
        # end def

    async def _stamp(self, event: dict[str, object]) -> dict[str, object]:
        """Sign the event under Level 2, or return it unchanged under Level 1."""
        if self._signer is not None:
            return await self._signer.sign(event)
            # end if
        return event
        # end def

    def action(
        self,
        action_type: str,
        target_resource: TargetResource | dict[str, object],
        *,
        mutates: bool,
        egress: bool,
        disclose: dict[str, object] | None = None,
        commit: object | None = None,
    ) -> AuditedAction:
        """Create an audited action to use as `async with`.

        The effect axis (`mutates`, `egress`) is declared explicitly per operation. Confidentiality
        is the tool's choice (§4.3): `disclose` records cleartext context, `commit` records a hash of
        the exact input; either, both, or neither may be given.
        """
        target = (
            target_resource
            if isinstance(target_resource, TargetResource)
            else TargetResource.model_validate(target_resource)
        )
        return AuditedAction(
            self,
            self._deps.new_id(),
            action_type,
            target,
            mutates=mutates,
            egress=egress,
            disclose=disclose,
            commit=commit,
        )
        # end def

    # end class


class AuditedAction:
    """One audited operation as an async context manager (see the module docstring)."""

    def __init__(
        self,
        session: AmcpSession,
        event_id: str,
        action_type: str,
        target: TargetResource,
        *,
        mutates: bool,
        egress: bool,
        disclose: dict[str, object] | None,
        commit: object | None,
    ) -> None:
        """Bind the action's immutable descriptors; the correlation id is shared by attempt and outcome."""
        self._session = session
        self._id = event_id
        self._action_type = action_type
        self._target = target
        self._mutates = mutates
        self._egress = egress
        self._disclose = disclose
        self._commit_hash = hash_canonical(commit) if commit is not None else None
        # Populated on a successful __aenter__; None while unaccepted.
        self.accept: AcceptResponse | None = None
        # end def

    async def _build(self, outcome: Outcome, reason: AbortReason | None = None) -> dict[str, object]:
        """Build and stamp the wire event for `outcome`, reusing the shared correlation id."""
        event = AuditEvent(
            id=self._id,
            spec_version=SPEC_VERSION,
            ts=self._session._deps.now(),
            call_id=self._session._call_id,
            action_type=self._action_type,
            mutates=self._mutates,
            egress=self._egress,
            target_resource=self._target,
            outcome=outcome,
            reason=reason,
            action_context=self._disclose,
            action_context_hash=self._commit_hash,
        )
        return await self._session._stamp(event.to_wire())
        # end def

    async def _emit_aborted(self, reason: AbortReason) -> None:
        """Emit an aborted outcome recording why the domain action was not performed (§7.2)."""
        await self._session._transport.send_outcome(await self._build(Outcome.ABORTED, reason))
        # end def

    async def __aenter__(self) -> AuditedAction:
        """Emit the attempt, await accept, run Polluted Stop; abort (and raise) unless cleared."""
        attempt = await self._build(Outcome.ATTEMPTED)
        response = await self._session._transport.send_attempt(attempt)

        if not isinstance(response, AcceptResponse):
            # reject (invalid) or unavailable (not persisted): do not act; signal aborted (§11.3).
            reason: AbortReason = (
                reasons.HOST_REJECTED if isinstance(response, RejectResponse) else reasons.HOST_UNAVAILABLE
            )
            await self._emit_aborted(reason)
            raise AmcpAbortedError(self._action_type, self._target.ref, reason)
            # end if

        # Polluted Stop (§7.2): recompute the record hash over the exact attempt bytes; a mismatch
        # means the host sealed a different record, so the tool must not act.
        if self._session._polluted_stop:
            expected = compute_record_hash(attempt, response.seq, response.host_ts, response.previous_hash)
            if expected != response.record_hash:
                await self._emit_aborted(reasons.HASH_MISMATCH)
                raise AmcpAbortedError(self._action_type, self._target.ref, reasons.HASH_MISMATCH)
                # end if
            # end if

        self.accept = response
        return self
        # end def

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        """Emit success (body completed) or failed (body raised); never suppress the exception."""
        outcome = Outcome.FAILED if exc_type is not None else Outcome.SUCCESS
        await self._session._transport.send_outcome(await self._build(outcome))
        return False
        # end def

    # end class
