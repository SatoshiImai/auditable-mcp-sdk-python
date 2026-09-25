"""The tool-side audit-before-act session — the async context-manager core.

`AuditedAction` is the source of truth for the tool lifecycle, enforced at the language level:

- `__aenter__` emits the attempt, awaits the host response, and (under Level 2) performs the
  Polluted Stop check (§7.2). If the host does not `accept`, or the recomputed record hash does not
  match, it emits an `aborted` outcome and raises `AmcpAbortedError` — so the `async with` body (the
  domain action) never runs. This is the audit-before-act guarantee (§11.3).
- `__aexit__` emits the terminal outcome: `success` if the body completed, `failed` if it raised.
  It never suppresses the body's exception.

`AmcpSession` is one audit session - one `tools/call` (§6.3). It binds a transport, the session's id,
id/time sources, and an optional Level-2 signer, and numbers the events it signs from 0 (§7.4). Level 1
and Level 2 emission are identical; Level 2 only adds the signer.

The numbering belongs to the audit session, not to the `AmcpSession` object. Under §6.4 one call can
reach the tool as several requests carrying one `session_id`, each served by a handler invocation of its
own; a transport that knows this exposes the session's `SessionNumbering` as `numbering`, and every
`AmcpSession` built over it continues the one sequence instead of restarting it at 0.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Protocol
from uuid import uuid4

import anyio

from auditable_mcp import reasons
from auditable_mcp.canonical import hash_canonical
from auditable_mcp.clock import Clock, now_iso
from auditable_mcp.hashing import compute_record_hash, countersignature_payload
from auditable_mcp.models import (
    SESSION_ID_PATTERN,
    SPEC_VERSION,
    AbortReason,
    AcceptResponse,
    AuditEvent,
    Outcome,
    RejectResponse,
    TargetResource,
)
from auditable_mcp.transport import AmcpUsageError, AuditTransport


class EventSigner(Protocol):
    """Stamps an event with `key_id`, `signer_seq`, and `signature` (Level 2, §5, §8.2).

    `sign` is async because a production signer typically calls a network HSM/KMS; a local signer
    just returns synchronously under the async signature.
    """

    @property
    def key_id(self) -> str:
        """The `key_id` this signer stamps, which names the sequence it advances in a session (§7.4)."""
        ...

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Return the event stamped with `key_id`, `signer_seq` and its signature."""
        ...

    # end class


class CountersignatureVerifier(Protocol):
    """Verifies a host's countersignature over the accept's host-assigned fields and `log_id` (§5.2, §7.1).

    The payload is supplied already canonical, so a verifier resolves the key and does cryptography
    only. A `host_key_id` with no current registry entry - never registered, or revoked - returns
    False: the countersignature is not established either way (§10.9).
    """

    async def verify(self, host_key_id: str, signature: str, payload: bytes) -> bool:
        """Return True if the signature verifies against the registered host key."""
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


_logger = logging.getLogger(__name__)


def new_session_id() -> str:
    """Mint an audit session id, for a tool acting as its own host in the degraded posture (§6.2, §6.3)."""
    return str(uuid4())
    # end def


class SessionNumbering:
    """The `signer_seq` state of one audit session: the next value, and the section that assigns it (§7.4).

    Numbering and emission are one section, so two concurrent operations of one session leave in the
    order they were numbered. Every `AmcpSession` serving the same audit session must share one instance.
    """

    def __init__(self) -> None:
        """Start the session's sequence at 0."""
        self.lock = anyio.Lock()
        self.next_signer_seq = 0
        # end def

    # end class


@asynccontextmanager
async def _numbering(session: AmcpSession) -> AsyncIterator[int | None]:
    """Hold this session's numbering across the emission inside, and advance it only if that emitted.

    Level 1 numbers nothing, so it takes no section: serializing it would cost concurrency the
    specification does not ask for.

    An emission that raised never reached the host, so the number it was given is still unused -
    advancing anyway would leave a gap the host reads as a suppressed event (§7.4).
    """
    if session._signer is None:
        yield None
        return
        # end if
    numbering = session._numbering
    async with numbering.lock:
        signer_seq = numbering.next_signer_seq
        yield signer_seq
        numbering.next_signer_seq = signer_seq + 1
        # end async with
    # end def


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
    """One audit session: wraps a call's internal operations in audit-before-act (± a Level-2 signer)."""

    def __init__(
        self,
        transport: AuditTransport,
        session_id: str,
        *,
        signer: EventSigner | None = None,
        deps: Deps | None = None,
        polluted_stop: bool | None = None,
        countersignature_verifier: CountersignatureVerifier | None = None,
        require_countersign: bool = False,
    ) -> None:
        """Bind the session to a transport, its audit session id, id/time deps, and the optional seams.

        `session_id` is the one the host issued for this call (§6.3) - or, for a tool acting as its own
        host in the degraded posture, the one it minted with `new_session_id`. Every event carries it.

        Polluted Stop runs whenever a signer is present (Level 2 MUST, §11.3) or a countersignature is
        required (§7.2: the countersignature binds only `record_hash`, and Polluted Stop is what binds
        `record_hash` to this tool's own event); otherwise it is optional and off by default. Pass
        `polluted_stop=True` to opt an L1 tool into the check.

        A `countersignature_verifier` makes the tool check any countersignature an accept carries, whether or
        not it requires one - having checked, it must act on the result (§7.2). `require_countersign`
        additionally aborts an accept that carries none.

        The session numbers the events it signs from 0 (§7.4). When `transport` has a `numbering`
        attribute holding a `SessionNumbering`, the session continues that sequence - the one the
        transport keeps for every request of the call; otherwise it starts its own. Nothing is shared
        with another audit session, so one key serves any number of concurrent calls, processes, and
        hosts without their coordinating.

        Raises:
            AmcpUsageError: If `session_id` is not a lowercase, non-nil UUID (§4, §6.3).
            ValueError: If `require_countersign` is set without a `countersignature_verifier`, or
                Polluted Stop is switched off where it is required.
        """
        if not isinstance(session_id, str) or re.fullmatch(SESSION_ID_PATTERN, session_id) is None:
            raise AmcpUsageError(
                f'session_id {session_id!r} is not a session id: it must be a lowercase, non-nil UUID '
                '(§4, §6.3), such as one `new_session_id()` mints'
            )
            # end if
        # Requiring a countersign without the means to check one would accept any bytes as a signature,
        # which is worse than not requiring it at all (§11.3 Countersign Enforcement).
        if require_countersign and countersignature_verifier is None:
            raise ValueError('require_countersign needs a CountersignatureVerifier')
            # end if
        # §11.3 makes Polluted Stop REQUIRED under Level 2 and OPTIONAL under Level 1. A signer is this
        # SDK's Level-2 marker, so switching the check off while signing is a configuration the
        # specification does not allow, and the default already does the right thing.
        if polluted_stop is False and signer is not None:
            raise ValueError('Polluted Stop is REQUIRED under Level 2 (§7.2, §11.3)')
            # end if
        if polluted_stop is False and require_countersign:
            raise ValueError('Polluted Stop is REQUIRED wherever a countersignature is required (§7.2, §11.3)')
            # end if
        self._transport = transport
        self._session_id = session_id
        self._signer = signer
        shared = getattr(transport, 'numbering', None)
        self._numbering = shared if isinstance(shared, SessionNumbering) else SessionNumbering()
        self._deps = deps if deps is not None else SystemDeps()
        required = signer is not None or require_countersign
        self._polluted_stop = required if polluted_stop is None else polluted_stop
        self._countersignature_verifier = countersignature_verifier
        self._require_countersign = require_countersign
        # end def

    @property
    def session_id(self) -> str:
        """The audit session every event of this call carries (§6.3)."""
        return self._session_id
        # end def

    async def _stamp(self, event: dict[str, object], signer_seq: int | None) -> dict[str, object]:
        """Sign the event under Level 2 with the number the section holds, or return it unchanged."""
        if self._signer is not None and signer_seq is not None:
            return await self._signer.sign(event, signer_seq)
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

        The effect axis (`mutates`, `egress`) is declared explicitly per operation (§4.2). Confidentiality
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

    async def _build(
        self, outcome: Outcome, signer_seq: int | None, reason: AbortReason | None = None
    ) -> dict[str, object]:
        """Build and stamp the wire event for `outcome`, reusing the shared correlation id."""
        event = AuditEvent(
            id=self._id,
            spec_version=SPEC_VERSION,
            ts=self._session._deps.now(),
            session_id=self._session._session_id,
            action_type=self._action_type,
            mutates=self._mutates,
            egress=self._egress,
            target_resource=self._target,
            outcome=outcome,
            reason=reason,
            action_context=self._disclose,
            action_context_hash=self._commit_hash,
        )
        return await self._session._stamp(event.to_wire(), signer_seq)
        # end def

    async def _emit_aborted(self, reason: AbortReason) -> None:
        """Emit an aborted outcome recording why the domain action was not performed (§7.2)."""
        async with _numbering(self._session) as signer_seq:
            await self._session._transport.send_outcome(await self._build(Outcome.ABORTED, signer_seq, reason))
            # end async with
        # end def

    async def _emit_aborted_best_effort(self, reason: AbortReason) -> None:
        """Emit the aborted outcome without letting a failure to emit it mask the abort itself (§7.2).

        Every abort path goes through here. Building the outcome signs it under Level 2, so a dead
        signer or a dead transport can fail the emission - and the abort is what the caller must act
        on, not the second failure that happened while recording it.
        """
        try:
            await self._emit_aborted(reason)
        except Exception:
            # The transport that just failed may fail again; the abort is what the caller must see.
            _logger.error('could not emit the aborted outcome after a transport fault (reason=%s)', reason)
            # end try
        # end def

    async def __aenter__(self) -> AuditedAction:
        """Emit the attempt, await accept, run Polluted Stop; abort (and raise) unless cleared."""
        fault: Exception | None = None
        # §7.4: the numbering and the emission are one section, so two concurrent actions of one call
        # cannot leave in the order their signing happened to finish in. The section spans the host's
        # answer, not just the send, because a transport resolves `send_attempt` only when the answer
        # arrives and gives no earlier point at which the frame is known to be on its way. It
        # serializes the attempts of one call under Level 2; calls share nothing, so it costs nothing
        # across them.
        async with _numbering(self._session) as signer_seq:
            # Building signs the event under Level 2, and a signer that fails is the tool's own
            # failure, not the host's. It stays outside the conversion below so it reaches the caller
            # as itself rather than as `host-unavailable`, which would send an operator to the host.
            attempt = await self._build(Outcome.ATTEMPTED, signer_seq)
            try:
                response = await self._session._transport.send_attempt(attempt)
            except AmcpUsageError:
                # Not a failure to record: the SDK was used against its own contract, and no audit
                # outcome describes that. Filing `host-unavailable` for it would blame the host for
                # the integrator's error and bury the one thing they need to see (§6.2).
                raise
            except Exception as error:
                # §6/§11.3: a transport fault (as against an `unavailable` result) is a failure to
                # record and is handled exactly as `unavailable` - fail closed. The catch is broad on
                # purpose: the transport is injected and its error types are not this SDK's to know.
                # The abort is emitted outside this section, which the emission needs for itself.
                fault = error
                # end try
            # end async with
        if fault is not None:
            await self._emit_aborted_best_effort(reasons.HOST_UNAVAILABLE)
            raise AmcpAbortedError(self._action_type, self._target.ref, reasons.HOST_UNAVAILABLE) from fault
            # end if

        if not isinstance(response, AcceptResponse):
            # reject (invalid) or unavailable (not persisted): do not act; signal aborted (§11.3).
            reason: AbortReason = (
                reasons.HOST_REJECTED if isinstance(response, RejectResponse) else reasons.HOST_UNAVAILABLE
            )
            await self._emit_aborted_best_effort(reason)
            raise AmcpAbortedError(self._action_type, self._target.ref, reason)
            # end if

        # §7.2 evaluates in precedence order: the response's status above, then the countersignature
        # that authenticates the host-assigned fields, then the hash computed over them. The reason is
        # sealed into the ledger and compared across implementations, so the order is not incidental.
        if self._session._require_countersign and response.host_signature is None:
            await self._emit_aborted_best_effort(reasons.HOST_UNCOUNTERSIGNED)
            raise AmcpAbortedError(self._action_type, self._target.ref, reasons.HOST_UNCOUNTERSIGNED)
            # end if
        if response.host_signature is not None and self._session._countersignature_verifier is not None:
            # The model admits the triple only together (§7.1), so a missing member here is a partial
            # countersignature that could not be checked, which is what `host-signature-invalid` names.
            verified = False
            if response.host_key_id is not None and response.log_id is not None:
                payload = countersignature_payload(
                    response.seq, response.host_ts, response.log_id, response.previous_hash, response.record_hash
                )
                verified = await self._session._countersignature_verifier.verify(
                    response.host_key_id, response.host_signature, payload
                )
                # end if
            if not verified:
                await self._emit_aborted_best_effort(reasons.HOST_SIGNATURE_INVALID)
                raise AmcpAbortedError(self._action_type, self._target.ref, reasons.HOST_SIGNATURE_INVALID)
                # end if
            # end if

        # Polluted Stop (§7.2): recompute the record hash over the exact attempt bytes; a mismatch
        # means the host sealed a different record, so the tool must not act.
        if self._session._polluted_stop:
            expected = compute_record_hash(attempt, response.seq, response.host_ts, response.previous_hash)
            if expected != response.record_hash:
                await self._emit_aborted_best_effort(reasons.HASH_MISMATCH)
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
    ) -> None:
        """Emit success (body completed) or failed (body raised); never suppress the exception."""
        outcome = Outcome.FAILED if exc_type is not None else Outcome.SUCCESS
        try:
            async with _numbering(self._session) as signer_seq:
                await self._session._transport.send_outcome(await self._build(outcome, signer_seq))
                # end async with
        except Exception:
            # §6: an outcome has no response, so there is nothing to retry and nothing to tell the
            # host; losing it leaves an attempt the host records unresolved when the call ends
            # (§10.8). Raising here would replace the body's exception - the one the caller must act
            # on - with the audit layer's, which is what this method promises
            # not to do. The operation already happened either way.
            _logger.error('could not emit the %s outcome; the operation is left unresolved (§10.8)', outcome)
            # end try
        # end def

    # end class
