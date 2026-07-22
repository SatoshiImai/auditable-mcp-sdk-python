"""Typed wire contracts for Auditable MCP (the Pydantic source of ergonomics).

These models mirror the language-neutral JSON Schema under `spec/schema/`, which remains the
normative contract (generated upstream from the TypeScript Zod source of truth). Pydantic gives
tool authors IDE completion and strict runtime shape validation; `to_wire()` emits the exact
JSON — absent optionals omitted — that canonicalization and hashing consume (§8).

Three contracts live here: the audit event (§4), the capability object (§6.1), and the attempt
response tagged union (§7.1). The §8.2 record-hash preimage is deliberately *not* modeled — it is
a local hash input, never a wire object (see `hashing.py`).
"""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError

from auditable_mcp.canonical import MAX_SAFE_INTEGER

# The only spec version defined by this contract; a mismatch is a hard validation error.
SPEC_VERSION: Literal['auditable-mcp/0.1'] = 'auditable-mcp/0.1'

# Patterns copied verbatim from the normative JSON Schema (spec/schema/), applied to `str` fields so
# validation matches the contract exactly without transforming the value — the bytes must survive
# untouched for canonicalization and hashing (§8). Rich types (UUID/datetime) would re-serialize and
# change those bytes, and accept a different (looser) set than the schema; `tests/conformance` guards
# these copies against schema drift.
UUID_PATTERN = (
    r'^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}'
    r'|00000000-0000-0000-0000-000000000000)$'
)
DATETIME_PATTERN = (
    r'^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29'
    r'|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)'
    r'|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z))$'
)
CHAIN_HASH_PATTERN = r'^[0-9a-f]{64}$'
CONTEXT_HASH_PATTERN = r'^sha256:[0-9a-f]{64}$'


class Outcome(StrEnum):
    """The lifecycle state an event records (§7.2)."""

    ATTEMPTED = 'attempted'
    SUCCESS = 'success'
    FAILED = 'failed'
    ABORTED = 'aborted'
    # end class


class Level(StrEnum):
    """The negotiated assurance level (§5, §6.1)."""

    L1 = 'L1'
    L2 = 'L2'
    # end class


class Status(StrEnum):
    """The attempt-response discriminator (§7.1)."""

    ACCEPT = 'accept'
    REJECT = 'reject'
    UNAVAILABLE = 'unavailable'
    # end class


class WireModel(BaseModel):
    """Base for every wire contract: strict, closed, and immutable.

    `strict` forbids silent coercion (a protocol machine must not accept `1` for a boolean),
    `extra='forbid'` mirrors the schema's `additionalProperties: false`, and `frozen` makes the
    models hashable value objects — the signing layer derives new instances via `model_copy`.
    """

    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)

    def to_wire(self) -> dict[str, object]:
        """Return the JSON-compatible dict with absent optionals omitted (the exact wire bytes)."""
        return self.model_dump(mode='json', exclude_none=True)
        # end def

    # end class


class TargetResource(WireModel):
    """The domain target of an operation (§4)."""

    kind: str = Field(min_length=1)
    ref: str = Field(min_length=1)
    scope_hint: str | None = None
    # end class


class AuditEvent(WireModel):
    """One audit record describing one internal operation (§4).

    The Level-2 fields (`sequence`, `key_id`, `signature`) are optional so a single model serves
    both levels; the signing layer populates them. Structural conformance to the full pattern
    constraints (uuid/date-time regexes) is enforced by the shared JSON Schema at the host boundary.
    """

    id: str = Field(pattern=UUID_PATTERN)
    spec_version: Literal['auditable-mcp/0.1'] = SPEC_VERSION
    ts: str = Field(pattern=DATETIME_PATTERN)
    call_id: str = Field(min_length=1)
    traceparent: str | None = None
    action_type: str = Field(min_length=1)
    mutates: StrictBool
    egress: StrictBool
    target_resource: TargetResource
    # strict=False so an incoming wire string ('attempted') coerces to the enum; effect flags stay strict.
    outcome: Annotated[Outcome, Field(strict=False)]
    reason: str | None = None
    action_context: dict[str, object] | None = None
    action_context_hash: str | None = Field(default=None, pattern=CONTEXT_HASH_PATTERN)
    sequence: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    key_id: str | None = None
    signature: str | None = None
    # end class


class AuditCapability(WireModel):
    """An audit capability: a requirement when host-declared, a supported level when tool-declared (§6.1)."""

    level: Annotated[Level, Field(strict=False)] = Level.L1
    attempt: Literal['request'] = 'request'
    # end class


class AcceptResponse(WireModel):
    """A sealed attempt: carries the host-assigned fields the tool needs for Polluted Stop (§7.1, §7.2)."""

    status: Literal[Status.ACCEPT] = Status.ACCEPT
    seq: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    record_hash: str = Field(pattern=CHAIN_HASH_PATTERN)
    host_ts: str = Field(pattern=DATETIME_PATTERN)
    previous_hash: str = Field(pattern=CHAIN_HASH_PATTERN)
    # end class


class RejectResponse(WireModel):
    """A refused attempt: ledger integrity could not be guaranteed (§7.1)."""

    status: Literal[Status.REJECT] = Status.REJECT
    reason: str
    # end class


class UnavailableResponse(WireModel):
    """A transient persistence failure: fail closed and retry (§7.1). `retryable` is always true."""

    status: Literal[Status.UNAVAILABLE] = Status.UNAVAILABLE
    reason: str
    retryable: Literal[True] = True
    # end class


# The host reply to `audit/attempt` — a tagged union discriminated on `status` (§7.1).
AttemptResponse = Annotated[
    AcceptResponse | RejectResponse | UnavailableResponse,
    Field(discriminator='status'),
]


def first_validation_error(event: object) -> str | None:
    """Return the first structural validation message for `event` as an AuditEvent, or None if valid.

    This is the shared shape check used at the host ingest boundary (§7.1) and by the ledger verifier.
    It enforces the event's structure, types, required fields, and closed shape. Pattern-level
    conformance (uuid / date-time / hex regexes) is defined by the normative JSON Schema under
    `spec/schema/` and covered by the conformance vectors; tightening ingest to enforce those patterns
    directly is a planned hardening.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first error as ``<location>: <message>``.
    """
    try:
        AuditEvent.model_validate(event)
    except ValidationError as exc:
        error = exc.errors()[0]
        location = '.'.join(str(part) for part in error['loc'])
        return f'{location}: {error["msg"]}' if location else error['msg']
        # end try
    return None
    # end def
