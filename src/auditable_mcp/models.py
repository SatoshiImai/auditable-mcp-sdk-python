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
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, model_validator

from auditable_mcp.canonical import MAX_SAFE_INTEGER

# The only spec version defined by this contract; a mismatch is a hard validation error.
SPEC_VERSION: Literal['auditable-mcp/0.2'] = 'auditable-mcp/0.2'

# §7.6 Tier-1 code spaces pinned onto the wire contracts. The tool abort reason (on an aborted
# outcome), the host reject reason, and the unavailable reason are three distinct spaces.
AbortReason = Literal['hash-mismatch', 'host-rejected', 'host-unavailable']
RejectReason = Literal['schema-invalid', 'replay-detected', 'signature-invalid', 'l2-unsigned', 'unknown-key']

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
# Standard base64 with optional padding (§5.1: base64url is forbidden on the wire).
SIGNATURE_PATTERN = r'^[A-Za-z0-9+/]+={0,2}$'


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

    The Level-2 fields (`signer_seq`, `key_id`, `signature`) are optional so a single model serves
    both levels; the signing layer populates them. `reason` is pinned to the Tier-1 abort codes and
    is required exactly when `outcome` is `aborted` (§7.6, §7.2).
    """

    id: str = Field(pattern=UUID_PATTERN)
    # REQUIRED and hashed into the canonical bytes (§4): a defaulted-in version would fork the chain.
    spec_version: Literal['auditable-mcp/0.2']
    ts: str = Field(pattern=DATETIME_PATTERN)
    call_id: str = Field(min_length=1)
    traceparent: str | None = None
    action_type: str = Field(min_length=1)
    mutates: StrictBool
    egress: StrictBool
    target_resource: TargetResource
    # strict=False so an incoming wire string ('attempted') coerces to the enum; effect flags stay strict.
    outcome: Annotated[Outcome, Field(strict=False)]
    reason: AbortReason | None = None
    action_context: dict[str, object] | None = None
    action_context_hash: str | None = Field(default=None, pattern=CONTEXT_HASH_PATTERN)
    signer_seq: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    key_id: str | None = Field(default=None, min_length=1)
    signature: str | None = Field(default=None, pattern=SIGNATURE_PATTERN)

    @model_validator(mode='after')
    def _require_reason_when_aborted(self) -> 'AuditEvent':
        """An aborted outcome MUST carry a Tier-1 abort reason (§7.2)."""
        if self.outcome == Outcome.ABORTED and self.reason is None:
            raise ValueError('an aborted outcome requires a reason')
            # end if
        return self
        # end def

    # end class


# Published spec versions a verifier accepts when reading a sealed ledger. Emission and ingest stay
# pinned to the current SPEC_VERSION (AuditEvent, §6.1); a verifier reading a stored ledger must accept
# records sealed under an earlier published version, since their bytes and hash chain are immutable
# evidence. Keep this tuple in sync with the SealedAuditEvent literal below.
KNOWN_SPEC_VERSIONS = ('auditable-mcp/0.1', 'auditable-mcp/0.1.1', 'auditable-mcp/0.2')


class SealedAuditEvent(AuditEvent):
    """Verification view of a sealed event: read-lenient on `spec_version` (accepts any published version)."""

    # Deliberately widens the parent's pinned literal. This model only validates stored records; it is
    # never substituted where the strict wire AuditEvent is required, so the widening is safe.
    spec_version: Literal['auditable-mcp/0.1', 'auditable-mcp/0.1.1', 'auditable-mcp/0.2']  # type: ignore[assignment]
    # end class


class AuditCapability(WireModel):
    """An audit capability exchanged during negotiation: the version, level, and attempt mode (§6.1)."""

    # All three REQUIRED (§6.1, normative audit-capability.schema.json): a peer that omits any field is
    # rejected, not silently coerced, so version negotiation cannot be bypassed by omission. The host's
    # own partial self-declaration is completed with explicit SDK defaults before validation (host.py).
    spec_version: str = Field(min_length=1)
    level: Annotated[Level, Field(strict=False)]
    attempt: Literal['request']
    # end class


class AuditCapabilityInput(TypedDict, total=False):
    """A partial host self-declaration: unset fields are filled from the SDK's own capability defaults."""

    spec_version: str
    level: Level
    attempt: Literal['request']
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
    """A refused attempt: ledger integrity could not be guaranteed (§7.1). `reason` is a Tier-1 code."""

    status: Literal[Status.REJECT] = Status.REJECT
    reason: RejectReason
    # end class


class UnavailableResponse(WireModel):
    """A transient host-internal failure: fail closed and retry (§7.1). `retryable` is always true."""

    status: Literal[Status.UNAVAILABLE] = Status.UNAVAILABLE
    reason: Literal['internal-error'] = 'internal-error'
    retryable: Literal[True] = True
    # end class


# The host reply to `audit/attempt` — a tagged union discriminated on `status` (§7.1).
AttemptResponse = Annotated[
    AcceptResponse | RejectResponse | UnavailableResponse,
    Field(discriminator='status'),
]


def _first_error(model: type[BaseModel], event: object) -> str | None:
    """Return the first Pydantic validation message for `event` under `model`, or None if valid."""
    try:
        model.model_validate(event)
    except ValidationError as exc:
        error = exc.errors()[0]
        location = '.'.join(str(part) for part in error['loc'])
        return f'{location}: {error["msg"]}' if location else error['msg']
        # end try
    return None
    # end def


def first_validation_error(event: object) -> str | None:
    """Return the first structural validation message for `event` as a wire AuditEvent, or None if valid.

    This is the strict ingest/emission shape check (§7.1): `spec_version` must equal the current
    `SPEC_VERSION`. It enforces the event's structure, types, required fields, and closed shape. The
    ledger verifier uses `first_sealed_validation_error` instead, which accepts any published version.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first error as ``<location>: <message>``.
    """
    return _first_error(AuditEvent, event)
    # end def


def first_sealed_validation_error(event: object) -> str | None:
    """Like `first_validation_error`, but read-lenient on `spec_version` (ledger verification).

    A sealed record is immutable evidence, so a verifier reading a stored ledger accepts records sealed
    under any published `spec_version` (`KNOWN_SPEC_VERSIONS`) - the record's bytes and hash chain do
    not change with the reader's version. Ingest and emission stay pinned to the current version.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first error as ``<location>: <message>``.
    """
    return _first_error(SealedAuditEvent, event)
    # end def
