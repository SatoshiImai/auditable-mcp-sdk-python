"""Typed wire contracts for Auditable MCP (the Pydantic source of ergonomics).

These models mirror the language-neutral JSON Schema under `spec/schema/`, which remains the
normative contract (generated upstream from the TypeScript Zod source of truth). Pydantic gives
tool authors IDE completion and strict runtime shape validation; `to_wire()` emits the exact
JSON — absent optionals omitted — that canonicalization and hashing consume (§8).

The contracts here are the audit event (§4), the capability object (§6.1), the attempt response
tagged union (§7.1), and the two `_meta` objects the 2026-07-28 binding carries (§6.4). The §8.2
record-hash preimage is deliberately *not* modeled — it is a local hash input, never a wire object
(see `hashing.py`).
"""

from enum import StrEnum
from typing import Annotated, Final, Literal, TypedDict

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictBool, ValidationError, model_validator

from auditable_mcp.canonical import MAX_SAFE_INTEGER, has_lone_surrogate

# The only spec version defined by this contract; a mismatch is a hard validation error.
SPEC_VERSION: Literal['auditable-mcp/0.3'] = 'auditable-mcp/0.3'

# The [SEP-2133] extension identifier: the key of the capability object in the `extensions` member of
# ClientCapabilities (host) or ServerCapabilities (tool), and of this extension's `_meta` objects
# (§6.1, §6.4). The identifier names the extension; SPEC_VERSION names the wire version.
EXTENSION_ID: Final = 'com.timberlandchapel/auditable-mcp'

# §7.6 Tier-1 code spaces pinned onto the wire contracts. The tool abort reason (on an aborted
# outcome), the host reject reason, and the unavailable reason are three distinct spaces.
AbortReason = Literal[
    'hash-mismatch', 'host-rejected', 'host-unavailable', 'host-uncountersigned', 'host-signature-invalid'
]
RejectReason = Literal['schema-invalid', 'replay-detected', 'signature-invalid', 'l2-unsigned', 'unknown-key']

# Patterns copied verbatim from the normative JSON Schema (spec/schema/), applied to `str` fields so
# validation matches the contract exactly without transforming the value — the bytes must survive
# untouched for canonicalization and hashing (§8). Rich types (UUID/datetime) would re-serialize and
# change those bytes, and accept a different (looser) set than the schema; `tests/conformance` guards
# these copies against schema drift. A UUID is the lowercase form RFC 9562 §4 gives for output and is
# compared as a string (§4); a `session_id` is never the nil UUID (§6.3).
UUID_PATTERN = (
    r'^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
    r'|00000000-0000-0000-0000-000000000000)$'
)
SESSION_ID_PATTERN = r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
# Before v0.3 the schema accepted either case.
EARLIER_UUID_PATTERN = (
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
# base64url without padding, as JWS writes a signature (§5.1).
SIGNATURE_PATTERN = r'^[A-Za-z0-9_-]+$'


def _integral(value: object) -> object:
    """Read an integral JSON number written as a float (`1.0`) as the integer it is.

    JSON Schema's `integer` accepts it, and JCS canonicalizes it to `1`, so refusing it would refuse an
    event the schema admits. The canonical bytes are computed from the received structure, never from
    this model, so reading it as an int changes nothing that is hashed or signed (§8).
    """
    if isinstance(value, float) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
        # end if
    return value
    # end def


# A JSON Schema `integer` in the §8.1 domain: an int, or a float with an integral value.
JsonCount = Annotated[int, BeforeValidator(_integral), Field(ge=0, le=MAX_SAFE_INTEGER)]


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


class Countersign(StrEnum):
    """What a participant declares on the countersignature axis (§5.2, §6.1).

    Unlike `Level`, the obligation on this axis falls on the host: `HOST` means sealed records carry a
    countersignature - a host declaring it will countersign, a tool declaring it requires one.
    """

    NONE = 'none'
    HOST = 'host'
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

    @model_validator(mode='before')
    @classmethod
    def _unicode_scalar_values_only(cls, data: object) -> object:
        """Refuse a lone surrogate in any member name or value, nested ones included (§8.1)."""
        if has_lone_surrogate(data):
            raise ValueError('a string holds a lone surrogate, which is not a Unicode scalar value (§8.1)')
            # end if
        return data
        # end def

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
    spec_version: Literal['auditable-mcp/0.3']
    ts: str = Field(pattern=DATETIME_PATTERN)
    # The audit session the host issued for the parent tools/call (§6.3), hashed and signed.
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
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
    signer_seq: JsonCount | None = None
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

    @model_validator(mode='after')
    def _level_2_fields_travel_together(self) -> 'AuditEvent':
        """`signer_seq`, `key_id`, and `signature` are present together or not at all (§4, `dependentRequired`)."""
        if len({self.signer_seq is None, self.key_id is None, self.signature is None}) != 1:
            raise ValueError('signer_seq, key_id, and signature must appear together or not at all')
            # end if
        return self
        # end def

    # end class


# Published spec versions a verifier accepts when reading a sealed ledger. Emission and ingest stay
# pinned to the current SPEC_VERSION (AuditEvent, §6.1); a verifier reading a stored ledger must accept
# records sealed under an earlier published version, since their bytes and hash chain are immutable
# evidence. Keep this tuple in sync with the two sealed views below.
KNOWN_SPEC_VERSIONS = ('auditable-mcp/0.1', 'auditable-mcp/0.1.1', 'auditable-mcp/0.2', 'auditable-mcp/0.3')
_EARLIER_SPEC_VERSIONS = KNOWN_SPEC_VERSIONS[:-1]


class SealedAuditEvent(AuditEvent):
    """Verification view of a sealed event under the current version."""

    # end class


class SealedAuditEventV01(WireModel):
    """Verification view of an event sealed under v0.1 (`spec/schema/earlier/0.1`).

    That version named the call by `call_id`, numbered events in `sequence`, and left `reason`,
    `key_id`, and `signature` as unconstrained strings.
    """

    id: str = Field(pattern=EARLIER_UUID_PATTERN)
    spec_version: Literal['auditable-mcp/0.1']
    ts: str = Field(pattern=DATETIME_PATTERN)
    call_id: str = Field(min_length=1)
    traceparent: str | None = None
    action_type: str = Field(min_length=1)
    mutates: StrictBool
    egress: StrictBool
    target_resource: TargetResource
    outcome: Annotated[Outcome, Field(strict=False)]
    reason: str | None = None
    action_context: dict[str, object] | None = None
    action_context_hash: str | None = Field(default=None, pattern=CONTEXT_HASH_PATTERN)
    sequence: JsonCount | None = None
    key_id: str | None = None
    signature: str | None = None
    # end class


class EarlierSealedAuditEvent(WireModel):
    """Verification view of an event sealed under v0.1.1 or v0.2 (`spec/schema/earlier/<version>`).

    Those records named the call by its JSON-RPC `call_id`, carry no `session_id`, and number
    `signer_seq` per key rather than per session; their bytes are immutable evidence, so a verifier reads
    them in the shape they were sealed in.
    """

    id: str = Field(pattern=EARLIER_UUID_PATTERN)
    spec_version: Literal['auditable-mcp/0.1.1', 'auditable-mcp/0.2']
    ts: str = Field(pattern=DATETIME_PATTERN)
    call_id: str = Field(min_length=1)
    traceparent: str | None = None
    action_type: str = Field(min_length=1)
    mutates: StrictBool
    egress: StrictBool
    target_resource: TargetResource
    outcome: Annotated[Outcome, Field(strict=False)]
    reason: Literal['hash-mismatch', 'host-rejected', 'host-unavailable'] | None = None
    action_context: dict[str, object] | None = None
    action_context_hash: str | None = Field(default=None, pattern=CONTEXT_HASH_PATTERN)
    signer_seq: JsonCount | None = None
    key_id: str | None = Field(default=None, min_length=1)
    # Standard base64 with padding: the encoding those versions signed in.
    signature: str | None = Field(default=None, pattern=r'^[A-Za-z0-9+/]+={0,2}$')

    @model_validator(mode='after')
    def _require_reason_when_aborted(self) -> 'EarlierSealedAuditEvent':
        """An aborted outcome carries a reason, as those versions' schema required."""
        if self.outcome == Outcome.ABORTED and self.reason is None:
            raise ValueError('an aborted outcome requires a reason')
            # end if
        return self
        # end def

    # end class


class AuditCapability(WireModel):
    """An audit capability exchanged during negotiation: the version, level, and attempt mode (§6.1)."""

    # All three REQUIRED (§6.1, normative audit-capability.schema.json): a peer that omits any field is
    # rejected, not silently coerced, so version negotiation cannot be bypassed by omission. The host's
    # own partial self-declaration is completed with explicit SDK defaults before validation (host.py).
    spec_version: str = Field(min_length=1)
    level: Annotated[Level, Field(strict=False)]
    attempt: Literal['request']
    countersign: Annotated[Countersign, Field(strict=False)]
    # end class


class AuditCapabilityInput(TypedDict, total=False):
    """A partial host self-declaration: unset fields are filled from the SDK's own capability defaults."""

    spec_version: str
    level: Level
    attempt: Literal['request']
    countersign: Countersign
    # end class


class AcceptResponse(WireModel):
    """A sealed attempt: carries the host-assigned fields the tool needs for Polluted Stop (§7.1, §7.2)."""

    status: Literal[Status.ACCEPT] = Status.ACCEPT
    seq: JsonCount
    record_hash: str = Field(pattern=CHAIN_HASH_PATTERN)
    host_ts: str = Field(pattern=DATETIME_PATTERN)
    previous_hash: str = Field(pattern=CHAIN_HASH_PATTERN)
    # The countersignature (§7.1): present exactly when the host declares `countersign: "host"`. The
    # three fields appear together or not at all - a signature no key names is unverifiable, one that
    # names no ledger can be presented as a statement about another, and a key or a ledger name with
    # no signature establishes nothing.
    host_signature: str | None = Field(default=None, pattern=SIGNATURE_PATTERN)
    host_key_id: str | None = Field(default=None, min_length=1)
    log_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode='after')
    def _countersignature_fields_travel_together(self) -> 'AcceptResponse':
        """Reject a partial countersignature (§7.1, schema `dependentRequired`)."""
        present = {self.host_signature is None, self.host_key_id is None, self.log_id is None}
        if len(present) != 1:
            raise ValueError('host_signature, host_key_id, and log_id must appear together or not at all')
            # end if
        return self
        # end def

    # end class


class RejectResponse(WireModel):
    """A refused attempt: ledger integrity could not be guaranteed (§7.1). `reason` is a Tier-1 code."""

    status: Literal[Status.REJECT] = Status.REJECT
    reason: RejectReason
    # end class


class UnavailableResponse(WireModel):
    """Nothing was decided: the tool fails closed, and may send the identical attempt again (§7.1)."""

    status: Literal[Status.UNAVAILABLE] = Status.UNAVAILABLE
    reason: Literal['internal-error'] = 'internal-error'
    # end class


# The host's answer to an attempt — a tagged union discriminated on `status` (§7.1).
AttemptResponse = Annotated[
    AcceptResponse | RejectResponse | UnavailableResponse,
    Field(discriminator='status'),
]


class AuditRequestMeta(WireModel):
    """What the host puts in a tools/call's `_meta` under the extension identifier (§6.3, §6.4).

    `session_id` names the audit session on every request of the call; `responses` answers, on a
    retry, every attempt of the round before, keyed by the attempt's `id`.
    """

    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    responses: dict[Annotated[str, Field(pattern=UUID_PATTERN)], AttemptResponse] | None = None
    # end class


class AuditResultMeta(WireModel):
    """What the tool puts in a result's `_meta` under the extension identifier (§6.4).

    The events are the wire dicts exactly as emitted, not re-modeled: their bytes are hashed, and a
    host validates each one as it seals it (§7.1).
    """

    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    events: list[dict[str, object]] = Field(min_length=1)
    # end class


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
    under any published `spec_version` (`KNOWN_SPEC_VERSIONS`), each in the shape its version defined -
    the record's bytes and hash chain do not change with the reader's version. Ingest and emission stay
    pinned to the current version.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first error as ``<location>: <message>``.
    """
    version = event.get('spec_version') if isinstance(event, dict) else None
    if version == 'auditable-mcp/0.1':
        return _first_error(SealedAuditEventV01, event)
        # end if
    if version in _EARLIER_SPEC_VERSIONS:
        return _first_error(EarlierSealedAuditEvent, event)
        # end if
    return _first_error(SealedAuditEvent, event)
    # end def
