"""Wire field names for the Auditable MCP contracts.

The complete registry of object keys across the wire contracts (§4 event and target_resource, §6.1
capability, §7.1 attempt response, §6.4 `_meta` objects), so protocol keys are referenced by name
instead of repeated string literals. Values are the exact keys defined by `spec/schema/`.
"""

# Audit event (§4).
ID = 'id'
SPEC_VERSION = 'spec_version'
TS = 'ts'
SESSION_ID = 'session_id'
TRACEPARENT = 'traceparent'
ACTION_TYPE = 'action_type'
MUTATES = 'mutates'
EGRESS = 'egress'
TARGET_RESOURCE = 'target_resource'
OUTCOME = 'outcome'
REASON = 'reason'
ACTION_CONTEXT = 'action_context'
ACTION_CONTEXT_HASH = 'action_context_hash'
SIGNER_SEQ = 'signer_seq'
KEY_ID = 'key_id'
SIGNATURE = 'signature'

# target_resource (§4).
KIND = 'kind'
REF = 'ref'
SCOPE_HINT = 'scope_hint'

# Attempt response (§7.1). `reason` is shared with the event above.
STATUS = 'status'
SEQ = 'seq'
RECORD_HASH = 'record_hash'
HOST_TS = 'host_ts'
PREVIOUS_HASH = 'previous_hash'
HOST_SIGNATURE = 'host_signature'
HOST_KEY_ID = 'host_key_id'
LOG_ID = 'log_id'

# Audit capability (§6.1).
LEVEL = 'level'
ATTEMPT = 'attempt'
COUNTERSIGN = 'countersign'

# The `_meta` objects of the 2026-07-28 binding (§6.4). `session_id` is shared with the event above.
RESPONSES = 'responses'
EVENTS = 'events'
