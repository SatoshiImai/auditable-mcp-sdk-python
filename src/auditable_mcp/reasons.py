"""Reason and anomaly codes shared across modules or carried on the wire (§7.1, §7.2, §7.4).

Codes local to a single module are defined in that module.
"""

# Terminal-outcome reasons a tool emits on abort (§7.2 RECOMMENDED).
HASH_MISMATCH = 'hash-mismatch'
HOST_REJECTED = 'host-rejected'
HOST_UNAVAILABLE = 'host-unavailable'

# Host reject reasons and anomaly kinds (§7.1, §7.4).
SCHEMA_INVALID = 'schema-invalid'
ATTEMPT_MUST_BE_ATTEMPTED = 'attempt-must-be-attempted'
NUMERIC_DOMAIN = 'numeric-domain'
L2_UNSIGNED = 'l2-unsigned'
ATTEMPT_REPLAY = 'attempt-replay'
PERSISTENCE_FAILURE = 'persistence-failure'
SIGNER_SEQUENCE_REPLAY = 'signer-sequence-replay'
SIGNER_SEQUENCE_GAP = 'signer-sequence-gap'
UNKNOWN_KEY = 'unknown-key'
SIGNATURE_INVALID = 'signature-invalid'
OUTCOME_AFTER_REJECT = 'outcome-after-reject'
OUTCOME_WITHOUT_ATTEMPT = 'outcome-without-attempt'
