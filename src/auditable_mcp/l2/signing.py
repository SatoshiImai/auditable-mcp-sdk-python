"""Level-2 signing (tool side).

The detached signature is computed over the RFC 8785 canonical form of the event with the
`signature` field removed (§8.2), so `key_id` and `sequence` are part of the signed payload and
tampering with any field invalidates the signature. `Ed25519Signer` implements the session's
`EventSigner` protocol and owns the per-key monotonic sequence counter.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditable_mcp import fields
from auditable_mcp.canonical import canonicalize
from auditable_mcp.l2.keys import ToolKey


def signature_payload(event: dict[str, object]) -> bytes:
    """Return the bytes to sign or verify: canonical(event without the `signature` field), UTF-8."""
    rest = {key: value for key, value in event.items() if key != fields.SIGNATURE}
    return canonicalize(rest).encode('utf-8')
    # end def


def sign_event(
    event: dict[str, object], key_id: str, signer_seq: int, private_key: Ed25519PrivateKey
) -> dict[str, object]:
    """Return `event` stamped with `key_id`, `signer_seq`, and a base64 detached Ed25519 signature."""
    signed = {**event, fields.KEY_ID: key_id, fields.SIGNER_SEQ: signer_seq}
    signature = base64.b64encode(private_key.sign(signature_payload(signed))).decode('ascii')
    return {**signed, fields.SIGNATURE: signature}
    # end def


class Ed25519Signer:
    """A stateful `EventSigner` that stamps events with a monotonic per-key signer_seq (§7.4)."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey, *, start_signer_seq: int = 0) -> None:
        """Bind the signer to a key and the next signer_seq value it will emit."""
        self._key_id = key_id
        self._private_key = private_key
        self._next_signer_seq = start_signer_seq
        # end def

    @classmethod
    def from_tool_key(cls, tool_key: ToolKey, *, start_signer_seq: int = 0) -> 'Ed25519Signer':
        """Build a signer from a generated tool key."""
        return cls(tool_key.key_id, tool_key.private_key, start_signer_seq=start_signer_seq)
        # end def

    async def sign(self, event: dict[str, object]) -> dict[str, object]:
        """Stamp the event with the next signer_seq and a detached signature (local, no I/O)."""
        signer_seq = self._next_signer_seq
        self._next_signer_seq += 1
        return sign_event(event, self._key_id, signer_seq, self._private_key)
        # end def

    # end class
