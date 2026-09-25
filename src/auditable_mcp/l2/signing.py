"""Signing: Level-2 events (tool side) and countersignatures (host side).

The detached signature is computed over the RFC 8785 canonical form of the event with the
`signature` field removed (§8.2), so `key_id` and `sequence` are part of the signed payload and
tampering with any field invalidates the signature. `Ed25519Signer` implements the session's
`EventSigner` protocol; the session, not the signer, owns the sequence (§7.4).

`Ed25519Countersigner` is the host-side counterpart (§5.2, §7.1). It signs an already-canonical
payload built by the host (`hashing.countersignature_payload`), carries no sequence of its own, and is bound
to a `host_key_id` a verifier's registry resolves separately from any tool key: the two registries
have the same shape and the same algorithm identifiers, and never share an entry.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditable_mcp import fields
from auditable_mcp.canonical import canonicalize
from auditable_mcp.encoding import b64url_encode
from auditable_mcp.l2.keys import ToolKey


def signature_payload(event: dict[str, object]) -> bytes:
    """Return the bytes to sign or verify: canonical(event without the `signature` field), UTF-8."""
    rest = {key: value for key, value in event.items() if key != fields.SIGNATURE}
    return canonicalize(rest).encode('utf-8')
    # end def


def sign_event(
    event: dict[str, object], key_id: str, signer_seq: int, private_key: Ed25519PrivateKey
) -> dict[str, object]:
    """Return `event` stamped with `key_id`, `signer_seq`, and a base64url detached Ed25519 signature (§5.1)."""
    signed = {**event, fields.KEY_ID: key_id, fields.SIGNER_SEQ: signer_seq}
    signature = b64url_encode(private_key.sign(signature_payload(signed)))
    return {**signed, fields.SIGNATURE: signature}
    # end def


class Ed25519Signer:
    """A stateful `EventSigner` that stamps events with a monotonic per-key signer_seq (§7.4)."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        """Bind the signer to a key.

        The sequence is not the signer's: a counter in a signer's memory cannot hold §7.4 across a
        restart or across two processes sharing the key. It lives in a `SignerSeqStore` the session
        holds, and arrives here per event.
        """
        self._key_id = key_id
        self._private_key = private_key
        # end def

    @classmethod
    def from_tool_key(cls, tool_key: ToolKey) -> 'Ed25519Signer':
        """Build a signer from a generated tool key."""
        return cls(tool_key.key_id, tool_key.private_key)
        # end def

    @property
    def key_id(self) -> str:
        """The `key_id` this signer stamps, which names the sequence it advances (§7.4)."""
        return self._key_id
        # end def

    async def sign(self, event: dict[str, object], signer_seq: int) -> dict[str, object]:
        """Stamp the event with `signer_seq` and a detached signature (local, no I/O)."""
        return sign_event(event, self._key_id, signer_seq, self._private_key)
        # end def

    # end class


class Ed25519Countersigner:
    """A `Countersigner` that signs the host-assigned fields of a record this host sealed (§7.1)."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        """Bind the signer to the `host_key_id` a verifier's registry resolves to this key."""
        self._key_id = key_id
        self._private_key = private_key
        # end def

    @property
    def key_id(self) -> str:
        """The `host_key_id` returned alongside every signature this host produces."""
        return self._key_id
        # end def

    async def sign(self, payload: bytes) -> str:
        """Return the base64url detached signature over the canonical payload (local, no I/O)."""
        return b64url_encode(self._private_key.sign(payload))
        # end def

    # end class
