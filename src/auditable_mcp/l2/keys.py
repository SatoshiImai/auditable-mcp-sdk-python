"""Level-2 key material: Ed25519 tool keys and the host's public-key registry.

A tool holds a private key and signs its self-attestations; the host verifies against a public key
registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
real-time control (§5, §10.2).
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class ToolKey:
    """A tool's Ed25519 key pair and its identity."""

    key_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey
    # end class


def generate_tool_key(key_id: str) -> ToolKey:
    """Generate a fresh Ed25519 tool key under `key_id`."""
    private_key = Ed25519PrivateKey.generate()
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


class KeyRegistry[PublicKeyT]:
    """Maps `key_id` to a registered public key, established out-of-band at onboarding.

    Parameterized by public-key type so each verifier holds a type-correct registry —
    `KeyRegistry[Ed25519PublicKey]` for Ed25519, `KeyRegistry[EllipticCurvePublicKey]` for ECDSA. A
    `key_id` the host has never onboarded is untrusted; its events are rejected as unverifiable.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._keys: dict[str, PublicKeyT] = {}
        # end def

    def register(self, key_id: str, public_key: PublicKeyT) -> None:
        """Register a public key under its `key_id`."""
        self._keys[key_id] = public_key
        # end def

    def register_tool_key(self: 'KeyRegistry[Ed25519PublicKey]', tool_key: ToolKey) -> None:
        """Register the public half of a generated (Ed25519) tool key."""
        self._keys[tool_key.key_id] = tool_key.public_key
        # end def

    def get(self, key_id: str) -> PublicKeyT | None:
        """Return the registered public key for `key_id`, or None if unknown."""
        return self._keys.get(key_id)
        # end def

    # end class
