"""Level-2 key material: Ed25519 tool keys and the host's public-key registry.

A tool holds a private key and signs its self-attestations; the host verifies against a public key
registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
real-time control (§5, §10.2).

§5.1 binds the signature algorithm to the `key_id` through this registry (the event carries no
algorithm), so one host verifies a heterogeneous fleet — Ed25519 tools alongside KMS ECDSA P-256
tools. §10.9 governs lifecycle: a `key_id` maps to exactly one key for life (re-registering it with a
different key is forbidden — rotation uses a fresh `key_id`), and revocation is forward-only.
"""

from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# A public key is one of the two schemes defined by §5.1.
PublicKey = Ed25519PublicKey | EllipticCurvePublicKey


class SignatureAlgorithm(StrEnum):
    """The signature algorithms defined by this version (§5.1)."""

    ED25519 = 'Ed25519'
    ECDSA_P256_SHA256 = 'ECDSA_P256_SHA256'
    # end class


@dataclass(frozen=True)
class ToolKey:
    """A tool's Ed25519 key pair and its identity."""

    key_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey
    # end class


@dataclass(frozen=True)
class RegisteredKey:
    """A registered public key and the algorithm bound to its `key_id` (§5.1)."""

    algorithm: SignatureAlgorithm
    public_key: PublicKey
    # end class


def generate_tool_key(key_id: str) -> ToolKey:
    """Generate a fresh Ed25519 tool key under `key_id`."""
    private_key = Ed25519PrivateKey.generate()
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


class KeyRole(StrEnum):
    """Whose keys a registry holds (§5.1 for a tool's, §7.1 for a host's).

    §10.9 requires the two registries to share no entry, and the only way an SDK can hold that is to
    make one registry serve one role. Without it a single registry serves both, a tool's own key
    resolves as a `host_key_id`, and the tool manufactures the host-witnessed state §5.2 says it
    cannot - defeating the axis rather than degrading it.
    """

    TOOL = 'tool'
    HOST = 'host'
    # end class


class KeyRegistry:
    """Maps `key_id` to its bound algorithm and public key, established out-of-band at onboarding (§5.1).

    One registry holds one role's keys (§10.9); see `KeyRole`.
    """

    def __init__(self, role: KeyRole = KeyRole.TOOL) -> None:
        """Initialize an empty registry for one role's keys (§10.9)."""
        self.role = role
        self._keys: dict[str, RegisteredKey] = {}
        # end def

    def register(self, key_id: str, public_key: PublicKey, algorithm: SignatureAlgorithm) -> None:
        """Register a public key and its algorithm under `key_id`.

        Re-registering the same key is idempotent; re-registering a `key_id` with a different key or
        algorithm is forbidden — rotation MUST use a fresh `key_id` (§10.9).

        Raises:
            ValueError: If `key_id` is already bound to a different key or algorithm.
        """
        existing = self._keys.get(key_id)
        if existing is not None and (existing.algorithm != algorithm or existing.public_key is not public_key):
            raise ValueError(f'key_id {key_id!r} is already registered with a different key (§10.9)')
            # end if
        self._keys[key_id] = RegisteredKey(algorithm=algorithm, public_key=public_key)
        # end def

    def register_tool_key(self, tool_key: ToolKey) -> None:
        """Register the public half of a generated (Ed25519) tool key."""
        self.register(tool_key.key_id, tool_key.public_key, SignatureAlgorithm.ED25519)
        # end def

    def revoke(self, key_id: str) -> None:
        """Revoke `key_id`; it is thereafter `unknown-key` (forward-only, §10.9). Sealed records stay valid."""
        self._keys.pop(key_id, None)
        # end def

    def get(self, key_id: str) -> RegisteredKey | None:
        """Return the registered key + algorithm for `key_id`, or None if unknown."""
        return self._keys.get(key_id)
        # end def

    # end class
