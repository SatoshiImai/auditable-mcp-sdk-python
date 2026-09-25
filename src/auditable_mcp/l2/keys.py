"""Level-2 key material: Ed25519 tool keys and the host's public-key registry.

A tool holds a private key and signs its self-attestations; the host verifies against a public key
registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
real-time control (§5, §10.2).

§5.1 binds the signature algorithm to the `key_id` through this registry (the event carries no
algorithm), so one host verifies a heterogeneous fleet — Ed25519 tools alongside KMS ECDSA P-256
tools. §10.9 governs lifecycle: a `key_id` maps to exactly one key for life (re-registering it with a
different key is forbidden — rotation uses a fresh `key_id`), and revocation is forward-only: a revoked
entry stays in the registry, marked revoked, so the records it signed while valid still verify.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from auditable_mcp.l2.algorithms import KeyRole, PublicKey, SignatureAlgorithm
from auditable_mcp.l2.jwk import REVOKED_MEMBER, public_jwk, public_key_of

# §5.1: an entry's public key must be a key of the entry's algorithm. Pinning the pair here is what
# lets the verifiers assert the key type instead of meeting a mismatch mid-verification.
_KEY_TYPES: dict[SignatureAlgorithm, type[Ed25519PublicKey] | type[EllipticCurvePublicKey]] = {
    SignatureAlgorithm.ED25519: Ed25519PublicKey,
    SignatureAlgorithm.ES256: EllipticCurvePublicKey,
}


@dataclass(frozen=True)
class ToolKey:
    """A tool's Ed25519 key pair and its identity."""

    key_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey
    # end class


@dataclass(frozen=True)
class RegisteredKey:
    """A registered public key and the algorithm bound to its `key_id` (§5.1).

    `revoked` marks an entry whose key confirms nothing new (§10.9): a verifier reading a sealed record
    still checks it against the entry, while a host refuses a new event under it as `unknown-key` and a
    tool refuses a new accept countersigned under it.
    """

    algorithm: SignatureAlgorithm
    public_key: PublicKey
    revoked: bool = False
    # end class


def _same_key(left: PublicKey, right: PublicKey) -> bool:
    """Return True if the two keys are the same public key.

    Compared by their encoded bytes, not by object identity: a deployment that re-reads its registry
    from disk holds a different object for the same key, and re-registering it is the idempotent case
    §10.9 permits rather than the different-key case it forbids.
    """
    encoding = serialization.Encoding.DER
    form = serialization.PublicFormat.SubjectPublicKeyInfo
    return left.public_bytes(encoding, form) == right.public_bytes(encoding, form)
    # end def


def _is_key_of(public_key: PublicKey, algorithm: SignatureAlgorithm) -> bool:
    """Return True if `public_key` is a key of `algorithm`: its type and, for ES256, its curve (§5.1)."""
    if not isinstance(public_key, _KEY_TYPES[algorithm]):
        return False
        # end if
    if isinstance(public_key, EllipticCurvePublicKey):
        return isinstance(public_key.curve, SECP256R1)
        # end if
    return True
    # end def


def generate_tool_key(key_id: str) -> ToolKey:
    """Generate a fresh Ed25519 tool key under `key_id`."""
    private_key = Ed25519PrivateKey.generate()
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


def tool_key_pkcs8(tool_key: ToolKey) -> bytes:
    """Render a tool key's private half as unencrypted PKCS#8 DER, for a deployment to store.

    The form is pinned so a deployment does not have to invent one: two implementations that each
    invent one cannot hand a key to each other.

    This is for development and for a tool that signs in its own process. A deployment that has to
    withstand a compromised worker keeps the private half where the worker cannot read it and signs
    through a KMS adapter instead; there is no private half to render then.

    Args:
        tool_key: The key whose private half to render.

    Returns:
        The PKCS#8 DER bytes.
    """
    return tool_key.private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # end def


def load_tool_key(key_id: str, pkcs8: bytes) -> ToolKey:
    """Read a tool key back from unencrypted PKCS#8 DER or PEM under `key_id`.

    A tool that mints a key per process leaves every signature uncheckable once that process ends, and
    binds one `key_id` to many keys against §10.9. Reading a stored key is how a tool keeps one.

    Args:
        key_id: The `key_id` this key signs under.
        pkcs8: The private key as PKCS#8, DER or PEM.

    Returns:
        The tool key.

    Raises:
        ValueError: The bytes are not a PKCS#8 Ed25519 private key, or `key_id` is empty.
    """
    if not key_id:
        raise ValueError('a tool key binds a non-empty key_id (§5.1)')
        # end if
    loader = (
        serialization.load_pem_private_key
        if pkcs8.lstrip().startswith(b'-----')
        else serialization.load_der_private_key
    )
    try:
        private_key = loader(pkcs8, password=None)
    except (ValueError, TypeError) as error:
        raise ValueError('the tool key is not an unencrypted PKCS#8 private key') from error
        # end try
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(f'a tool key is Ed25519, not {type(private_key).__name__} (§5.1)')
        # end if
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


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
            ValueError: If `key_id` is empty, if `public_key` is not a key of `algorithm`, or if
                `key_id` is already bound to a different key or algorithm.
        """
        if not key_id:
            raise ValueError('a registry entry binds a non-empty key_id (§5.1)')
            # end if
        # §5.1: the public key MUST be a key of the entry's algorithm, and a disagreeing entry is
        # refused here rather than carried to verification time, where every event bound to it would
        # be rejected `signature-invalid` — a forged signature, which is not what went wrong.
        if not _is_key_of(public_key, algorithm):
            raise ValueError(f'the key registered under {key_id!r} is not a key of {algorithm} (§5.1)')
            # end if
        existing = self._keys.get(key_id)
        if existing is not None and (existing.algorithm != algorithm or not _same_key(existing.public_key, public_key)):
            raise ValueError(f'key_id {key_id!r} is already registered with a different key (§10.9)')
            # end if
        if existing is not None:
            # Registering the same key again changes nothing, and in particular does not lift a revocation.
            return
            # end if
        self._keys[key_id] = RegisteredKey(algorithm=algorithm, public_key=public_key)
        # end def

    def register_tool_key(self, tool_key: ToolKey) -> None:
        """Register the public half of a generated (Ed25519) tool key."""
        self.register(tool_key.key_id, tool_key.public_key, SignatureAlgorithm.ED25519)
        # end def

    def to_jwks(self) -> dict[str, object]:
        """Render this registry as a JWK Set for provisioning a peer's registry (§5.1).

        Every key carries this registry's role, so a peer loading the set into a registry of the other
        role is refused rather than silently holding a tool's key as a host's (§5.2, §10.9). A revoked
        entry carries `amcp_revoked: true`, so a peer provisioned from the set holds it revoked as well.

        Returns:
            The JWK Set as a plain dictionary, its `keys` in `key_id` order.
        """
        return {
            'keys': [
                public_jwk(key_id, entry.public_key, entry.algorithm, self.role, revoked=entry.revoked)
                for key_id, entry in sorted(self._keys.items())
            ]
        }
        # end def

    def load_jwks(self, document: dict[str, object]) -> None:
        """Register every key in a JWK Set, adding to what this registry already holds (§5.1).

        Loading is additive because rotation mints a fresh `key_id` (§10.9) while the records the old
        one signed still have to verify: dropping the old entry would break history rather than
        rotate it. Re-registering an entry unchanged is idempotent, as `register` is. An entry marked
        `amcp_revoked: true` is held revoked; revocation is forward-only, so an unrevoked copy of a key
        already revoked here does not lift the revocation (§10.9).

        Args:
            document: A JWK Set, as `to_jwks` renders one.

        Raises:
            ValueError: The set is malformed, a key names a role other than this registry's, or a
                `key_id` is already bound to a different key (§10.9).
        """
        keys = document.get('keys') if isinstance(document, dict) else None
        if not isinstance(keys, list):
            raise ValueError('a JWK Set carries its keys under `keys` (RFC 7517)')
            # end if
        if not all(isinstance(key, dict) for key in keys):
            # Skipping what is not a key would load the rest of a set that is not what it claims to be.
            raise ValueError("every member of a JWK Set's `keys` is a JWK object (RFC 7517)")
            # end if
        entries = [public_key_of(key) for key in keys]
        for key_id, _public_key, _algorithm, role in entries:
            if role is not self.role:
                raise ValueError(
                    f'key_id {key_id!r} is a {role.value} key; this registry holds {self.role.value} keys (§10.9)'
                )
                # end if
            # end for
        # Rehearse on a copy first: a `key_id` repeated within the set, or already bound here to another
        # key, is refused by `register` itself - and refused before anything lands, so a set with one bad
        # key leaves this registry as it was rather than half-provisioned.
        rehearsal = KeyRegistry(self.role)
        rehearsal._keys = dict(self._keys)
        for key_id, public_key, algorithm, _role in entries:
            rehearsal.register(key_id, public_key, algorithm)
            # end for
        for key in keys:
            if key.get(REVOKED_MEMBER) is True:
                rehearsal.revoke(str(key['kid']))
                # end if
            # end for
        self._keys = rehearsal._keys
        # end def

    def revoke(self, key_id: str) -> None:
        """Revoke `key_id`, keeping its entry (forward-only, §10.9).

        A host thereafter refuses new events under it as `unknown-key`, and a tool refuses a new accept
        countersigned under it; a verifier checks the records it signed while valid against it as before.

        Raises:
            ValueError: `key_id` was never registered here. Revoking it would do nothing, and an operator
                who meant to revoke a key must not be left believing it is revoked.
        """
        entry = self._keys.get(key_id)
        if entry is None:
            raise ValueError(f'key_id {key_id!r} is not registered; there is nothing to revoke (§10.9)')
            # end if
        self._keys[key_id] = RegisteredKey(algorithm=entry.algorithm, public_key=entry.public_key, revoked=True)
        # end def

    def get(self, key_id: str) -> RegisteredKey | None:
        """Return the entry for `key_id`, revoked or not, or None if it was never registered."""
        return self._keys.get(key_id)
        # end def

    def current(self, key_id: str) -> RegisteredKey | None:
        """Return the entry for `key_id` if it may confirm something new: registered and not revoked."""
        entry = self._keys.get(key_id)
        return entry if entry is not None and not entry.revoked else None
        # end def

    def public_keys(self) -> list[PublicKey]:
        """Return every public key this registry holds, revoked ones included."""
        return [entry.public_key for entry in self._keys.values()]
        # end def

    # end class


def assert_registries_disjoint(tool_registry: KeyRegistry, host_registry: KeyRegistry) -> None:
    """Refuse a pair of registries that share a key (§10.9).

    A tool holding a key the countersignature registry binds to a host can countersign its own records,
    manufacturing the state §5.2 rests on it being unable to reach. The comparison is by key, not by
    `key_id`: the two registries name their entries independently, and the same key under two names is
    still one key. Revoked entries count, since a revoked key is still a key the other side holds.

    Args:
        tool_registry: The registry of tool keys (§5.1).
        host_registry: The registry of host keys (§7.1).

    Raises:
        ValueError: The roles are not tool and host, or some key is registered in both.
    """
    if tool_registry.role is not KeyRole.TOOL or host_registry.role is not KeyRole.HOST:
        raise ValueError(
            'assert_registries_disjoint takes a tool-key registry and a host-key registry, in that order (§10.9)'
        )
        # end if
    for tool_key in tool_registry.public_keys():
        if any(_same_key(tool_key, host_key) for host_key in host_registry.public_keys()):
            raise ValueError('a key is registered for both a tool and a host; the two registries share no key (§10.9)')
            # end if
        # end for
    # end def
