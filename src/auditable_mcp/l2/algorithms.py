"""The algorithm and role vocabulary §5.1 binds to a `key_id`, shared by the registry and the JWK form."""

from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# A public key is one of the two schemes defined by §5.1.
PublicKey = Ed25519PublicKey | EllipticCurvePublicKey


class SignatureAlgorithm(StrEnum):
    """The signature algorithms defined by this version (§5.1)."""

    ED25519 = 'Ed25519'
    ES256 = 'ES256'
    # end class


class KeyRole(StrEnum):
    """Whose keys a registry holds (§5.1 for a tool's, §7.1 for a host's).

    §10.9 requires the two registries to share no entry, and the only way an SDK can hold that is to
    make one registry serve one role. Without it a single registry serves both, a tool's own key
    resolves as a `host_key_id`, and the tool manufactures the host-countersigned state §5.2 says it
    cannot - defeating the axis rather than degrading it.
    """

    TOOL = 'tool'
    HOST = 'host'
    # end class
