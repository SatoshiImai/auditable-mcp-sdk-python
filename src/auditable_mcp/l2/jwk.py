"""The interchange form for registry entries: a JWK Set (RFC 7517), plus RFC 7638 thumbprints.

Spec sec. 5.1 gives a registry entry its meaning - one `key_id`, one algorithm, one public key that
MUST be a key of that algorithm - and leaves provisioning to the deployment. It says nothing about
bytes, which is right for a specification and not enough for two implementations that have to hand
each other a key. Without a form in the SDK, every consumer invents one.

The form is the standard one rather than a private invention. JWK already carries `kid`, the
algorithm and the key material in fixed-length members, so a wrong encoding is refused at
registration instead of surfacing later as `signature-invalid` - which names a forged signature and
sends an operator looking for the wrong thing.

JWK encodes key material base64url without padding, and sec. 5.1 writes a signature the same way, so
a key file and a wire event share one encoding and one strict decoder (`auditable_mcp.encoding`). The
`alg` member is the fully-specified JOSE name the registry binds (RFC 9864), which is also sec. 5.1's
algorithm identifier: `Ed25519`, not the deprecated polymorphic `EdDSA`.

## What this does not do

It decides how to read the bytes, never whether the bytes are genuine. A substituted public key
verifies forged records perfectly. Authenticating the channel belongs to the deployment (its secret
store, its file permissions, its infrastructure-as-code); `jwk_thumbprint` exists so a person can
compare a key out of band, not so the SDK can claim to have checked it.
"""

import hashlib
import json
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicKey, EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.l2.algorithms import KeyRole, PublicKey, SignatureAlgorithm

# Each coordinate of a P-256 point, and an Ed25519 public key, are this many bytes. Fixed lengths are
# what let a wrong encoding be refused at registration (sec. 5.1).
_P256_COORD_LEN: Final = 32
_ED25519_KEY_LEN: Final = 32

# RFC 8037 for the Ed25519 parameters; RFC 7518 for the P-256 ones.
_PARAMETERS: Final[dict[SignatureAlgorithm, dict[str, str]]] = {
    SignatureAlgorithm.ED25519: {'kty': 'OKP', 'crv': 'Ed25519', 'alg': 'Ed25519'},
    SignatureAlgorithm.ES256: {'kty': 'EC', 'crv': 'P-256', 'alg': 'ES256'},
}
# The `alg` value a JWK may carry for each algorithm. `alg` is optional in a JWK (RFC 7517); when present
# it names the algorithm the key is, by the fully-specified name §5.1 uses. The polymorphic `EdDSA` that
# RFC 9864 deprecates is not an identifier of this specification.
_ACCEPTED_ALG: Final[dict[SignatureAlgorithm, frozenset[str]]] = {
    SignatureAlgorithm.ED25519: frozenset({'Ed25519'}),
    SignatureAlgorithm.ES256: frozenset({'ES256'}),
}
_BY_PARAMETERS: Final[dict[tuple[str, str], SignatureAlgorithm]] = {
    (value['kty'], value['crv']): key for key, value in _PARAMETERS.items()
}

# RFC 7638 hashes only the required members of a key, in lexicographic order.
_THUMBPRINT_MEMBERS: Final[dict[str, tuple[str, ...]]] = {
    'OKP': ('crv', 'kty', 'x'),
    'EC': ('crv', 'kty', 'x', 'y'),
}

# RFC 7517 sec. 4 asks a private member name to be collision-resistant, so the role does not ride on a
# bare `role` that a future registered member could claim.
ROLE_MEMBER: Final = 'amcp_role'
# Marks a revoked entry (sec. 10.9). Revocation is forward-only, so a peer provisioned from a set has to
# learn it too; without the member an exported set would carry a revoked key as a live one.
REVOKED_MEMBER: Final = 'amcp_revoked'


def _unb64url(value: object, member: str) -> bytes:
    """Decode a JWK member that must be unpadded base64url.

    Args:
        value: The member as read from the document.
        member: Its name, for the refusal.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: The member is absent, not a string, or not canonical base64url.
    """
    raw = b64url_decode(value)
    if raw is None:
        raise ValueError(f'a JWK member {member!r} is not unpadded base64url (RFC 7517)')
        # end if
    return raw
    # end def


def public_jwk(
    key_id: str,
    public_key: PublicKey,
    algorithm: SignatureAlgorithm,
    role: KeyRole,
    *,
    revoked: bool = False,
) -> dict[str, Any]:
    """Render one registry entry as a JWK (RFC 7517, RFC 8037).

    Args:
        key_id: The entry's `key_id`, carried as `kid`.
        public_key: The entry's public key.
        algorithm: The algorithm bound to the entry (sec. 5.1).
        role: Whether the key belongs to a tool or a host (sec. 10.9); carried as `amcp_role`.
        revoked: Whether the entry is revoked (sec. 10.9); carried as `amcp_revoked: true` when it is.

    Returns:
        The JWK as a plain dictionary.

    Raises:
        ValueError: `public_key` is not a key of `algorithm`.
    """
    parameters = _PARAMETERS[algorithm]
    if algorithm is SignatureAlgorithm.ED25519:
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError(f'an {algorithm} entry binds an Ed25519 key (§5.1)')
            # end if
        material = {'x': b64url_encode(public_key.public_bytes_raw())}
    else:
        if not isinstance(public_key, EllipticCurvePublicKey):
            raise ValueError(f'a {algorithm} entry binds an elliptic-curve key (§5.1)')
            # end if
        numbers = public_key.public_numbers()
        material = {
            'x': b64url_encode(numbers.x.to_bytes(_P256_COORD_LEN, 'big')),
            'y': b64url_encode(numbers.y.to_bytes(_P256_COORD_LEN, 'big')),
        }
        # end if
    jwk: dict[str, Any] = {'kid': key_id, **parameters, **material, ROLE_MEMBER: role.value}
    if revoked:
        jwk[REVOKED_MEMBER] = True
        # end if
    return jwk
    # end def


def public_key_of(jwk: dict[str, Any]) -> tuple[str, PublicKey, SignatureAlgorithm, KeyRole]:
    """Read one JWK back into the entry it describes.

    Args:
        jwk: The JWK as a plain dictionary.

    Returns:
        The `key_id`, public key, algorithm and role the JWK carries.

    Whether the entry is revoked is the JWK's `amcp_revoked` member, which this function checks is a
    boolean where present.

    Raises:
        ValueError: The JWK is malformed, names an algorithm this version does not define (sec. 12.1),
            carries key material of the wrong length, names no role, or carries an `amcp_revoked` that
            is not a boolean.
    """
    if 'd' in jwk:
        # The private member of both key types (RFC 7518 sec. 6.2.2.1, RFC 8037 sec. 2). A registry is
        # provisioned with public keys only, so a file carrying `d` means a private key is travelling
        # the public channel; accepting it quietly would make that normal.
        raise ValueError('this JWK carries a private key (`d`); a registry is provisioned with public keys only')
        # end if
    key_id = jwk.get('kid')
    if not isinstance(key_id, str) or not key_id:
        raise ValueError('a JWK in this set carries no `kid`, which is the entry’s key_id (§5.1)')
        # end if
    algorithm = _BY_PARAMETERS.get((str(jwk.get('kty')), str(jwk.get('crv'))))
    if algorithm is None:
        raise ValueError(
            f'kty/crv {jwk.get("kty")!r}/{jwk.get("crv")!r} is not an algorithm this version defines (§12.1)'
        )
        # end if
    if 'alg' in jwk and jwk['alg'] not in _ACCEPTED_ALG[algorithm]:
        raise ValueError(f'a {jwk.get("kty")}/{jwk.get("crv")} key is not an {jwk["alg"]!r} key (RFC 7517 `alg`)')
        # end if
    try:
        role = KeyRole(str(jwk.get(ROLE_MEMBER)))
    except ValueError as error:
        # A set that does not say whose keys it holds can be loaded into the wrong registry, and a tool
        # key in a host registry lets a tool sign itself into the countersigned state (§5.2).
        raise ValueError(
            f'a JWK in this set carries no {ROLE_MEMBER!r}; the set does not say whose keys it holds'
        ) from error
        # end try
    _check_revoked(jwk)
    if algorithm is SignatureAlgorithm.ED25519:
        raw = _unb64url(jwk.get('x'), 'x')
        if len(raw) != _ED25519_KEY_LEN:
            raise ValueError(f'an Ed25519 `x` is {_ED25519_KEY_LEN} bytes, not {len(raw)} (RFC 8037)')
            # end if
        return key_id, Ed25519PublicKey.from_public_bytes(raw), algorithm, role
        # end if
    coordinates = []
    for member in ('x', 'y'):
        raw = _unb64url(jwk.get(member), member)
        if len(raw) != _P256_COORD_LEN:
            raise ValueError(f'a P-256 {member!r} is {_P256_COORD_LEN} bytes, not {len(raw)} (RFC 7518)')
            # end if
        coordinates.append(int.from_bytes(raw, 'big'))
        # end for
    numbers = EllipticCurvePublicNumbers(coordinates[0], coordinates[1], SECP256R1())
    return key_id, numbers.public_key(), algorithm, role
    # end def


def _check_revoked(jwk: dict[str, Any]) -> None:
    """Refuse an `amcp_revoked` member that is not a boolean (sec. 10.9).

    Args:
        jwk: The JWK as a plain dictionary.

    Raises:
        ValueError: The member is present and is not a boolean.
    """
    if not isinstance(jwk.get(REVOKED_MEMBER, False), bool):
        raise ValueError(f'a JWK member {REVOKED_MEMBER!r} is a boolean')
        # end if
    # end def


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Return the RFC 7638 thumbprint of `jwk`, base64url without padding.

    The thumbprint covers only the members RFC 7638 requires, so it is the same for the same key
    however the surrounding document was written. It is there for a person comparing a key over a
    second channel; it authenticates nothing by itself.

    Args:
        jwk: The JWK as a plain dictionary.

    Returns:
        The thumbprint.

    Raises:
        ValueError: The JWK names a key type this version does not define.
    """
    members = _THUMBPRINT_MEMBERS.get(str(jwk.get('kty')))
    if members is None:
        raise ValueError(f'kty {jwk.get("kty")!r} is not a key type this version defines (§12.1)')
        # end if
    missing = [member for member in members if not isinstance(jwk.get(member), str)]
    if missing:
        # A thumbprint of an incomplete key is a value for something that is not a key, and a person
        # comparing it out of band would see a match where there is nothing to match.
        raise ValueError(f'a thumbprint needs every required member as a string; this JWK lacks {missing} (RFC 7638)')
        # end if
    canonical = json.dumps({member: jwk[member] for member in members}, separators=(',', ':'), sort_keys=True)
    return b64url_encode(hashlib.sha256(canonical.encode('utf-8')).digest())
    # end def
