"""M1/M2: the interchange form two implementations hand each other keys in (§5.1, RFC 7517)."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.l2 import (
    REVOKED_MEMBER,
    ROLE_MEMBER,
    KeyRegistry,
    KeyRole,
    SignatureAlgorithm,
    generate_tool_key,
    jwk_thumbprint,
    load_tool_key,
    public_jwk,
    public_key_of,
    tool_key_pkcs8,
)


def _p256() -> object:
    """A P-256 public key, standing in for one held in a KMS."""
    return generate_private_key(SECP256R1()).public_key()
    # end def


class TestTheInterchangeForm:
    """A key written by one side reads back as the same entry on the other."""

    def test_an_ed25519_entry_survives_the_round_trip(self) -> None:
        """The whole entry - key_id, key, algorithm, role - comes back, not just the bytes."""
        key = generate_tool_key('tool-1')
        jwk = public_jwk('tool-1', key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        key_id, public_key, algorithm, role = public_key_of(jwk)
        assert (key_id, algorithm, role) == ('tool-1', SignatureAlgorithm.ED25519, KeyRole.TOOL)
        assert public_key.public_bytes_raw() == key.public_key.public_bytes_raw()
        # end def

    def test_a_p256_entry_survives_the_round_trip(self) -> None:
        """The KMS-hosted algorithm travels the same way, as one entry with two coordinates."""
        original = _p256()
        jwk = public_jwk('host-1', original, SignatureAlgorithm.ES256, KeyRole.HOST)
        key_id, public_key, algorithm, role = public_key_of(jwk)
        assert (key_id, algorithm, role) == ('host-1', SignatureAlgorithm.ES256, KeyRole.HOST)
        assert public_key.public_numbers() == original.public_numbers()
        # end def

    def test_the_parameters_are_the_standard_ones(self) -> None:
        """A peer reads this with an ordinary JWK library (RFC 7517, RFC 8037); `alg` is the RFC 9864 name."""
        jwk = public_jwk('tool-1', generate_tool_key('tool-1').public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        assert (jwk['kty'], jwk['crv'], jwk['alg']) == ('OKP', 'Ed25519', 'Ed25519')
        assert jwk['kid'] == 'tool-1'
        # end def

    @pytest.mark.parametrize('member', ['x', 'y'])
    def test_key_material_of_the_wrong_length_is_refused_at_registration(self, member: str) -> None:
        """A fixed length is what stops a wrong encoding surfacing later as a forged signature."""
        jwk = public_jwk('host-1', _p256(), SignatureAlgorithm.ES256, KeyRole.HOST)
        raw = b64url_decode(jwk[member])
        assert raw is not None
        jwk[member] = b64url_encode(raw[:-3])
        with pytest.raises(ValueError, match='32 bytes'):
            public_key_of(jwk)
            # end with
        # end def

    def test_an_algorithm_this_version_does_not_define_is_refused(self) -> None:
        """§12.1 fixes the algorithm set; a new one arrives with a new spec_version, not in a key file."""
        jwk = public_jwk('tool-1', generate_tool_key('tool-1').public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        jwk['crv'] = 'Ed448'
        with pytest.raises(ValueError, match='§12.1'):
            public_key_of(jwk)
            # end with
        # end def

    def test_a_key_that_names_no_role_is_refused(self) -> None:
        """A set that does not say whose keys it holds can be loaded into the wrong registry (§5.2)."""
        jwk = public_jwk('tool-1', generate_tool_key('tool-1').public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        del jwk[ROLE_MEMBER]
        with pytest.raises(ValueError, match=ROLE_MEMBER):
            public_key_of(jwk)
            # end with
        # end def

    # end class


class TestTheThumbprint:
    """RFC 7638: the same key gives the same thumbprint, whatever the document around it says."""

    def test_it_ignores_everything_but_the_required_members(self) -> None:
        """A person comparing a key out of band must not see it change because a `kid` changed."""
        key = generate_tool_key('tool-1').public_key
        first = public_jwk('tool-1', key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        second = public_jwk('another-id', key, SignatureAlgorithm.ED25519, KeyRole.HOST)
        assert jwk_thumbprint(first) == jwk_thumbprint(second)
        # end def

    def test_two_keys_do_not_share_a_thumbprint(self) -> None:
        """Otherwise it would compare nothing."""
        first = public_jwk('a', generate_tool_key('a').public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        second = public_jwk('b', generate_tool_key('b').public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        assert jwk_thumbprint(first) != jwk_thumbprint(second)
        # end def

    # end class


class TestProvisioningARegistry:
    """The door one deployment provisions another's registry through."""

    def test_a_set_written_by_one_registry_loads_into_another(self) -> None:
        """This is what the two implementations actually do with each other."""
        source = KeyRegistry(KeyRole.TOOL)
        source.register_tool_key(generate_tool_key('tool-1'))
        source.register_tool_key(generate_tool_key('tool-2'))
        target = KeyRegistry(KeyRole.TOOL)
        target.load_jwks(source.to_jwks())
        assert target.to_jwks() == source.to_jwks()
        # end def

    def test_loading_adds_rather_than_replaces(self) -> None:
        """Rotation mints a fresh key_id (§10.9); dropping the old one breaks history, not rotates it."""
        registry = KeyRegistry(KeyRole.TOOL)
        registry.register_tool_key(generate_tool_key('tool-v1'))
        second = KeyRegistry(KeyRole.TOOL)
        second.register_tool_key(generate_tool_key('tool-v2'))
        registry.load_jwks(second.to_jwks())
        assert registry.get('tool-v1') is not None
        assert registry.get('tool-v2') is not None
        # end def

    def test_a_tool_set_is_refused_by_a_host_registry(self) -> None:
        """A tool key held as a host's lets a tool sign itself into the countersigned state (§5.2)."""
        tools = KeyRegistry(KeyRole.TOOL)
        tools.register_tool_key(generate_tool_key('tool-1'))
        with pytest.raises(ValueError, match='this registry holds host keys'):
            KeyRegistry(KeyRole.HOST).load_jwks(tools.to_jwks())
            # end with
        # end def

    def test_one_bad_key_leaves_the_registry_untouched(self) -> None:
        """A half-provisioned registry verifies some records and rejects others, for no stated reason."""
        source = KeyRegistry(KeyRole.TOOL)
        source.register_tool_key(generate_tool_key('tool-1'))
        document = source.to_jwks()
        document['keys'].append({**document['keys'][0], 'kid': 'tool-2', ROLE_MEMBER: 'host'})  # type: ignore[union-attr,index]
        target = KeyRegistry(KeyRole.TOOL)
        with pytest.raises(ValueError):
            target.load_jwks(document)
            # end with
        assert target.get('tool-1') is None
        # end def

    def test_a_document_that_is_not_a_set_is_refused(self) -> None:
        """A bare key, or a file of something else, is not a JWK Set (RFC 7517)."""
        with pytest.raises(ValueError, match='`keys`'):
            KeyRegistry(KeyRole.TOOL).load_jwks({'kty': 'OKP'})
            # end with
        # end def

    def test_a_revoked_entry_is_exported_revoked_and_loads_revoked(self) -> None:
        """§10.9: a peer provisioned from the set does not hold a revoked key as a live one."""
        source = KeyRegistry(KeyRole.TOOL)
        source.register_tool_key(generate_tool_key('tool-1'))
        source.register_tool_key(generate_tool_key('tool-2'))
        source.revoke('tool-1')
        document = source.to_jwks()
        target = KeyRegistry(KeyRole.TOOL)
        target.load_jwks(document)
        assert [key.get(REVOKED_MEMBER) for key in document['keys']] == [True, None]  # type: ignore[union-attr]
        assert target.current('tool-1') is None
        assert target.get('tool-1') is not None
        assert target.current('tool-2') is not None
        assert target.to_jwks() == document
        # end def

    def test_an_unrevoked_copy_does_not_lift_a_revocation(self) -> None:
        """Revocation is forward-only: loading an older export of the key leaves it revoked (§10.9)."""
        key = generate_tool_key('tool-1')
        older = KeyRegistry(KeyRole.TOOL)
        older.register_tool_key(key)
        registry = KeyRegistry(KeyRole.TOOL)
        registry.register_tool_key(key)
        registry.revoke('tool-1')
        registry.load_jwks(older.to_jwks())
        assert registry.current('tool-1') is None
        # end def

    def test_a_revocation_member_that_is_not_a_boolean_is_refused(self) -> None:
        """A string `"false"` is not a revocation state, and reading it either way would guess."""
        key = generate_tool_key('tool-1')
        jwk = public_jwk('tool-1', key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)
        with pytest.raises(ValueError, match=REVOKED_MEMBER):
            public_key_of({**jwk, REVOKED_MEMBER: 'false'})
            # end with
        # end def

    def test_revoking_a_key_id_never_registered_is_refused(self) -> None:
        """An operator who revokes a mistyped key_id must not believe the real key is revoked."""
        registry = KeyRegistry(KeyRole.TOOL)
        registry.register_tool_key(generate_tool_key('tool-1'))
        with pytest.raises(ValueError, match='tool-9'):
            registry.revoke('tool-9')
            # end with
        assert registry.current('tool-1') is not None
        # end def

    # end class


class TestTheStoredPrivateKey:
    """M2: a tool keeps one key across restarts instead of minting one per process (§10.9)."""

    def test_a_key_survives_being_written_and_read(self) -> None:
        """A key that does not survive the process leaves every signature it made uncheckable."""
        original = generate_tool_key('tool-1')
        restored = load_tool_key('tool-1', tool_key_pkcs8(original))
        assert restored.public_key.public_bytes_raw() == original.public_key.public_bytes_raw()
        # end def

    def test_pem_reads_as_well_as_der(self) -> None:
        """A deployment storing the key in a secret manager usually has it as PEM."""
        from cryptography.hazmat.primitives import serialization

        original = generate_tool_key('tool-1')
        pem = original.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert load_tool_key('tool-1', pem).public_key.public_bytes_raw() == original.public_key.public_bytes_raw()
        # end def

    def test_bytes_that_are_not_a_private_key_are_refused(self) -> None:
        """The refusal names the format, so an operator knows what to store instead."""
        with pytest.raises(ValueError, match='PKCS#8'):
            load_tool_key('tool-1', b'not a key')
            # end with
        # end def

    def test_a_key_of_another_algorithm_is_refused(self) -> None:
        """A tool signs Ed25519; a P-256 private key here means the deployment stored the wrong one."""
        from cryptography.hazmat.primitives import serialization

        p256 = generate_private_key(SECP256R1()).private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match='Ed25519'):
            load_tool_key('tool-1', p256)
            # end with
        # end def

    def test_an_empty_key_id_is_refused(self) -> None:
        """A registry entry binds a non-empty key_id (§5.1), so a key cannot carry an empty one."""
        with pytest.raises(ValueError, match='key_id'):
            load_tool_key('', tool_key_pkcs8(generate_tool_key('tool-1')))
            # end with
        # end def

    # end class
