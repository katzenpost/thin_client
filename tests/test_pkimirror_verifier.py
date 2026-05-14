"""Unit tests for the cert.Certificate verifier used by PkiMirrorClient.

The hybrid Falcon-padded-512-Ed25519 path is exercised end-to-end by the
integration tests against a live mixnet; hpqc's Python bindings are
verify-only, so we cannot synthesise a fresh hybrid signature here.
PyNaCl supplies Ed25519 signing, which is sufficient to exercise the
verifier's CBOR parsing, message reconstruction, scheme dispatch, hash
lookup, and threshold accounting against synthetic certificates."""

import os
import struct

import cbor2
import nacl.signing
import pytest

from hpqc.hash import sum256

from katzenpost_reticulum.pkimirror.dirauth_config import (
    DirauthConfig,
    DirauthIdentity,
)
from katzenpost_reticulum.pkimirror.errors import PkiMirrorVerificationError
from katzenpost_reticulum.pkimirror.verifier import verify_and_unwrap


def _signed_message(version: int, expiration: int, key_type: str, certified: bytes) -> bytes:
    return (
        struct.pack("<I", version)
        + struct.pack("<Q", expiration)
        + key_type.encode("ascii")
        + certified
    )


def _build_cert(version: int, expiration: int, key_type: str, certified: bytes, signatures: dict) -> bytes:
    return cbor2.dumps(
        {
            "Version": version,
            "Expiration": expiration,
            "KeyType": key_type,
            "Certified": certified,
            "Signatures": signatures,
        }
    )


def _ed25519_identity(name: str):
    signing_key = nacl.signing.SigningKey(os.urandom(32))
    verify_key = bytes(signing_key.verify_key)
    identity = DirauthIdentity(name=name, scheme="ED25519", pubkey=verify_key)
    return signing_key, identity


def _sign_for(signing_key: nacl.signing.SigningKey, msg: bytes) -> dict:
    verify_key = bytes(signing_key.verify_key)
    return {
        "PublicKeySum256": sum256(verify_key),
        "Payload": signing_key.sign(msg).signature,
    }


def test_no_dirauth_config_raises():
    cfg = DirauthConfig(identities=[])
    with pytest.raises(PkiMirrorVerificationError, match="no dirauth identities"):
        verify_and_unwrap(b"\xa0", cfg)


def test_non_map_cbor_raises():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    # CBOR-encoded integer; well-formed CBOR but not a map.
    with pytest.raises(PkiMirrorVerificationError, match="not a CBOR map"):
        verify_and_unwrap(cbor2.dumps(42), cfg)


def test_malformed_cbor_raises():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    # Truncated indefinite-length map header: not valid CBOR.
    with pytest.raises(PkiMirrorVerificationError, match="not valid CBOR"):
        verify_and_unwrap(b"\xbf\x61", cfg)


def test_wrong_version_raises():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    raw = _build_cert(
        version=99,
        expiration=10_000,
        key_type="Ed25519",
        certified=b"doc",
        signatures={},
    )
    with pytest.raises(PkiMirrorVerificationError, match="version"):
        verify_and_unwrap(raw, cfg)


def test_missing_signatures_field_raises():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    raw = cbor2.dumps(
        {
            "Version": 0,
            "Expiration": 10_000,
            "KeyType": "Ed25519",
            "Certified": b"doc",
            # Signatures omitted
        }
    )
    with pytest.raises(PkiMirrorVerificationError, match="missing field"):
        verify_and_unwrap(raw, cfg)


def test_signature_missing_for_identity_below_threshold():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    raw = _build_cert(
        version=0,
        expiration=10_000,
        key_type="Ed25519",
        certified=b"doc",
        signatures={},  # no signatures at all
    )
    with pytest.raises(PkiMirrorVerificationError, match="below threshold"):
        verify_and_unwrap(raw, cfg)


def test_invalid_signature_below_threshold():
    signing_key, identity = _ed25519_identity("auth1")
    other_key = nacl.signing.SigningKey(os.urandom(32))
    cfg = DirauthConfig(identities=[identity])
    msg = _signed_message(0, 10_000, "Ed25519", b"doc")
    # Sign with the wrong key so the signature payload will not verify
    # under the configured identity's public key, even though we place
    # it under the correct PublicKeySum256.
    bad_sig = other_key.sign(msg).signature
    raw = _build_cert(
        version=0,
        expiration=10_000,
        key_type="Ed25519",
        certified=b"doc",
        signatures={
            sum256(bytes(signing_key.verify_key)): {
                "PublicKeySum256": sum256(bytes(signing_key.verify_key)),
                "Payload": bad_sig,
            },
        },
    )
    with pytest.raises(PkiMirrorVerificationError, match="below threshold"):
        verify_and_unwrap(raw, cfg)


def test_valid_single_signature_meets_threshold_and_unwraps():
    signing_key, identity = _ed25519_identity("auth1")
    cfg = DirauthConfig(identities=[identity])
    certified = b"the verified document payload"
    msg = _signed_message(0, 10_000, "Ed25519", certified)
    raw = _build_cert(
        version=0,
        expiration=10_000,
        key_type="Ed25519",
        certified=certified,
        signatures={
            sum256(bytes(signing_key.verify_key)): _sign_for(signing_key, msg),
        },
    )
    out = verify_and_unwrap(raw, cfg)
    assert out == certified


def test_majority_threshold_with_three_identities():
    sk1, id1 = _ed25519_identity("auth1")
    sk2, id2 = _ed25519_identity("auth2")
    sk3, id3 = _ed25519_identity("auth3")
    cfg = DirauthConfig(identities=[id1, id2, id3])
    certified = b"three-party consensus document"
    msg = _signed_message(0, 20_000, "Ed25519", certified)
    # Two valid signatures out of three configured identities: threshold
    # is floor(3/2)+1 = 2, so this should verify.
    raw = _build_cert(
        version=0,
        expiration=20_000,
        key_type="Ed25519",
        certified=certified,
        signatures={
            sum256(bytes(sk1.verify_key)): _sign_for(sk1, msg),
            sum256(bytes(sk2.verify_key)): _sign_for(sk2, msg),
        },
    )
    assert verify_and_unwrap(raw, cfg) == certified


def test_below_majority_threshold_with_three_identities():
    sk1, id1 = _ed25519_identity("auth1")
    sk2, id2 = _ed25519_identity("auth2")
    sk3, id3 = _ed25519_identity("auth3")
    cfg = DirauthConfig(identities=[id1, id2, id3])
    certified = b"one-of-three is insufficient"
    msg = _signed_message(0, 20_000, "Ed25519", certified)
    raw = _build_cert(
        version=0,
        expiration=20_000,
        key_type="Ed25519",
        certified=certified,
        signatures={
            sum256(bytes(sk1.verify_key)): _sign_for(sk1, msg),
        },
    )
    with pytest.raises(PkiMirrorVerificationError, match="below threshold"):
        verify_and_unwrap(raw, cfg)


def test_unsupported_scheme_label_skipped():
    # An identity with an unsupported scheme label should be ignored
    # (logged), not verified against; the configured threshold then
    # cannot be met from the remaining identities and the call fails.
    sk1, id1 = _ed25519_identity("auth1")
    odd_identity = DirauthIdentity(
        name="auth2",
        scheme="DILITHIUM-3-Ed448",  # unknown to the verifier
        pubkey=b"\x00" * 32,
    )
    cfg = DirauthConfig(identities=[id1, odd_identity])
    certified = b"single-good-signature document"
    msg = _signed_message(0, 20_000, "Ed25519", certified)
    raw = _build_cert(
        version=0,
        expiration=20_000,
        key_type="Ed25519",
        certified=certified,
        signatures={
            sum256(bytes(sk1.verify_key)): _sign_for(sk1, msg),
        },
    )
    # Two identities configured, threshold floor(2/2)+1 = 2, only one
    # supported scheme: must fail.
    with pytest.raises(PkiMirrorVerificationError, match="below threshold"):
        verify_and_unwrap(raw, cfg)
