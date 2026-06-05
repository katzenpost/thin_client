"""Verification of cert.Certificate-wrapped Katzenpost PKI documents
against the dirauth identities configured for the pkimirror client.

The wire format mirrors the Go ``katzenpost/core/cert`` package.
A cert.Certificate is a CBOR map carrying Version, Expiration, KeyType,
Certified, and Signatures. The signed message that each dirauth
endorses is the byte concatenation
``u32-LE(Version) || u64-LE(Expiration) || KeyType-ASCII || Certified``.
Signatures are indexed by the BLAKE2b-256 hash of each signer's raw
public key bytes.
"""

from __future__ import annotations

import logging
import struct
from typing import Optional

import cbor2

from hpqc.hash import sum256
from hpqc.sign.ed25519 import Ed25519Scheme
from hpqc.sign.hybrid import FalconPadded512Ed25519

from katzenpost_reticulum.pkimirror.dirauth_config import (
    DirauthConfig,
    DirauthIdentity,
)
from katzenpost_reticulum.pkimirror.errors import PkiMirrorVerificationError

logger = logging.getLogger(__name__)

# CertVersion as declared by katzenpost/core/cert/cert.go.
_CERT_VERSION = 0

# Mapping from the PEM scheme label captured by the dirauth_config
# parser to the matching hpqc Python verifier. Labels are upper-cased
# at lookup time, matching the format katzenpost itself writes into
# the PEM marker line.
_SCHEMES_BY_LABEL = {
    "ED25519": Ed25519Scheme(),
    "FALCON-PADDED-512-ED25519": FalconPadded512Ed25519,
}


def _cert_signed_message(
    version: int,
    expiration: int,
    key_type: str,
    certified: bytes,
) -> bytes:
    return (
        struct.pack("<I", version)
        + struct.pack("<Q", expiration)
        + key_type.encode("ascii")
        + certified
    )


def _decode_certificate(raw: bytes) -> dict:
    try:
        cert = cbor2.loads(raw)
    except Exception as exc:
        raise PkiMirrorVerificationError(
            f"cert.Certificate is not valid CBOR: {exc}",
        ) from exc
    if not isinstance(cert, dict):
        raise PkiMirrorVerificationError("cert.Certificate is not a CBOR map")
    for field in ("Version", "Expiration", "KeyType", "Certified", "Signatures"):
        if field not in cert:
            raise PkiMirrorVerificationError(
                f"cert.Certificate missing field: {field}",
            )
    return cert


def _verifier_for_identity(identity: DirauthIdentity) -> Optional[object]:
    scheme = _SCHEMES_BY_LABEL.get(identity.scheme.upper())
    if scheme is None:
        logger.warning(
            "Dirauth %r uses unsupported signature scheme %r; "
            "cannot verify against this identity",
            identity.name,
            identity.scheme,
        )
        return None
    if len(identity.pubkey) != scheme.public_key_size:
        logger.warning(
            "Dirauth %r public key length %d does not match scheme %s expected size %d",
            identity.name,
            len(identity.pubkey),
            identity.scheme,
            scheme.public_key_size,
        )
        return None
    return scheme


def verify_and_unwrap(raw_cert: bytes, dirauth_config: DirauthConfig) -> bytes:
    """Verify the cert.Certificate wrapper against the configured dirauth
    identities and return the stripped Certified payload.

    A simple majority of configured dirauths must sign with valid
    signatures (floor(N/2)+1, matching the threshold the katzenpost
    voting protocol applies elsewhere). Raises
    :class:`PkiMirrorVerificationError` on any failure: malformed
    wrapper, mismatched cert version, signature payload missing, or
    insufficient valid signatures.
    """
    if not dirauth_config.identities:
        raise PkiMirrorVerificationError(
            "no dirauth identities configured; cannot verify",
        )

    cert = _decode_certificate(raw_cert)
    version = cert["Version"]
    if version != _CERT_VERSION:
        raise PkiMirrorVerificationError(
            f"cert.Certificate version {version!r} "
            f"does not match expected {_CERT_VERSION}",
        )
    expiration = cert["Expiration"]
    key_type = cert["KeyType"]
    certified = cert["Certified"]
    signatures = cert["Signatures"]

    if not isinstance(expiration, int):
        raise PkiMirrorVerificationError(
            "cert.Certificate Expiration is not an integer",
        )
    if not isinstance(key_type, str):
        raise PkiMirrorVerificationError(
            "cert.Certificate KeyType is not a string",
        )
    if not isinstance(certified, (bytes, bytearray)):
        raise PkiMirrorVerificationError(
            "cert.Certificate Certified is not bytes",
        )
    if not isinstance(signatures, dict):
        raise PkiMirrorVerificationError(
            "cert.Certificate Signatures is not a CBOR map",
        )

    msg = _cert_signed_message(version, expiration, key_type, bytes(certified))

    n = len(dirauth_config.identities)
    threshold = n // 2 + 1
    good = 0
    for identity in dirauth_config.identities:
        scheme = _verifier_for_identity(identity)
        if scheme is None:
            continue
        identity_hash = sum256(identity.pubkey)
        sig = signatures.get(identity_hash)
        if sig is None:
            logger.debug(
                "no signature from dirauth %r in the certificate",
                identity.name,
            )
            continue
        payload = sig.get("Payload") if isinstance(sig, dict) else None
        if not isinstance(payload, (bytes, bytearray)):
            logger.debug(
                "signature from dirauth %r has no Payload bytes",
                identity.name,
            )
            continue
        if scheme.verify(identity.pubkey, msg, bytes(payload)):
            good += 1
        else:
            logger.warning(
                "signature from dirauth %r failed verification",
                identity.name,
            )

    if good < threshold:
        raise PkiMirrorVerificationError(
            f"only {good} of {n} dirauth signatures verified, "
            f"below threshold {threshold}",
        )

    return bytes(certified)
