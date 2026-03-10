# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Signing, verification, and signer identity model.

Identity vs. integrity
======================

A self-signed container proves that the content has not been modified
since the signer created it (**integrity**), but it does NOT prove
WHO the signer is (**identity**).  The signing key is inside the
container, so an attacker who replaces the entire container can also
replace the key.

This module provides several identity verification modes to address
this gap:

=================  =====================================================
Mode               Description
=================  =====================================================
integrity_only     No identity check; only self-consistency.
fingerprint        Verify against a hex fingerprint (SHA-256 of PK).
public_key         Verify against a public key file on disk.
trust_store        Verify against a directory of ``.pub`` key files.
=================  =====================================================

Recommended deployment:
  - For personal use: ``integrity_only`` is acceptable.
  - For team use: distribute signing public keys out-of-band and
    use ``public_key`` or ``trust_store`` mode.
  - For automation: pin the expected fingerprint in configuration.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional, Set, Dict

from .config import SuiteConfig
from .crypto import sig_sign as _sig_sign, sig_verify as _sig_verify, fingerprint
from .exceptions import IdentityVerificationError


class SignerIdentity:
    """Configurable identity verifier for container signers."""

    def __init__(
        self,
        mode: str,
        expected_fingerprint: Optional[bytes] = None,
        expected_public_key: Optional[bytes] = None,
        trusted_fingerprints: Optional[Set[bytes]] = None,
        trusted_keys: Optional[Dict[bytes, bytes]] = None,
    ) -> None:
        self.mode = mode
        self.expected_fingerprint = expected_fingerprint
        self.expected_public_key = expected_public_key
        self.trusted_fingerprints = trusted_fingerprints or set()
        self.trusted_keys = trusted_keys or {}

    # -- Factory methods --

    @staticmethod
    def integrity_only() -> SignerIdentity:
        """No identity verification; only self-consistency."""
        return SignerIdentity(mode="integrity_only")

    @staticmethod
    def from_fingerprint(hex_fingerprint: str) -> SignerIdentity:
        """Verify against a known SHA-256 fingerprint (hex string)."""
        return SignerIdentity(
            mode="fingerprint",
            expected_fingerprint=bytes.fromhex(hex_fingerprint),
        )

    @staticmethod
    def from_public_key_file(path: str) -> SignerIdentity:
        """Verify against a public key stored in a file."""
        pk_data = Path(path).read_bytes()
        return SignerIdentity(
            mode="public_key",
            expected_public_key=pk_data,
            expected_fingerprint=hashlib.sha256(pk_data).digest(),
        )

    @staticmethod
    def from_trust_store(directory: str) -> SignerIdentity:
        """Verify against any key in a directory of ``.pub`` key files.

        Supports both raw key files and JSON-envelope files with
        metadata (expiry, revocation, labels).  See
        :mod:`pqc_folder_encryptor.key_management` for the envelope format.
        """
        from .key_management import load_key_file

        trust_dir = Path(directory)
        if not trust_dir.is_dir():
            raise FileNotFoundError(f"Trust store not found: {directory}")
        fps: Set[bytes] = set()
        keys: Dict[bytes, bytes] = {}
        for kf in trust_dir.glob("*.pub"):
            meta = load_key_file(kf)
            # Skip revoked or expired keys
            if not meta.is_valid:
                continue
            fps.add(meta.fingerprint)
            keys[meta.fingerprint] = meta.public_key
        return SignerIdentity(
            mode="trust_store",
            trusted_fingerprints=fps,
            trusted_keys=keys,
        )

    # -- Verification --

    def verify_identity(self, sig_public_key: bytes) -> None:
        """Check the signer's public key against the configured identity.

        Raises IdentityVerificationError if the check fails.
        Does nothing in ``integrity_only`` mode.
        """
        if self.mode == "integrity_only":
            return

        fp = hashlib.sha256(sig_public_key).digest()

        if self.mode == "fingerprint":
            if fp != self.expected_fingerprint:
                raise IdentityVerificationError()
        elif self.mode == "public_key":
            if sig_public_key != self.expected_public_key:
                raise IdentityVerificationError()
        elif self.mode == "trust_store":
            if fp not in self.trusted_fingerprints:
                raise IdentityVerificationError()
        else:
            raise IdentityVerificationError()


def sign_authenticated_region(
    suite: SuiteConfig,
    signing_sk: bytes,
    authenticated_bytes: bytes,
) -> bytes:
    """Sign the authenticated region of a container."""
    return _sig_sign(suite, signing_sk, authenticated_bytes)


def verify_container_signature(
    suite: SuiteConfig,
    signing_pk: bytes,
    authenticated_bytes: bytes,
    signature: bytes,
) -> None:
    """Verify the ML-DSA-65 signature over the authenticated region.

    Raises SignatureVerificationError on failure.
    """
    _sig_verify(suite, signing_pk, authenticated_bytes, signature)
