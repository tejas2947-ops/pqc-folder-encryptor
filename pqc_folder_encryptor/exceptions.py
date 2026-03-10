# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Typed exceptions for PQC Folder Encryptor.

Hierarchy:
  PQCError (base)
  +-- ContainerError (format/parsing)
  |   +-- InvalidMagicError
  |   +-- UnsupportedVersionError
  |   +-- UnknownSuiteError
  |   +-- CorruptedContainerError
  |   +-- TruncatedContainerError
  +-- CryptoError (cryptographic failures)
  |   +-- SignatureVerificationError
  |   +-- DecryptionError
  |   +-- KeyDerivationError
  +-- ManifestError (manifest validation)
  |   +-- ManifestIntegrityError
  |   +-- UnsafePathError
  +-- ValidationError (general validation)
      +-- EmptyFolderError
      +-- FileIntegrityError
      +-- PathEscapeError
      +-- IdentityVerificationError

Security note: error messages are designed to be informative for the user
without leaking internal state (e.g., which specific byte failed).
"""
from __future__ import annotations


class PQCError(Exception):
    """Base exception for all PQC Folder Encryptor errors."""


# -- Container errors --

class ContainerError(PQCError):
    """Errors related to container format and parsing."""


class InvalidMagicError(ContainerError):
    def __init__(self) -> None:
        super().__init__("Not a valid .pqc container")


class UnsupportedVersionError(ContainerError):
    def __init__(self, version: int) -> None:
        super().__init__(
            f"Unsupported format version: {version}. "
            f"This tool may need to be updated."
        )
        self.version = version


class UnknownSuiteError(ContainerError):
    def __init__(self, suite_id: int) -> None:
        super().__init__(f"Unknown cryptographic suite: 0x{suite_id:04x}")
        self.suite_id = suite_id


class CorruptedContainerError(ContainerError):
    def __init__(self, detail: str = "") -> None:
        msg = "Corrupted container structure"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class TruncatedContainerError(ContainerError):
    def __init__(self) -> None:
        super().__init__("Container truncated")


# -- Crypto errors --

class CryptoError(PQCError):
    """Errors related to cryptographic operations."""


class SignatureVerificationError(CryptoError):
    def __init__(self) -> None:
        super().__init__(
            "Signature verification failed \u2014 container may be tampered"
        )


class DecryptionError(CryptoError):
    def __init__(self, context: str = "payload") -> None:
        if context == "private_key":
            super().__init__("Incorrect passphrase")
        else:
            super().__init__("Decryption authentication failed")


class KeyDerivationError(CryptoError):
    def __init__(self, detail: str = "") -> None:
        msg = "Key derivation failed"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


# -- Manifest errors --

class ManifestError(PQCError):
    """Errors related to manifest validation."""


class ManifestIntegrityError(ManifestError):
    def __init__(self) -> None:
        super().__init__("Manifest integrity check failed")


class UnsafePathError(ManifestError):
    def __init__(self, path: str = "") -> None:
        # Do not reveal the full unsafe path in production messages
        super().__init__("Unsafe path detected in manifest")
        self.path = path


# -- Validation errors --

class ValidationError(PQCError):
    """General validation errors."""


class EmptyFolderError(ValidationError):
    def __init__(self) -> None:
        super().__init__("Source folder is empty")


class FileIntegrityError(ValidationError):
    def __init__(self, path: str) -> None:
        super().__init__(f"File integrity check failed: {path}")
        self.path = path


class PathEscapeError(ValidationError):
    def __init__(self) -> None:
        super().__init__("Path escape attempt blocked")


class IdentityVerificationError(ValidationError):
    def __init__(self) -> None:
        super().__init__(
            "Signer identity verification failed \u2014 "
            "container was not signed by the expected key"
        )


class KeyExpiredError(ValidationError):
    def __init__(self, key_id: str = "") -> None:
        msg = "Signing key has expired"
        if key_id:
            msg += f" ({key_id})"
        super().__init__(msg)


class KeyRevokedError(ValidationError):
    def __init__(self, key_id: str = "") -> None:
        msg = "Signing key has been revoked"
        if key_id:
            msg += f" ({key_id})"
        super().__init__(msg)
