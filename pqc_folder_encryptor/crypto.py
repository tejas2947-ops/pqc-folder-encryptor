# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Cryptographic operations with domain separation and suite abstraction.

All algorithm-specific code is isolated here behind suite-aware wrappers.
Adding a new suite requires wiring its primitives into the dispatch
functions below; no other module should import algorithm-specific symbols.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as _mlkem768_keygen,
    encrypt as _mlkem768_encap,
    decrypt as _mlkem768_decap,
    PUBLIC_KEY_SIZE as MLKEM768_PK_SIZE,
    SECRET_KEY_SIZE as MLKEM768_SK_SIZE,
    CIPHERTEXT_SIZE as MLKEM768_CT_SIZE,
)
from pqcrypto.sign.ml_dsa_65 import (
    generate_keypair as _mldsa65_keygen,
    sign as _mldsa65_sign,
    verify as _mldsa65_verify,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type as Argon2Type

from .config import (
    SuiteConfig, SuiteId, Argon2Params,
    MLDSA65_PK_SIZE_FALLBACK, MLDSA65_SK_SIZE_FALLBACK,
)
from .exceptions import DecryptionError, KeyDerivationError, SignatureVerificationError

# ---------------------------------------------------------------------------
# Try to import ML-DSA-65 size constants; fall back to FIPS 204 values.
# ---------------------------------------------------------------------------
try:
    from pqcrypto.sign.ml_dsa_65 import PUBLIC_KEY_SIZE as MLDSA65_PK_SIZE
except ImportError:
    MLDSA65_PK_SIZE = MLDSA65_PK_SIZE_FALLBACK

try:
    from pqcrypto.sign.ml_dsa_65 import SECRET_KEY_SIZE as MLDSA65_SK_SIZE
except ImportError:
    MLDSA65_SK_SIZE = MLDSA65_SK_SIZE_FALLBACK

# ---------------------------------------------------------------------------
# Size lookup tables, keyed by suite ID.
# ---------------------------------------------------------------------------
KEM_SIZES = {
    SuiteId.MLKEM768_MLDSA65_AES256GCM: {
        "pk": MLKEM768_PK_SIZE,
        "sk": MLKEM768_SK_SIZE,
        "ct": MLKEM768_CT_SIZE,
    },
}

SIG_SIZES = {
    SuiteId.MLKEM768_MLDSA65_AES256GCM: {
        "pk": MLDSA65_PK_SIZE,
        "sk": MLDSA65_SK_SIZE,
    },
}

GCM_TAG_SIZE = 16  # AES-GCM authentication tag


# ===================================================================
# KEM operations
# ===================================================================

def kem_generate_keypair(suite: SuiteConfig) -> Tuple[bytes, bytes]:
    """Generate a KEM key pair.  Returns (public_key, secret_key)."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        return _mlkem768_keygen()
    raise ValueError(f"No KEM implementation for suite {suite.suite_id!r}")


def kem_encapsulate(suite: SuiteConfig, pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate against a public key.  Returns (ciphertext, shared_secret)."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        return _mlkem768_encap(pk)
    raise ValueError(f"No KEM implementation for suite {suite.suite_id!r}")


def kem_decapsulate(suite: SuiteConfig, sk: bytes, ct: bytes) -> bytes:
    """Decapsulate with a secret key.  Returns shared_secret."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        return _mlkem768_decap(sk, ct)
    raise ValueError(f"No KEM implementation for suite {suite.suite_id!r}")


# ===================================================================
# Signature operations
# ===================================================================

def sig_generate_keypair(suite: SuiteConfig) -> Tuple[bytes, bytes]:
    """Generate a signing key pair.  Returns (public_key, secret_key)."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        return _mldsa65_keygen()
    raise ValueError(f"No signing implementation for suite {suite.suite_id!r}")


def sig_sign(suite: SuiteConfig, sk: bytes, message: bytes) -> bytes:
    """Sign a message.  Returns the signature bytes."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        return _mldsa65_sign(sk, message)
    raise ValueError(f"No signing implementation for suite {suite.suite_id!r}")


def sig_verify(
    suite: SuiteConfig, pk: bytes, message: bytes, signature: bytes,
) -> None:
    """Verify a signature.  Raises SignatureVerificationError on failure."""
    if suite.suite_id == SuiteId.MLKEM768_MLDSA65_AES256GCM:
        try:
            _mldsa65_verify(pk, message, signature)
        except Exception:
            raise SignatureVerificationError()
        return
    raise ValueError(f"No signing implementation for suite {suite.suite_id!r}")


# ===================================================================
# Key derivation with domain separation
# ===================================================================

def derive_key(
    shared_secret: bytes,
    label: bytes,
    length: int = 32,
    salt: bytes | None = None,
) -> bytes:
    """Derive a key via HKDF-SHA256 with explicit domain separation.

    The *label* (HKDF ``info``) ensures that keys derived for different
    purposes are cryptographically independent, even from the same
    shared secret.  This prevents key-confusion attacks.
    """
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=label,
        ).derive(shared_secret)
    except Exception as exc:
        raise KeyDerivationError(str(exc))


def derive_passphrase_key(
    passphrase: str,
    params: Argon2Params,
    salt: bytes | None = None,
) -> Tuple[bytes, bytes]:
    """Derive a symmetric key from a passphrase via Argon2id.

    Returns (derived_key, salt).  If *salt* is ``None``, a random salt
    is generated.
    """
    if salt is None:
        salt = secrets.token_bytes(params.salt_len)
    try:
        key = hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Argon2Type.ID,
        )
    except Exception as exc:
        raise KeyDerivationError(f"Argon2id: {exc}")
    return key, salt


# ===================================================================
# AEAD (AES-256-GCM)
# ===================================================================

def aead_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM.  Returns (nonce, ciphertext_with_tag)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes | None = None,
    context: str = "payload",
) -> bytes:
    """Decrypt with AES-256-GCM.

    *context* is used only for the error message on failure:
    ``"private_key"`` produces "Incorrect passphrase"; anything else
    produces "Decryption authentication failed".
    """
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        raise DecryptionError(context)


# ===================================================================
# Utility
# ===================================================================

def fingerprint(public_key: bytes) -> bytes:
    """SHA-256 fingerprint of a public key (32 bytes)."""
    return hashlib.sha256(public_key).digest()
