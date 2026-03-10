# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Cryptographic suite configuration, constants, and enums.

Design principles:
- Each suite defines a COMPLETE set of algorithms (no mixing).
- Suite IDs are registered integers; unknown IDs cause hard failure.
- Adding a new suite requires only a new entry here + algorithm wiring in crypto.py.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Dict

# ---------------------------------------------------------------------------
# Magic bytes: first byte is 0x89 (non-ASCII) to detect binary/text
# corruption, followed by "PQC" for human identification.
# This is the same technique used by PNG (\x89PNG).
# ---------------------------------------------------------------------------
MAGIC = b"\x89PQC"
MAGIC_SIZE = 4

# ---------------------------------------------------------------------------
# Format version: incremented when the binary layout changes in an
# incompatible way.  Readers MUST reject unknown versions.
# ---------------------------------------------------------------------------
FORMAT_VERSION = 3
FORMAT_VERSION_PADDED = 4
SUPPORTED_FORMAT_VERSIONS = frozenset({3, 4})

# ---------------------------------------------------------------------------
# Maximum field sizes (defense against malformed containers)
# ---------------------------------------------------------------------------
MAX_FOLDER_NAME_LEN = 4096        # bytes
MAX_PAYLOAD_LEN = 100 * (1024 ** 3)  # 100 GB
MAX_SIG_LEN = 65536               # bytes

# ---------------------------------------------------------------------------
# Padding defaults (v3.1)
# ---------------------------------------------------------------------------
DEFAULT_PADDING_BLOCK_SIZE = 0        # 0 = no padding (v3 compatible)
PADDING_BLOCK_1MB = 1024 * 1024       # 1 MB blocks
PADDING_BLOCK_16MB = 16 * 1024 * 1024 # 16 MB blocks

# ---------------------------------------------------------------------------
# ML-DSA-65 sizes (FIPS 204) -- used when library does not export them
# ---------------------------------------------------------------------------
MLDSA65_PK_SIZE_FALLBACK = 1952
MLDSA65_SK_SIZE_FALLBACK = 4032


class SuiteId(enum.IntEnum):
    """Cryptographic suite identifiers.

    Each value maps to a complete, validated combination of algorithms.
    Unknown values MUST be rejected at parse time.
    """
    # Suite 1: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + Argon2id
    MLKEM768_MLDSA65_AES256GCM = 0x0001

    # Reserved for future:
    # MLKEM1024_MLDSA87_AES256GCM = 0x0002
    # MLKEM768_MLDSA65_CHACHA20POLY1305 = 0x0003


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id parameter set, stored in the container header."""
    time_cost: int = 3
    memory_cost: int = 65536   # KiB (64 MB)
    parallelism: int = 4
    hash_len: int = 32         # Determined by suite (AES-256 = 32 bytes)
    salt_len: int = 16


@dataclass(frozen=True)
class SuiteConfig:
    """Complete configuration for a cryptographic suite."""
    suite_id: SuiteId
    kem_algorithm: str
    sig_algorithm: str
    aead_algorithm: str
    kdf_algorithm: str
    kdf_hash: str
    nonce_len: int
    key_len: int
    argon2_defaults: Argon2Params

    # Domain separation labels for HKDF derivations.
    # Each derivation purpose gets a unique, versioned label to prevent
    # key confusion attacks where a key derived for one purpose is
    # accidentally (or maliciously) used for another.
    encryption_key_label: bytes
    manifest_binding_label: bytes


# ---------------------------------------------------------------------------
# Suite registry
# ---------------------------------------------------------------------------
SUITE_REGISTRY: Dict[SuiteId, SuiteConfig] = {
    SuiteId.MLKEM768_MLDSA65_AES256GCM: SuiteConfig(
        suite_id=SuiteId.MLKEM768_MLDSA65_AES256GCM,
        kem_algorithm="ML-KEM-768",
        sig_algorithm="ML-DSA-65",
        aead_algorithm="AES-256-GCM",
        kdf_algorithm="HKDF",
        kdf_hash="SHA-256",
        nonce_len=12,
        key_len=32,
        argon2_defaults=Argon2Params(),
        encryption_key_label=b"pqc-folder-encryptor.v1.encryption-key",
        manifest_binding_label=b"pqc-folder-encryptor.v1.manifest-binding",
    ),
}

DEFAULT_SUITE = SuiteId.MLKEM768_MLDSA65_AES256GCM


def get_suite(suite_id: int) -> SuiteConfig:
    """Look up a suite by numeric ID.  Raises ValueError if unknown."""
    try:
        sid = SuiteId(suite_id)
    except ValueError:
        raise ValueError(
            f"Unknown cryptographic suite ID: 0x{suite_id:04x}. "
            f"Supported: {[f'0x{s.value:04x}' for s in SuiteId]}"
        )
    return SUITE_REGISTRY[sid]
