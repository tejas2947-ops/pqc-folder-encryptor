# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Binary container format (.pqc v3) serialization and parsing.

All multi-byte integers are **big-endian** (network byte order).

Container layout
================

::

    +-------------------------------------------------------------+
    | HEADER (8 bytes, fixed)                                     |
    |   [0:4]   magic            b"\\x89PQC"                      |
    |   [4:6]   format_version   uint16 BE                       |
    |   [6:8]   suite_id         uint16 BE                       |
    +-------------------------------------------------------------+
    | KDF_PARAMS (28 bytes, fixed for Argon2id)                   |
    |   [8:24]  argon2_salt      16 bytes                        |
    |   [24:28] argon2_memory    uint32 BE (KiB)                 |
    |   [28:32] argon2_time      uint32 BE                       |
    |   [32:36] argon2_parallel  uint32 BE                       |
    +-------------------------------------------------------------+
    | KEM_DATA (variable)                                         |
    |   kem_ct_len               uint32 BE                       |
    |   kem_ciphertext           kem_ct_len bytes                |
    +-------------------------------------------------------------+
    | ENCRYPTED_SK (variable)                                     |
    |   sk_nonce                 12 bytes                         |
    |   esk_len                  uint32 BE                       |
    |   encrypted_sk             esk_len bytes                   |
    +-------------------------------------------------------------+
    | PUBLIC_KEYS (variable)                                      |
    |   kem_pk_len               uint32 BE                       |
    |   kem_public_key           kem_pk_len bytes                |
    |   sig_pk_len               uint32 BE                       |
    |   sig_public_key           sig_pk_len bytes                |
    +-------------------------------------------------------------+
    | METADATA (variable)                                         |
    |   sig_pk_fingerprint       32 bytes (SHA-256 of sig PK)    |
    |   folder_name_len          uint32 BE                       |
    |   folder_name              folder_name_len bytes (UTF-8)   |
    +-------------------------------------------------------------+
    | ENCRYPTED_PAYLOAD (variable)                                |
    |   data_nonce               12 bytes                         |
    |   payload_len              uint64 BE                       |
    |   encrypted_payload        payload_len bytes (AES-256-GCM) |
    +-------------------------------------------------------------+
    ^^^^^^^^^^^^^^^^ authenticated region (signed) ^^^^^^^^^^^^^^^^

    +-------------------------------------------------------------+
    | SIGNATURE (variable)                                        |
    |   sig_len                  uint32 BE                       |
    |   signature                sig_len bytes (ML-DSA-65)       |
    +-------------------------------------------------------------+

Signature coverage
==================
The ML-DSA-65 signature covers **all bytes from offset 0 through the
end of encrypted_payload** (exclusive of the SIGNATURE section).

This protects against:
  - Header/metadata tampering
  - Algorithm confusion / downgrade attacks
  - Ciphertext substitution
  - KEM ciphertext swapping
  - Structure truncation or extension

Decrypted payload structure
===========================
::

    manifest_len     uint32 BE
    manifest_json    manifest_len bytes (canonical JSON)
    [for each file in manifest order:]
        file_len     uint32 BE
        file_data    file_len bytes
"""
from __future__ import annotations

import io
import secrets
import struct
from dataclasses import dataclass

from .config import (
    MAGIC, MAGIC_SIZE, FORMAT_VERSION, FORMAT_VERSION_PADDED,
    SUPPORTED_FORMAT_VERSIONS,
    MAX_FOLDER_NAME_LEN, MAX_PAYLOAD_LEN, MAX_SIG_LEN,
    SuiteId, get_suite,
)
from .crypto import fingerprint as compute_fingerprint, KEM_SIZES, SIG_SIZES, GCM_TAG_SIZE
from .manifest import validate_folder_name
from .exceptions import (
    InvalidMagicError,
    UnsupportedVersionError,
    UnknownSuiteError,
    CorruptedContainerError,
    TruncatedContainerError,
)


@dataclass
class ContainerHeader:
    """All parsed fields from a .pqc v3 container."""
    format_version: int
    suite_id: int
    argon2_salt: bytes
    argon2_memory: int
    argon2_time: int
    argon2_parallel: int
    kem_ciphertext: bytes
    sk_nonce: bytes
    encrypted_sk: bytes
    kem_public_key: bytes
    sig_public_key: bytes
    sig_pk_fingerprint: bytes
    folder_name: str
    data_nonce: bytes
    encrypted_payload: bytes
    signature: bytes
    authenticated_bytes: bytes  # all bytes covered by the signature


# ===================================================================
# Serialization
# ===================================================================

def build_authenticated_region(
    *,
    suite_id: SuiteId,
    argon2_salt: bytes,
    argon2_memory: int,
    argon2_time: int,
    argon2_parallel: int,
    kem_ciphertext: bytes,
    sk_nonce: bytes,
    encrypted_sk: bytes,
    kem_public_key: bytes,
    sig_public_key: bytes,
    folder_name: str,
    data_nonce: bytes,
    encrypted_payload: bytes,
    format_version: int = FORMAT_VERSION,
) -> bytes:
    """Build the authenticated region (everything the signature covers).

    This is deterministic: same inputs always produce the same bytes.
    """
    buf = io.BytesIO()

    # HEADER
    buf.write(MAGIC)
    buf.write(struct.pack("!H", format_version))
    buf.write(struct.pack("!H", suite_id.value))

    # KDF_PARAMS
    buf.write(argon2_salt)
    buf.write(struct.pack("!I", argon2_memory))
    buf.write(struct.pack("!I", argon2_time))
    buf.write(struct.pack("!I", argon2_parallel))

    # KEM_DATA
    buf.write(struct.pack("!I", len(kem_ciphertext)))
    buf.write(kem_ciphertext)

    # ENCRYPTED_SK
    buf.write(sk_nonce)
    buf.write(struct.pack("!I", len(encrypted_sk)))
    buf.write(encrypted_sk)

    # PUBLIC_KEYS
    buf.write(struct.pack("!I", len(kem_public_key)))
    buf.write(kem_public_key)
    buf.write(struct.pack("!I", len(sig_public_key)))
    buf.write(sig_public_key)

    # METADATA
    buf.write(compute_fingerprint(sig_public_key))
    fname_bytes = folder_name.encode("utf-8")
    buf.write(struct.pack("!I", len(fname_bytes)))
    buf.write(fname_bytes)

    # ENCRYPTED_PAYLOAD
    buf.write(data_nonce)
    buf.write(struct.pack("!Q", len(encrypted_payload)))
    buf.write(encrypted_payload)

    return buf.getvalue()


def finalize_container(auth_region: bytes, signature: bytes) -> bytes:
    """Append the signature section to the authenticated region."""
    buf = io.BytesIO()
    buf.write(auth_region)
    buf.write(struct.pack("!I", len(signature)))
    buf.write(signature)
    return buf.getvalue()


# ===================================================================
# Parsing
# ===================================================================

def _read_exact(stream: io.BytesIO, n: int) -> bytes:
    """Read exactly *n* bytes; raise TruncatedContainerError on short read."""
    data = stream.read(n)
    if len(data) != n:
        raise TruncatedContainerError()
    return data


def _read_u16(stream: io.BytesIO) -> int:
    return struct.unpack("!H", _read_exact(stream, 2))[0]


def _read_u32(stream: io.BytesIO) -> int:
    return struct.unpack("!I", _read_exact(stream, 4))[0]


def _read_u64(stream: io.BytesIO) -> int:
    return struct.unpack("!Q", _read_exact(stream, 8))[0]


def parse_container(data: bytes) -> ContainerHeader:
    """Parse a .pqc v3 container, performing structural validation.

    Validates:
      - Magic bytes
      - Format version (must be in SUPPORTED_FORMAT_VERSIONS)
      - Suite ID (must be registered)
      - Argon2 parameters (within sane bounds)
      - Field lengths (must match expected sizes for the suite)
      - Signing-key fingerprint consistency
      - No trailing data after signature

    Does NOT perform cryptographic validation (signature, decryption).
    """
    stream = io.BytesIO(data)

    # -- HEADER --
    magic = _read_exact(stream, MAGIC_SIZE)
    if magic != MAGIC:
        raise InvalidMagicError()

    format_version = _read_u16(stream)
    if format_version not in SUPPORTED_FORMAT_VERSIONS:
        raise UnsupportedVersionError(format_version)

    suite_id_raw = _read_u16(stream)
    try:
        suite_cfg = get_suite(suite_id_raw)
    except ValueError:
        raise UnknownSuiteError(suite_id_raw)

    # -- KDF_PARAMS --
    argon2_salt = _read_exact(stream, 16)

    argon2_memory = _read_u32(stream)
    if argon2_memory < 1024 or argon2_memory > 16 * 1024 * 1024:
        raise CorruptedContainerError("Argon2 memory out of range")

    argon2_time = _read_u32(stream)
    if argon2_time < 1 or argon2_time > 1000:
        raise CorruptedContainerError("Argon2 time out of range")

    argon2_parallel = _read_u32(stream)
    if argon2_parallel < 1 or argon2_parallel > 256:
        raise CorruptedContainerError("Argon2 parallelism out of range")

    # -- KEM_DATA --
    kem_ct_len = _read_u32(stream)
    expected_ct = KEM_SIZES[suite_cfg.suite_id]["ct"]
    if kem_ct_len != expected_ct:
        raise CorruptedContainerError("KEM ciphertext length mismatch")
    kem_ciphertext = _read_exact(stream, kem_ct_len)

    # -- ENCRYPTED_SK --
    sk_nonce = _read_exact(stream, 12)
    esk_len = _read_u32(stream)
    expected_esk = KEM_SIZES[suite_cfg.suite_id]["sk"] + GCM_TAG_SIZE
    if esk_len != expected_esk:
        raise CorruptedContainerError("Encrypted secret key length mismatch")
    encrypted_sk = _read_exact(stream, esk_len)

    # -- PUBLIC_KEYS --
    kem_pk_len = _read_u32(stream)
    expected_pk = KEM_SIZES[suite_cfg.suite_id]["pk"]
    if kem_pk_len != expected_pk:
        raise CorruptedContainerError("KEM public key length mismatch")
    kem_public_key = _read_exact(stream, kem_pk_len)

    sig_pk_len = _read_u32(stream)
    expected_sig_pk = SIG_SIZES[suite_cfg.suite_id]["pk"]
    if sig_pk_len != expected_sig_pk:
        raise CorruptedContainerError("Signing public key length mismatch")
    sig_public_key = _read_exact(stream, sig_pk_len)

    # -- METADATA --
    sig_pk_fp = _read_exact(stream, 32)
    actual_fp = compute_fingerprint(sig_public_key)
    if sig_pk_fp != actual_fp:
        raise CorruptedContainerError("Signing key fingerprint mismatch")

    folder_name_len = _read_u32(stream)
    if folder_name_len > MAX_FOLDER_NAME_LEN:
        raise CorruptedContainerError("Folder name too long")
    folder_name_bytes = _read_exact(stream, folder_name_len)
    try:
        folder_name = folder_name_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CorruptedContainerError("Invalid folder name encoding")
    validate_folder_name(folder_name)

    # -- ENCRYPTED_PAYLOAD --
    data_nonce = _read_exact(stream, 12)
    payload_len = _read_u64(stream)
    if payload_len > MAX_PAYLOAD_LEN:
        raise CorruptedContainerError("Payload exceeds maximum size")
    encrypted_payload = _read_exact(stream, payload_len)

    # End of authenticated region
    auth_end = stream.tell()
    authenticated_bytes = data[:auth_end]

    # -- SIGNATURE --
    sig_len = _read_u32(stream)
    if sig_len > MAX_SIG_LEN:
        raise CorruptedContainerError("Signature too large")
    signature = _read_exact(stream, sig_len)

    # Reject trailing data
    if stream.read(1):
        raise CorruptedContainerError("Unexpected trailing data")

    return ContainerHeader(
        format_version=format_version,
        suite_id=suite_id_raw,
        argon2_salt=argon2_salt,
        argon2_memory=argon2_memory,
        argon2_time=argon2_time,
        argon2_parallel=argon2_parallel,
        kem_ciphertext=kem_ciphertext,
        sk_nonce=sk_nonce,
        encrypted_sk=encrypted_sk,
        kem_public_key=kem_public_key,
        sig_public_key=sig_public_key,
        sig_pk_fingerprint=sig_pk_fp,
        folder_name=folder_name,
        data_nonce=data_nonce,
        encrypted_payload=encrypted_payload,
        signature=signature,
        authenticated_bytes=authenticated_bytes,
    )


def pack_payload(manifest_bytes: bytes, file_blobs: list[bytes]) -> bytes:
    """Pack manifest + file blobs into the cleartext payload.

    Layout::

        manifest_len  (uint32 BE)
        manifest_json (manifest_len bytes)
        [for each blob:]
            blob_len  (uint32 BE)
            blob_data (blob_len bytes)
    """
    parts: list[bytes] = [
        struct.pack("!I", len(manifest_bytes)),
        manifest_bytes,
    ]
    for blob in file_blobs:
        parts.append(struct.pack("!I", len(blob)))
        parts.append(blob)
    return b"".join(parts)


def unpack_payload(payload: bytes, expected_count: int) -> list[bytes]:
    """Unpack file blobs from the cleartext payload.

    Returns a list of raw file data in manifest order.
    """
    offset = 0

    # Skip manifest (already parsed separately)
    if offset + 4 > len(payload):
        raise CorruptedContainerError("Payload too short for manifest length")
    manifest_len = struct.unpack("!I", payload[offset:offset + 4])[0]
    offset += 4 + manifest_len

    blobs: list[bytes] = []
    for _ in range(expected_count):
        if offset + 4 > len(payload):
            raise CorruptedContainerError("Payload truncated in file data")
        blob_len = struct.unpack("!I", payload[offset:offset + 4])[0]
        offset += 4
        if offset + blob_len > len(payload):
            raise CorruptedContainerError("Payload truncated in file data")
        blobs.append(payload[offset:offset + blob_len])
        offset += blob_len

    if offset != len(payload):
        raise CorruptedContainerError("Unexpected data after file entries")

    return blobs


# ===================================================================
# Payload padding (v3.1 — format version 4)
# ===================================================================

def pad_payload(payload: bytes, block_size: int) -> bytes:
    """Pad payload to the next multiple of *block_size*.

    Layout::

        original_length  uint64 BE
        original_payload (original_length bytes)
        random_padding   (to fill block boundary)

    The length prefix and random padding are inside the AES-GCM
    ciphertext, so they are integrity-protected.
    """
    length_prefix = struct.pack("!Q", len(payload))
    total = len(length_prefix) + len(payload)
    pad_needed = block_size - (total % block_size)
    if pad_needed == 0:
        pad_needed = block_size  # always add at least one block
    padding = secrets.token_bytes(pad_needed)
    return length_prefix + payload + padding


def unpad_payload(padded: bytes) -> bytes:
    """Remove padding added by :func:`pad_payload`."""
    if len(padded) < 8:
        raise CorruptedContainerError("Padded payload too short")
    original_len = struct.unpack("!Q", padded[:8])[0]
    if 8 + original_len > len(padded):
        raise CorruptedContainerError("Invalid padding length")
    return padded[8:8 + original_len]
