# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Fail-closed validation chain for container decryption.

Principle: **no file is written to disk** until ALL of the following
checks pass, in order:

::

    #   Check                         Abort message
    --  ----------------------------  ----------------------------------
    1   Magic bytes                   Not a valid .pqc container
    2   Format version                Unsupported format version
    3   Cryptographic suite           Unknown cryptographic suite
    4   Field lengths / consistency   Corrupted container structure
    5   Truncation detection          Container truncated
    6   Fingerprint consistency       Signing key fingerprint mismatch
    7   Signer identity (optional)    Signer identity verification failed
    8   Signature (ML-DSA-65)         Signature verification failed
    9   Passphrase -> SK decryption   Incorrect passphrase
    10  KEM decapsulation + KDF       Key derivation failed
    11  GCM authenticated decrypt     Decryption authentication failed
    12  Manifest parse + integrity    Manifest integrity check failed
    13  File hash verification        Manifest integrity check failed
    14  Path safety (no traversal)    Unsafe path detected in manifest
    15  Path escape check             Path escape attempt blocked

Steps 1-6 are performed by ``container.parse_container()``.
Steps 7-15 are performed by ``decrypt_and_extract()``.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .config import get_suite, Argon2Params, FORMAT_VERSION_PADDED
from .container import ContainerHeader, parse_container, unpack_payload, unpad_payload
from .crypto import (
    derive_passphrase_key,
    derive_key,
    aead_decrypt,
    kem_decapsulate,
)
from .manifest import (
    parse_manifest,
    validate_path_safety,
    verify_file_against_manifest,
)
from .signing import verify_container_signature, SignerIdentity
from .secure_memory import SecureBuffer
from .exceptions import (
    CorruptedContainerError,
    PathEscapeError,
)

ProgressCallback = Callable[[str, str, float], None]


def _null_progress(phase: str, detail: str, pct: float) -> None:
    pass


def decrypt_and_extract(
    container_data: bytes,
    passphrase: str,
    output_dir: str,
    *,
    identity: Optional[SignerIdentity] = None,
    progress: ProgressCallback = _null_progress,
) -> dict:
    """Decrypt, validate, and extract a .pqc container.

    Implements the full fail-closed validation chain.  Files are
    held in memory until every check passes; only then are they
    written to disk.

    Args:
        container_data: Raw bytes of the .pqc file.
        passphrase: User passphrase for Argon2id key derivation.
        output_dir: Base directory for extraction.
        identity: Optional signer identity verifier.
        progress: Optional ``(phase, detail, percent)`` callback.

    Returns:
        Dict with ``output_dir``, ``files``, ``signer_fingerprint``.

    Raises:
        InvalidMagicError, UnsupportedVersionError, UnknownSuiteError,
        CorruptedContainerError, TruncatedContainerError,
        IdentityVerificationError, SignatureVerificationError,
        DecryptionError, ManifestIntegrityError, UnsafePathError,
        PathEscapeError.
    """
    if identity is None:
        identity = SignerIdentity.integrity_only()

    # -- Steps 1-6: structural parsing (magic, version, suite, lengths,
    #    truncation, fingerprint) --
    progress("parse", "Validating container structure...", 5)
    header: ContainerHeader = parse_container(container_data)

    suite = get_suite(header.suite_id)

    # -- Step 7: signer identity (if configured) --
    progress("identity", "Checking signer identity...", 10)
    identity.verify_identity(header.sig_public_key)

    # -- Step 8: signature verification --
    progress("verify", "Verifying signature (ML-DSA-65)...", 15)
    verify_container_signature(
        suite,
        header.sig_public_key,
        header.authenticated_bytes,
        header.signature,
    )

    # -- Step 9: passphrase -> decrypt KEM secret key --
    progress("argon2", "Deriving passphrase key (Argon2id)...", 25)
    argon2_params = Argon2Params(
        time_cost=header.argon2_time,
        memory_cost=header.argon2_memory,
        parallelism=header.argon2_parallel,
    )
    ppk_raw, _ = derive_passphrase_key(passphrase, argon2_params, header.argon2_salt)
    sb_ppk = SecureBuffer(ppk_raw)

    try:
        progress("decrypt_sk", "Recovering private key...", 35)
        kem_sk_raw = aead_decrypt(
            bytes(sb_ppk), header.sk_nonce, header.encrypted_sk, context="private_key",
        )
    finally:
        sb_ppk.destroy()

    sb_kem_sk = SecureBuffer(kem_sk_raw)
    try:
        # -- Step 10: KEM decapsulation + key derivation --
        progress("decap", "ML-KEM-768 decapsulation...", 45)
        shared_secret_raw = kem_decapsulate(suite, bytes(sb_kem_sk), header.kem_ciphertext)
    finally:
        sb_kem_sk.destroy()

    sb_ss = SecureBuffer(shared_secret_raw)
    try:
        progress("kdf", "Deriving encryption key (HKDF)...", 50)
        encryption_key_raw = derive_key(bytes(sb_ss), suite.encryption_key_label)
    finally:
        sb_ss.destroy()

    sb_ek = SecureBuffer(encryption_key_raw)
    try:
        # -- Step 11: authenticated decryption of payload --
        progress("decrypt", "Decrypting payload (AES-256-GCM)...", 55)
        payload = aead_decrypt(
            bytes(sb_ek), header.data_nonce, header.encrypted_payload,
        )
    finally:
        sb_ek.destroy()

    # -- Step 11b: remove padding if format version 4 --
    if header.format_version == FORMAT_VERSION_PADDED:
        progress("unpad", "Removing padding...", 60)
        payload = unpad_payload(payload)

    # -- Step 12: parse manifest --
    progress("manifest", "Validating manifest...", 65)
    if len(payload) < 4:
        raise CorruptedContainerError("Payload too short for manifest")

    manifest_len = struct.unpack("!I", payload[:4])[0]
    if 4 + manifest_len > len(payload):
        raise CorruptedContainerError("Manifest length exceeds payload")

    manifest_bytes = payload[4:4 + manifest_len]
    manifest_entries = parse_manifest(manifest_bytes)

    # -- Step 13: extract file blobs and verify against manifest --
    progress("validate", "Verifying file integrity...", 70)
    file_blobs = unpack_payload(payload, len(manifest_entries))

    files_data: List[Tuple[str, bytes]] = []
    for entry, blob in zip(manifest_entries, file_blobs):
        verify_file_against_manifest(
            entry["path"], blob, entry["hash"], entry["size"],
        )
        files_data.append((entry["path"], blob))

    # -- Steps 14-15: path safety --
    progress("paths", "Validating extraction paths...", 75)
    out_path = Path(output_dir) / header.folder_name
    out_resolved = out_path.resolve()

    for rel_path, _ in files_data:
        validate_path_safety(rel_path)
        target = (out_path / rel_path).resolve()
        # Ensure the resolved target is within the output directory
        if not str(target).startswith(str(out_resolved)):
            raise PathEscapeError()

    # ================================================================
    # ALL VALIDATIONS PASSED — safe to write files to disk.
    # ================================================================
    progress("extract", "Extracting files...", 80)
    out_path.mkdir(parents=True, exist_ok=True)

    for i, (rel_path, data) in enumerate(files_data):
        pct = 80 + (i / max(len(files_data), 1)) * 18
        progress("extract", rel_path, pct)
        target = out_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    progress("done", f"Extracted {len(files_data)} files to {out_path}", 100)

    return {
        "output_dir": str(out_path),
        "files": len(files_data),
        "signer_fingerprint": header.sig_pk_fingerprint.hex(),
    }
