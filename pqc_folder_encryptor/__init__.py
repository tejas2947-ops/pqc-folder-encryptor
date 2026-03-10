# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
PQC Folder Encryptor — post-quantum encryption for directories.

Public API::

    from pqc_folder_encryptor import encrypt_folder, decrypt_folder

    # Encrypt
    result = encrypt_folder("my_folder", "my_folder.pqc", "passphrase")

    # Decrypt
    result = decrypt_folder("my_folder.pqc", "output_dir", "passphrase")
"""
from __future__ import annotations

__version__ = "3.1.0"

import struct
from pathlib import Path
from typing import Callable, Optional

from .config import (
    DEFAULT_SUITE,
    FORMAT_VERSION,
    FORMAT_VERSION_PADDED,
    SuiteId,
    get_suite,
)
from .crypto import (
    kem_generate_keypair,
    kem_encapsulate,
    sig_generate_keypair,
    derive_key,
    derive_passphrase_key,
    aead_encrypt,
    fingerprint,
)
from .manifest import generate_manifest, validate_path_safety, validate_folder_name
from .container import build_authenticated_region, finalize_container, pack_payload, pad_payload
from .signing import sign_authenticated_region, SignerIdentity
from .validation import decrypt_and_extract
from .exceptions import EmptyFolderError
from .secure_memory import SecureBuffer

ProgressCallback = Callable[[str, str, float], None]


def _null_progress(phase: str, detail: str, pct: float) -> None:
    pass


def encrypt_folder(
    source_dir: str,
    output_path: str,
    passphrase: str,
    progress: ProgressCallback = _null_progress,
    *,
    suite_id: SuiteId = DEFAULT_SUITE,
    padding: int = 0,
) -> dict:
    """Encrypt a directory into a .pqc container.

    Args:
        source_dir: Path to the folder to encrypt.
        output_path: Path for the output .pqc file.
        passphrase: User passphrase for key protection.
        progress: Optional ``(phase, detail, percent)`` callback.
        suite_id: Cryptographic suite to use (default: ML-KEM-768 suite).

    Returns:
        Dict with ``output``, ``files``, ``input_size``, ``output_size``.
    """
    suite = get_suite(suite_id)
    folder = Path(source_dir)

    # Collect files
    files = sorted([
        (str(f.relative_to(folder)), f)
        for f in folder.rglob("*") if f.is_file()
    ])
    if not files:
        raise EmptyFolderError()

    total_size = sum(f.stat().st_size for _, f in files)
    progress("init", f"{len(files)} files \u2014 {total_size:,} bytes", 2)

    # -- Key generation --
    progress("keygen", f"{suite.kem_algorithm}...", 5)
    kem_pk, kem_sk_raw = kem_generate_keypair(suite)

    progress("keygen", f"{suite.sig_algorithm}...", 8)
    sig_pk, sig_sk_raw = sig_generate_keypair(suite)

    # Wrap sensitive keys in SecureBuffers for cleanup
    sb_kem_sk = SecureBuffer(kem_sk_raw)
    sb_sig_sk = SecureBuffer(sig_sk_raw)
    try:
        # -- KEM encapsulation --
        progress("encap", "Encapsulating...", 10)
        kem_ct, shared_secret_raw = kem_encapsulate(suite, kem_pk)
        sb_ss = SecureBuffer(shared_secret_raw)

        try:
            # -- Key derivation with domain separation --
            progress("kdf", "HKDF \u2192 encryption key...", 12)
            encryption_key_raw = derive_key(bytes(sb_ss), suite.encryption_key_label)
            sb_ek = SecureBuffer(encryption_key_raw)
        finally:
            sb_ss.destroy()

        try:
            # -- Protect KEM secret key with passphrase --
            progress("argon2", "Deriving passphrase key (Argon2id)...", 15)
            ppk_raw, argon2_salt = derive_passphrase_key(
                passphrase, suite.argon2_defaults,
            )
            sb_ppk = SecureBuffer(ppk_raw)

            try:
                sk_nonce, encrypted_sk = aead_encrypt(bytes(sb_ppk), bytes(sb_kem_sk))
            finally:
                sb_ppk.destroy()

            # -- Read files and build manifest --
            n = len(files)
            file_entries = []
            file_blobs = []
            for i, (rel, fp) in enumerate(files):
                progress("read", rel, 20 + (i / n) * 40)
                safe_rel = validate_path_safety(rel)
                data = fp.read_bytes()
                file_entries.append((safe_rel, data))
                file_blobs.append(data)

            progress("manifest", "Building manifest...", 62)
            manifest_bytes = generate_manifest(file_entries)

            # -- Pack and encrypt payload --
            progress("pack", "Packing payload...", 65)
            payload = pack_payload(manifest_bytes, file_blobs)

            if padding > 0:
                progress("pad", f"Padding to {padding // 1024} KB blocks...", 68)
                payload = pad_payload(payload, padding)

            progress("encrypt", f"{suite.aead_algorithm}...", 70)
            data_nonce, encrypted_payload = aead_encrypt(bytes(sb_ek), payload)
        finally:
            sb_ek.destroy()

        # -- Build authenticated region --
        progress("build", "Building container...", 78)
        folder_name = validate_folder_name(folder.name)
        fv = FORMAT_VERSION_PADDED if padding > 0 else FORMAT_VERSION

        auth_region = build_authenticated_region(
            suite_id=suite.suite_id,
            argon2_salt=argon2_salt,
            argon2_memory=suite.argon2_defaults.memory_cost,
            argon2_time=suite.argon2_defaults.time_cost,
            argon2_parallel=suite.argon2_defaults.parallelism,
            kem_ciphertext=kem_ct,
            sk_nonce=sk_nonce,
            encrypted_sk=encrypted_sk,
            kem_public_key=kem_pk,
            sig_public_key=sig_pk,
            folder_name=folder_name,
            data_nonce=data_nonce,
            encrypted_payload=encrypted_payload,
            format_version=fv,
        )

        # -- Sign the entire authenticated region --
        progress("sign", f"{suite.sig_algorithm}...", 85)
        signature = sign_authenticated_region(suite, bytes(sb_sig_sk), auth_region)
    finally:
        sb_kem_sk.destroy()
        sb_sig_sk.destroy()

    # -- Finalize and write --
    progress("write", "Writing .pqc file...", 90)
    container = finalize_container(auth_region, signature)

    out = Path(output_path)
    out.write_bytes(container)

    output_size = out.stat().st_size
    progress("done", f"OK {out.name} ({output_size:,} bytes)", 100)

    return {
        "output": str(out),
        "files": len(files),
        "input_size": total_size,
        "output_size": output_size,
        "signer_fingerprint": fingerprint(sig_pk).hex(),
    }


def decrypt_folder(
    source_path: str,
    output_dir: str,
    passphrase: str,
    progress: ProgressCallback = _null_progress,
    *,
    identity: Optional[SignerIdentity] = None,
) -> dict:
    """Decrypt a .pqc container and extract its contents.

    Args:
        source_path: Path to the .pqc file.
        output_dir: Base directory for extraction.
        passphrase: User passphrase.
        progress: Optional ``(phase, detail, percent)`` callback.
        identity: Optional signer identity verifier.

    Returns:
        Dict with ``output_dir``, ``files``, ``signer_fingerprint``.
    """
    progress("read", "Reading .pqc file...", 2)
    container_data = Path(source_path).read_bytes()

    return decrypt_and_extract(
        container_data,
        passphrase,
        output_dir,
        identity=identity,
        progress=progress,
    )
