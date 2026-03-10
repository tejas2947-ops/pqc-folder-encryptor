#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Known-answer / regression tests for PQC Folder Encryptor v3.

Verifies key derivation, manifest canonicalization, container format
primitives, and path validation produce expected outputs.
"""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqc_folder_encryptor.config import (
    MAGIC, FORMAT_VERSION, SuiteId, Argon2Params, get_suite,
)
from pqc_folder_encryptor.crypto import derive_key, derive_passphrase_key
from pqc_folder_encryptor.manifest import (
    generate_manifest, parse_manifest, validate_path_safety,
)
from pqc_folder_encryptor.container import pack_payload, unpack_payload, pad_payload, unpad_payload
from pqc_folder_encryptor.secure_memory import SecureBuffer, secure_zero
from pqc_folder_encryptor.key_management import KeyMetadata, load_key_file, export_key_with_metadata
from pqc_folder_encryptor.exceptions import UnsafePathError, KeyExpiredError, KeyRevokedError

PASS = 0
FAIL = 0


def check(name, got, expected):
    global PASS, FAIL
    if got == expected:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")
        print(f"        got:      {got!r}")
        print(f"        expected: {expected!r}")


def check_raises(name, exc_type, fn, *args):
    global PASS, FAIL
    try:
        fn(*args)
        FAIL += 1
        print(f"  FAIL  {name} (no exception raised)")
    except exc_type:
        PASS += 1
        print(f"  PASS  {name}")
    except Exception as e:
        FAIL += 1
        print(f"  FAIL  {name} (wrong exception: {type(e).__name__}: {e})")


# ===================================================================
# Format constants
# ===================================================================

def test_magic_and_version():
    check("MAGIC", MAGIC, b"\x89PQC")
    check("MAGIC size", len(MAGIC), 4)
    check("FORMAT_VERSION", FORMAT_VERSION, 3)


def test_suite_registry():
    suite = get_suite(0x0001)
    check("suite KEM", suite.kem_algorithm, "ML-KEM-768")
    check("suite SIG", suite.sig_algorithm, "ML-DSA-65")
    check("suite AEAD", suite.aead_algorithm, "AES-256-GCM")
    check("suite key_len", suite.key_len, 32)


# ===================================================================
# Key derivation
# ===================================================================

def test_kdf_passphrase_deterministic():
    params = Argon2Params()
    salt = b"\x00" * 16
    k1, _ = derive_passphrase_key("test-password", params, salt)
    k2, _ = derive_passphrase_key("test-password", params, salt)
    check("passphrase KDF deterministic", k1, k2)
    check("passphrase KDF length", len(k1), 32)


def test_kdf_passphrase_salt_sensitivity():
    params = Argon2Params()
    k1, _ = derive_passphrase_key("same", params, b"\x00" * 16)
    k2, _ = derive_passphrase_key("same", params, b"\x01" + b"\x00" * 15)
    check("passphrase KDF salt sensitivity", k1 != k2, True)


def test_kdf_passphrase_password_sensitivity():
    params = Argon2Params()
    salt = b"\xaa" * 16
    k1, _ = derive_passphrase_key("password-a", params, salt)
    k2, _ = derive_passphrase_key("password-b", params, salt)
    check("passphrase KDF password sensitivity", k1 != k2, True)


def test_hkdf_deterministic():
    ss = b"\x42" * 32
    label = b"test-label"
    k1 = derive_key(ss, label)
    k2 = derive_key(ss, label)
    check("HKDF deterministic", k1, k2)
    check("HKDF length", len(k1), 32)


def test_hkdf_domain_separation():
    ss = b"\x42" * 32
    k1 = derive_key(ss, b"pqc-folder-encryptor.v1.encryption-key")
    k2 = derive_key(ss, b"pqc-folder-encryptor.v1.manifest-binding")
    check("HKDF domain separation", k1 != k2, True)


# ===================================================================
# Manifest
# ===================================================================

def test_manifest_canonical():
    entries = [("b.txt", b"BBB"), ("a.txt", b"AAA")]
    m = generate_manifest(entries)
    parsed = json.loads(m)
    check("manifest sorted", parsed[0]["path"], "a.txt")
    check("manifest no whitespace", b" " not in m, True)


def test_manifest_roundtrip():
    entries = [("dir/file.txt", b"hello"), ("root.bin", bytes(range(256)))]
    m = generate_manifest(entries)
    parsed = parse_manifest(m)
    check("manifest roundtrip count", len(parsed), 2)
    check("manifest first path", parsed[0]["path"], "dir/file.txt")


def test_path_traversal_rejection():
    check_raises("path traversal ..", UnsafePathError, validate_path_safety, "../etc/passwd")
    check_raises("path traversal absolute", UnsafePathError, validate_path_safety, "/etc/passwd")
    check_raises("path traversal null", UnsafePathError, validate_path_safety, "file\x00.txt")
    check_raises("path traversal drive", UnsafePathError, validate_path_safety, "C:/Windows/System32")
    check_raises("path traversal CON", UnsafePathError, validate_path_safety, "CON")


def test_path_normalization():
    result = validate_path_safety("dir\\subdir\\file.txt")
    check("backslash normalization", result, "dir/subdir/file.txt")


# ===================================================================
# Payload packing
# ===================================================================

def test_pack_unpack_roundtrip():
    manifest = b'[{"hash":"abc","path":"a.txt","size":5}]'
    blobs = [b"hello"]
    payload = pack_payload(manifest, blobs)
    recovered = unpack_payload(payload, 1)
    check("pack/unpack blob", recovered[0], b"hello")


def test_pack_unpack_multiple():
    manifest = b'[{"hash":"a","path":"a","size":3},{"hash":"b","path":"b","size":4}]'
    blobs = [b"AAA", b"BBBB"]
    payload = pack_payload(manifest, blobs)
    recovered = unpack_payload(payload, 2)
    check("multi-blob first", recovered[0], b"AAA")
    check("multi-blob second", recovered[1], b"BBBB")


def test_big_endian_format():
    manifest = b"[]"
    payload = pack_payload(manifest, [])
    length = struct.unpack("!I", payload[:4])[0]
    check("BE manifest length", length, 2)


# ===================================================================
# Padding (v3.1)
# ===================================================================

def test_pad_unpad_roundtrip():
    original = b"Hello, padded world!" * 100
    padded = pad_payload(original, 1024)
    check("padded length aligned", len(padded) % 1024, 0)
    check("padded larger", len(padded) > len(original), True)
    recovered = unpad_payload(padded)
    check("pad/unpad roundtrip", recovered, original)


def test_pad_unpad_empty():
    original = b""
    padded = pad_payload(original, 256)
    check("padded empty aligned", len(padded) % 256, 0)
    recovered = unpad_payload(padded)
    check("pad/unpad empty", recovered, original)


def test_pad_exact_block():
    # When data + 8 byte header is exact multiple, should add full block
    data = b"X" * (1024 - 8)  # exactly 1024 with 8-byte header
    padded = pad_payload(data, 1024)
    check("exact block gets extra padding", len(padded), 2048)
    check("exact block roundtrip", unpad_payload(padded), data)


# ===================================================================
# Secure memory (v3.1)
# ===================================================================

def test_secure_buffer_bytes():
    data = b"secret key material"
    sb = SecureBuffer(data)
    check("SecureBuffer bytes()", bytes(sb), data)
    check("SecureBuffer len()", len(sb), len(data))
    sb.destroy()


def test_secure_buffer_context_manager():
    data = b"\xaa" * 32
    with SecureBuffer(data) as sb:
        check("SecureBuffer context bytes", bytes(sb), data)
    # After exit, buffer should be zeroed
    check("SecureBuffer zeroed after exit", sb._buf, bytearray(32))


def test_secure_zero():
    buf = bytearray(b"sensitive data here")
    secure_zero(buf)
    check("secure_zero clears data", buf, bytearray(len(buf)))


# ===================================================================
# Key metadata (v3.1)
# ===================================================================

def test_key_metadata_valid():
    meta = KeyMetadata(
        public_key=b"test_pk",
        fingerprint=b"test_fp",
        status="active",
    )
    check("active key is valid", meta.is_valid, True)
    check("active key not expired", meta.is_expired, False)
    check("active key not revoked", meta.is_revoked, False)


def test_key_metadata_revoked():
    meta = KeyMetadata(
        public_key=b"test_pk",
        fingerprint=b"test_fp",
        status="revoked",
    )
    check("revoked key is_revoked", meta.is_revoked, True)
    check("revoked key not valid", meta.is_valid, False)


def test_key_metadata_expired():
    from datetime import datetime, timezone, timedelta
    past = datetime.now(timezone.utc) - timedelta(days=1)
    meta = KeyMetadata(
        public_key=b"test_pk",
        fingerprint=b"test_fp",
        expires_at=past,
    )
    check("expired key is_expired", meta.is_expired, True)
    check("expired key not valid", meta.is_valid, False)


def test_key_export_and_load(tmp_path=None):
    import tempfile, hashlib as hl
    tmp = Path(tempfile.mkdtemp(prefix="pqc_key_test_"))
    try:
        pk = b"fake_public_key_for_testing_1952_bytes" * 50
        key_file = tmp / "test.pub"
        export_key_with_metadata(pk, str(key_file), label="test@ttpsec.com")
        meta = load_key_file(key_file)
        check("exported key roundtrip pk", meta.public_key, pk)
        check("exported key label", meta.label, "test@ttpsec.com")
        check("exported key status", meta.status, "active")
        check("exported key fingerprint", meta.fingerprint, hl.sha256(pk).digest())
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


# ===================================================================

def main():
    print("Running known-answer / regression tests (v3 format)\n")

    test_magic_and_version()
    test_suite_registry()
    test_kdf_passphrase_deterministic()
    test_kdf_passphrase_salt_sensitivity()
    test_kdf_passphrase_password_sensitivity()
    test_hkdf_deterministic()
    test_hkdf_domain_separation()
    test_manifest_canonical()
    test_manifest_roundtrip()
    test_path_traversal_rejection()
    test_path_normalization()
    test_pack_unpack_roundtrip()
    test_pack_unpack_multiple()
    test_big_endian_format()

    print("\n--- v3.1 features ---\n")
    test_pad_unpad_roundtrip()
    test_pad_unpad_empty()
    test_pad_exact_block()
    test_secure_buffer_bytes()
    test_secure_buffer_context_manager()
    test_secure_zero()
    test_key_metadata_valid()
    test_key_metadata_revoked()
    test_key_metadata_expired()
    test_key_export_and_load()

    print(f"\nResults: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
