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
from pqc_folder_encryptor.container import pack_payload, unpack_payload
from pqc_folder_encryptor.exceptions import UnsafePathError

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

    print(f"\nResults: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
