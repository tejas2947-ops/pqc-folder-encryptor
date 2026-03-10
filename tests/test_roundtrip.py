#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Round-trip test: encrypt a folder, decrypt it, verify all files match.
Also tests rejection of wrong passphrase and tampered containers.
"""
import hashlib
import os
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqc_folder_encryptor import encrypt_folder, decrypt_folder
from pqc_folder_encryptor.exceptions import (
    DecryptionError,
    SignatureVerificationError,
)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="pqc_test_"))
    try:
        # -- Create test folder --
        src = tmp / "test_folder"
        src.mkdir()
        (src / "hello.txt").write_text("Hello, Post-Quantum World!", encoding="utf-8")
        (src / "binary.bin").write_bytes(os.urandom(4096))
        sub = src / "subdir" / "nested"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("Nested file content", encoding="utf-8")
        (src / "empty.txt").write_bytes(b"")

        originals = {}
        for f in src.rglob("*"):
            if f.is_file():
                originals[str(f.relative_to(src))] = sha256_file(f)
        print(f"Created {len(originals)} test files")

        # -- Encrypt --
        pqc_file = tmp / "test.pqc"
        passphrase = "test-passphrase-!@#$%^&*()"
        r = encrypt_folder(str(src), str(pqc_file), passphrase)
        print(f"Encrypted: {r['files']} files, {r['output_size']:,} bytes")
        assert pqc_file.exists(), "PQC file not created"

        # -- Decrypt --
        dst = tmp / "restored"
        dst.mkdir()
        r = decrypt_folder(str(pqc_file), str(dst), passphrase)
        print(f"Decrypted: {r['files']} files")

        # -- Verify file integrity --
        restored_dir = dst / "test_folder"
        assert restored_dir.exists(), "Restored folder not found"

        for rel, orig_hash in originals.items():
            normalized_rel = rel.replace("\\", "/")
            restored_file = restored_dir / normalized_rel
            assert restored_file.exists(), f"Missing file: {normalized_rel}"
            assert sha256_file(restored_file) == orig_hash, f"Hash mismatch: {normalized_rel}"
        print(f"Verified {len(originals)} files - ALL MATCH")

        # -- Wrong passphrase --
        try:
            bad_dst = tmp / "bad"
            bad_dst.mkdir()
            decrypt_folder(str(pqc_file), str(bad_dst), "wrong-password")
            print("FAIL: Should have raised error for wrong passphrase")
            return 1
        except DecryptionError as e:
            print(f"Wrong passphrase correctly rejected: {e}")

        # -- Tampered container (flip a byte in the ciphertext) --
        tampered = tmp / "tampered.pqc"
        data = pqc_file.read_bytes()
        pos = len(data) - 100
        tampered_data = data[:pos] + bytes([data[pos] ^ 0xFF]) + data[pos + 1:]
        tampered.write_bytes(tampered_data)
        try:
            tamper_dst = tmp / "tamper_out"
            tamper_dst.mkdir()
            decrypt_folder(str(tampered), str(tamper_dst), passphrase)
            print("FAIL: Should have detected tampering")
            return 1
        except Exception as e:
            print(f"Tampering correctly detected: {type(e).__name__}: {e}")

        print("\nAll tests PASSED")
        return 0

    except Exception as e:
        print(f"\nFAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
