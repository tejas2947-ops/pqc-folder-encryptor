# Security Policy

## Cryptographic Algorithms

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| Key Encapsulation | ML-KEM-768 | FIPS 203 | Post-quantum key exchange |
| Digital Signature | ML-DSA-65 | FIPS 204 | Integrity and authenticity |
| Symmetric Encryption | AES-256-GCM | FIPS 197 | Authenticated data encryption |
| Key Derivation (password) | Argon2id | RFC 9106 | Password-based key derivation |
| Key Derivation (shared secret) | HKDF-SHA256 | RFC 5869 | Shared secret expansion |
| Integrity | SHA-256 | FIPS 180-4 | Per-file integrity check |

## Encryption Flow

1. **Key Generation**: Fresh ML-KEM-768 and ML-DSA-65 keypairs per encryption
2. **Key Encapsulation**: ML-KEM-768 encapsulates a shared secret
3. **Key Derivation**: HKDF-SHA256 derives AES-256 key with domain separation
4. **Password Protection**: Argon2id (64 MB, 3 iterations, 4 threads) derives a key from the passphrase to encrypt the KEM secret key
5. **Encryption**: AES-256-GCM encrypts the packed folder payload
6. **Signing**: ML-DSA-65 signs the entire authenticated region (all bytes from magic through encrypted payload)

## Memory Protection (v3.1)

Sensitive cryptographic material (KEM secret keys, signing secret keys, shared secrets, derived keys) is wrapped in `SecureBuffer` objects that:

- Store data in mutable `bytearray` (not immutable `bytes`)
- Call `VirtualLock` (Windows) or `mlock` (Unix) to prevent swapping to disk
- Zero memory via `ctypes.memset` on cleanup

**Limitation**: This is a best-effort mitigation in Python. The garbage collector and underlying C libraries may retain internal copies. For maximum protection, consider deploying in a memory-encrypted environment (e.g., AMD SEV, Intel TDX).

## Payload Padding (v3.1)

When padding is enabled (`--padding`), the plaintext payload is padded with random bytes to the next block boundary before AES-GCM encryption. This hides the true size of the encrypted content. Padded containers use format version 4.

## Side-Channel Resistance

Constant-time execution is delegated to the underlying compiled C libraries:

| Operation | Library | Constant-time mechanism |
|-----------|---------|------------------------|
| ML-KEM-768 | `pqcrypto` (C) | Reference/optimized C implementation |
| ML-DSA-65 | `pqcrypto` (C) | Reference/optimized C implementation |
| AES-256-GCM | OpenSSL via `cryptography` | AES-NI hardware instructions |
| HKDF-SHA256 | OpenSSL via `cryptography` | Constant-time SHA-256 |
| Argon2id | `argon2-cffi` (C) | Memory-hard by design |

Adding artificial noise or delays at the Python level would be counterproductive: an attacker can average them out, and the Python interpreter already adds sufficient timing noise to mask any residual signal from the cryptographic operations.

## Key Lifecycle (v3.1)

Trust store `.pub` files support a JSON-envelope format with metadata:
- **Expiration dates**: Keys with `expires_at` in the past are automatically skipped
- **Revocation**: Keys with `status: "revoked"` are excluded from verification
- **Labels**: Human-readable identifiers for key management

Raw `.pub` files (binary public key bytes) remain supported for backward compatibility.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

- Email: security@ttpsec.cl
- Do NOT open a public issue for security vulnerabilities
- We will acknowledge receipt within 48 hours

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| 2.x     | Legacy    |
| < 2.0   | No        |
