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
3. **Key Derivation**: HKDF-SHA256 derives AES-256 key from shared secret
4. **Password Protection**: Argon2id (64 MB, 3 iterations, 4 threads) derives a key from the passphrase to encrypt the KEM secret key
5. **Encryption**: AES-256-GCM encrypts the packed folder payload
6. **Signing**: ML-DSA-65 signs (ciphertext || nonce || SHA-256(encrypted_data))

## .pqc File Format (v2)

```
[4B magic "PQC2"][2B version][2B name_len][name]
[KEM ciphertext][16B salt][12B SK nonce][encrypted SK]
[KEM public key][DSA public key]
[2B sig_len][signature][12B AES nonce][AES-GCM ciphertext]
```

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

- Email: security@ttpsec.cl
- Do NOT open a public issue for security vulnerabilities
- We will acknowledge receipt within 48 hours

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |
