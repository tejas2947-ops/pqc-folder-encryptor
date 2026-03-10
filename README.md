<p align="center">
  <img src="assets/banner-dark.svg" alt="TTPSEC PQC Folder Encryptor" width="700"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"/></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/FIPS_203-ML--KEM--768-00e676.svg" alt="FIPS 203"/>
  <img src="https://img.shields.io/badge/FIPS_204-ML--DSA--65-ff9800.svg" alt="FIPS 204"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-00b0ff.svg" alt="AES-256-GCM"/>
  <img src="https://img.shields.io/badge/Argon2id-9c27b0.svg" alt="Argon2id"/>
</p>

# PQC Folder Encryptor

Post-quantum cryptography folder encryption tool. Encrypts entire directories into a single `.pqc` file using NIST-standardized post-quantum algorithms.

Built by [TTPSEC SpA](https://ttpsec.cl) - OT/ICS Cybersecurity.

## Algorithms

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| Key Encapsulation | **ML-KEM-768** | FIPS 203 |
| Digital Signature | **ML-DSA-65** | FIPS 204 |
| Symmetric Encryption | **AES-256-GCM** | FIPS 197 |
| Password KDF | **Argon2id** (64 MB, 3 iter) | RFC 9106 |
| Key Expansion | **HKDF-SHA256** | RFC 5869 |

## Features

- Single-file Python application with auto-dependency installation
- GUI (tkinter) and CLI modes
- Encrypts full directory trees preserving structure
- Per-file SHA-256 integrity verification on decrypt
- Password strength indicator
- Standalone `.exe` build for Windows (no Python required)

## Quick Start

### From Source

```bash
# Install dependencies
pip install -r requirements.txt

# GUI mode (default)
python pqc_encryptor.py

# CLI - Encrypt a folder
python pqc_encryptor.py encrypt my_folder/ output.pqc -p "my-passphrase"

# CLI - Decrypt a .pqc file
python pqc_encryptor.py decrypt output.pqc restored/ -p "my-passphrase"
```

### Standalone .exe (Windows)

```bash
# Build the executable
build_exe.bat

# The .exe is in dist/PQC-Encryptor.exe
# Distribute it — no Python installation needed
```

## Requirements

- Python 3.10+
- Dependencies (auto-installed on first run):
  - `pqcrypto` - Post-quantum cryptographic primitives
  - `cryptography` - AES-GCM and HKDF
  - `argon2-cffi` - Argon2id password hashing

## How It Works

<p align="center">
  <img src="assets/architecture.svg" alt="Encryption Architecture" width="700"/>
</p>

### Encryption

```
Input folder
    |
    v
[Pack files + manifest with SHA-256 hashes]
    |
    v
[Generate ML-KEM-768 keypair] --> [Encapsulate shared secret]
    |                                       |
    v                                       v
[Argon2id(passphrase)] --> [AES-GCM encrypt KEM secret key]
                                            |
                                            v
                           [HKDF-SHA256(shared secret)] --> AES key
                                            |
                                            v
                           [AES-256-GCM encrypt payload]
                                            |
                                            v
                           [ML-DSA-65 sign (ct || nonce || hash)]
                                            |
                                            v
                                      output.pqc
```

### Decryption

```
input.pqc
    |
    v
[Argon2id(passphrase)] --> [Decrypt KEM secret key]
    |
    v
[ML-DSA-65 verify signature] --> abort if invalid
    |
    v
[ML-KEM-768 decapsulate] --> shared secret
    |
    v
[HKDF-SHA256] --> AES key --> [AES-256-GCM decrypt]
    |
    v
[Unpack files + verify SHA-256 per file]
    |
    v
Restored folder
```

## .pqc File Format (v2)

| Offset | Size | Content |
|--------|------|---------|
| 0 | 4 | Magic bytes `PQC2` |
| 4 | 2 | Format version (LE uint16) |
| 6 | 2 | Folder name length (LE uint16) |
| 8 | N | Folder name (UTF-8) |
| ... | 1088 | ML-KEM-768 ciphertext |
| ... | 16 | Argon2 salt |
| ... | 12 | SK encryption nonce |
| ... | 2400+16 | Encrypted KEM secret key (AES-GCM) |
| ... | 1184 | ML-KEM-768 public key |
| ... | 1952 | ML-DSA-65 public key |
| ... | 2 | Signature length (LE uint16) |
| ... | ~3309 | ML-DSA-65 signature |
| ... | 12 | AES-GCM nonce |
| ... | variable | AES-GCM encrypted payload |

## Verify Downloads

Every release includes a `SHA256SUMS.txt` file. Verify the `.exe` integrity:

```powershell
# PowerShell
certutil -hashfile PQC-Encryptor.exe SHA256
```

```bash
# Linux / Git Bash
sha256sum -c SHA256SUMS.txt
```

Compare the output hash with the value in `SHA256SUMS.txt`.

## Testing

```bash
python tests/test_roundtrip.py
```

The test creates a folder with various files, encrypts it, decrypts it, and verifies every file matches the original via SHA-256. It also confirms that a wrong passphrase is rejected.

## Project Structure

```
pqc-folder-encryptor/
├── pqc_encryptor.py              # Main application (GUI + CLI + crypto)
├── build_exe.bat                  # Windows .exe builder script
├── requirements.txt               # Python dependencies
├── requirements-dev.txt           # Build dependencies (PyInstaller)
├── tests/
│   └── test_roundtrip.py          # Encrypt/decrypt round-trip test
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                 # CI: test on push/PR
│   │   └── release.yml            # Build .exe + checksums on tag
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml         # Bug report template
│   │   └── feature_request.yml    # Feature request template
│   └── PULL_REQUEST_TEMPLATE.md   # PR template
├── LICENSE                        # MIT License
├── README.md                      # This file
├── CHANGELOG.md                   # Version history
├── SECURITY.md                    # Security policy and crypto details
├── CODE_OF_CONDUCT.md             # Contributor Code of Conduct
└── CONTRIBUTING.md                # Contribution guidelines
```

## License

MIT License - see [LICENSE](LICENSE) for details.

Copyright (c) 2026 TTPSEC SpA
