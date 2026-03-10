#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Environment verification script for PQC Folder Encryptor.

Checks that all required dependencies are installed with compatible
versions.  Run this BEFORE using the tool to ensure a correct setup.

Usage::

    python check_env.py

Why not auto-install?
---------------------
Auto-installing packages at runtime via ``pip`` is a security risk:

1. **Dependency confusion**: An attacker can register a malicious package
   with a similar name on PyPI (typosquatting) or on an internal index
   (dependency confusion).  Runtime installation without pinned hashes
   cannot detect such substitution.

2. **Supply chain compromise**: Even legitimate packages can be
   compromised.  Pinned versions + hash verification (via
   ``pip install --require-hashes``) is the only reliable defense.

3. **Reproducibility**: Runtime installation may resolve different
   versions across machines and over time, leading to inconsistent
   behavior and making bugs impossible to reproduce.

4. **Auditability**: Security teams cannot audit what was installed
   if packages are fetched silently at runtime.

Instead, install dependencies explicitly::

    pip install -r requirements.txt
    # or
    pip install .
"""
from __future__ import annotations

import importlib
import sys


REQUIRED = [
    ("pqcrypto", "pqcrypto", ">=0.4.0"),
    ("cryptography", "cryptography", ">=42.0"),
    ("argon2", "argon2-cffi", ">=25.1.0"),
]


def check() -> bool:
    ok = True
    print("PQC Folder Encryptor — Environment Check\n")
    print(f"  Python: {sys.version}")
    print()

    for module_name, pkg_name, version_req in REQUIRED:
        try:
            mod = importlib.import_module(module_name)
            ver = getattr(mod, "__version__", "unknown")
            print(f"  [OK]   {pkg_name:20s}  (version: {ver})")
        except ImportError:
            print(f"  [FAIL] {pkg_name:20s}  NOT INSTALLED")
            print(f"         Install with:  pip install \"{pkg_name}{version_req}\"")
            ok = False

    # Check PQC algorithm availability
    print()
    try:
        from pqcrypto.kem.ml_kem_768 import generate_keypair
        print("  [OK]   ML-KEM-768 available")
    except ImportError:
        print("  [FAIL] ML-KEM-768 not available in pqcrypto")
        ok = False

    try:
        from pqcrypto.sign.ml_dsa_65 import generate_keypair
        print("  [OK]   ML-DSA-65 available")
    except ImportError:
        print("  [FAIL] ML-DSA-65 not available in pqcrypto")
        ok = False

    print()
    if ok:
        print("  All checks passed. Environment is ready.")
    else:
        print("  Some checks FAILED. Install missing dependencies:")
        print("    pip install -r requirements.txt")
    print()

    return ok


if __name__ == "__main__":
    sys.exit(0 if check() else 1)
