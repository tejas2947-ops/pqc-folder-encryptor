# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Command-line interface for PQC Folder Encryptor.

Usage::

    python -m pqc_folder_encryptor encrypt <folder> <output.pqc>
    python -m pqc_folder_encryptor decrypt <file.pqc> <output_dir>
    python -m pqc_folder_encryptor info    <file.pqc>

Options:
    -p, --passphrase   Passphrase (prompted securely if omitted)
    --verify-key       Path to signing public key for identity verification
    --verify-fp        Hex fingerprint for identity verification
    --trust-store      Directory of trusted .pub files
    --export-key       Export signing public key after encryption
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import encrypt_folder, decrypt_folder, __version__
from .signing import SignerIdentity
from .container import parse_container
from .config import get_suite, SuiteId
from .exceptions import PQCError


def _progress(phase: str, detail: str, pct: float) -> None:
    bar_len = 30
    filled = int(pct / 100 * bar_len)
    bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
    print(f"\r  [{bar}] {pct:5.1f}%  {detail:<50}", end="", flush=True)


def _get_passphrase(mode: str) -> str:
    pw = getpass.getpass("Passphrase: ")
    if mode == "encrypt":
        pw2 = getpass.getpass("Confirm:    ")
        if pw != pw2:
            print("Error: passphrases do not match", file=sys.stderr)
            sys.exit(1)
    return pw


def _build_identity(args: argparse.Namespace) -> SignerIdentity:
    if args.verify_key:
        return SignerIdentity.from_public_key_file(args.verify_key)
    if args.verify_fp:
        return SignerIdentity.from_fingerprint(args.verify_fp)
    if args.trust_store:
        return SignerIdentity.from_trust_store(args.trust_store)
    return SignerIdentity.integrity_only()


def _parse_padding(value: str) -> int:
    """Parse a padding size like '1M', '16M', '512K', or raw bytes."""
    if not value:
        return 0
    v = value.strip().upper()
    if v.endswith("M"):
        return int(v[:-1]) * 1024 * 1024
    if v.endswith("K"):
        return int(v[:-1]) * 1024
    return int(v)


def cmd_encrypt(args: argparse.Namespace) -> None:
    pw = args.passphrase or _get_passphrase("encrypt")
    padding = _parse_padding(args.padding) if args.padding else 0
    print(f"\nTTPSEC \u2014 PQC Folder Encryptor v{__version__}\n")

    result = encrypt_folder(args.source, args.output, pw, _progress, padding=padding)

    print(f"\n\n  {result['files']} files \u2192 {result['output']}")
    print(f"  Input:  {result['input_size']:>12,} bytes")
    print(f"  Output: {result['output_size']:>12,} bytes")
    print(f"  Signer: {result['signer_fingerprint'][:16]}...")

    if args.export_key:
        # Re-read the container to extract the signing public key
        data = Path(result["output"]).read_bytes()
        header = parse_container(data)
        key_path = Path(args.export_key)
        key_path.write_bytes(header.sig_public_key)
        print(f"  Signing key exported to: {key_path}")

    print()


def cmd_decrypt(args: argparse.Namespace) -> None:
    pw = args.passphrase or _get_passphrase("decrypt")
    identity = _build_identity(args)
    print(f"\nTTPSEC \u2014 PQC Folder Encryptor v{__version__}\n")

    result = decrypt_folder(
        args.source, args.output, pw, _progress, identity=identity,
    )

    print(f"\n\n  {result['files']} files \u2192 {result['output_dir']}")
    print(f"  Signer: {result['signer_fingerprint'][:16]}...")
    print()


def cmd_info(args: argparse.Namespace) -> None:
    """Display container metadata without decrypting."""
    data = Path(args.source).read_bytes()
    header = parse_container(data)
    suite = get_suite(header.suite_id)

    print(f"\nTTPSEC \u2014 PQC Container Info")
    print(f"  File:           {args.source}")
    print(f"  Size:           {len(data):,} bytes")
    print(f"  Format version: {header.format_version}")
    print(f"  Suite:          0x{header.suite_id:04x} "
          f"({suite.kem_algorithm} + {suite.sig_algorithm} + {suite.aead_algorithm})")
    print(f"  Folder name:    {header.folder_name}")
    print(f"  Argon2id:       m={header.argon2_memory} KiB, "
          f"t={header.argon2_time}, p={header.argon2_parallel}")
    print(f"  Signer FP:      {header.sig_pk_fingerprint.hex()}")
    print()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pqc-folder-encryptor",
        description="TTPSEC PQC Folder Encryptor \u2014 Post-quantum encryption for directories",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # -- encrypt --
    enc = sub.add_parser("encrypt", help="Encrypt a folder into a .pqc container")
    enc.add_argument("source", help="Source folder to encrypt")
    enc.add_argument("output", help="Output .pqc file path")
    enc.add_argument("-p", "--passphrase", help="Passphrase (prompted if omitted)")
    enc.add_argument(
        "--export-key", metavar="PATH",
        help="Export the signing public key to a file",
    )
    enc.add_argument(
        "--padding", metavar="SIZE",
        help="Pad payload to block size (e.g., 1M, 16M, 512K). Hides true file size.",
    )

    # -- decrypt --
    dec = sub.add_parser("decrypt", help="Decrypt a .pqc container")
    dec.add_argument("source", help="Source .pqc file")
    dec.add_argument("output", help="Output directory")
    dec.add_argument("-p", "--passphrase", help="Passphrase (prompted if omitted)")
    dec.add_argument("--verify-key", metavar="PATH", help="Public key file for identity verification")
    dec.add_argument("--verify-fp", metavar="HEX", help="Expected signer fingerprint (hex)")
    dec.add_argument("--trust-store", metavar="DIR", help="Directory of trusted .pub key files")

    # -- info --
    inf = sub.add_parser("info", help="Show container metadata (no decryption)")
    inf.add_argument("source", help="Source .pqc file")

    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            cmd_encrypt(args)
        elif args.command == "decrypt":
            cmd_decrypt(args)
        elif args.command == "info":
            cmd_info(args)
    except PQCError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
