# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Manifest generation, canonicalization, and validation.

The manifest is a deterministic JSON array describing every file in the
container.  It provides:

- Integrity: SHA-256 hash per file, verified before extraction.
- Determinism: NFC-normalized paths, lexicographic sort, canonical JSON.
- Safety: path traversal prevention at generation AND extraction time.

Canonical JSON rules:
  - ``ensure_ascii=True``  (no raw Unicode in the wire format)
  - ``sort_keys=True``     (deterministic key order per entry)
  - ``separators=(",",":")`` (no whitespace)
  - Array sorted by ``path`` lexicographically.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import PurePosixPath
from typing import List, Tuple

from .exceptions import ManifestIntegrityError, UnsafePathError

# Windows reserved device names (case-insensitive)
_WINDOWS_RESERVED = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def _normalize_path(path: str) -> str:
    """Normalize and validate a single path component chain.

    Raises UnsafePathError on any suspicious input.
    """
    if "\x00" in path:
        raise UnsafePathError(path)

    # NFC Unicode normalization for cross-platform consistency
    path = unicodedata.normalize("NFC", path)

    # Unify separators
    path = path.replace("\\", "/")

    # Reject absolute paths before stripping
    if path.lstrip().startswith("/"):
        raise UnsafePathError(path)

    # Strip leading/trailing slashes and whitespace
    path = path.strip().strip("/")

    if not path:
        raise UnsafePathError(path)

    parts = PurePosixPath(path).parts

    for part in parts:
        if part in (".", ".."):
            raise UnsafePathError(path)
        if part.startswith("/"):
            raise UnsafePathError(path)
        # Reject Windows reserved names
        stem = part.split(".")[0].upper()
        if stem in _WINDOWS_RESERVED:
            raise UnsafePathError(path)

    return "/".join(parts)


def validate_path_safety(path: str) -> str:
    """Validate and normalize a path, rejecting traversal attempts.

    Returns the normalized path if safe.
    """
    normalized = _normalize_path(path)

    if normalized.startswith("/"):
        raise UnsafePathError(normalized)

    # Double-check no ".." after normalization
    if ".." in normalized.split("/"):
        raise UnsafePathError(normalized)

    # Reject drive letters (C:, D:, ...)
    first = normalized.split("/")[0]
    if len(first) >= 2 and first[1] == ":":
        raise UnsafePathError(normalized)

    return normalized


def validate_folder_name(name: str) -> str:
    """Validate a folder name (single component, no path separators)."""
    if not name:
        raise UnsafePathError(name)
    if "\x00" in name:
        raise UnsafePathError(name)
    if "/" in name or "\\" in name:
        raise UnsafePathError(name)
    if name in (".", ".."):
        raise UnsafePathError(name)

    name = unicodedata.normalize("NFC", name)

    stem = name.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise UnsafePathError(name)

    return name


def generate_manifest(file_entries: List[Tuple[str, bytes]]) -> bytes:
    """Build a canonical manifest from ``(relative_path, file_data)`` pairs.

    Returns canonical JSON as ASCII bytes.
    """
    entries = []
    for rel_path, data in file_entries:
        safe_path = validate_path_safety(rel_path)
        entries.append({
            "hash": hashlib.sha256(data).hexdigest(),
            "path": safe_path,
            "size": len(data),
        })

    # Deterministic order: lexicographic by normalized path
    entries.sort(key=lambda e: e["path"])

    # Check for duplicate paths (after normalization)
    paths = [e["path"] for e in entries]
    if len(set(paths)) != len(paths):
        raise ManifestIntegrityError()

    return json.dumps(
        entries,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def parse_manifest(manifest_bytes: bytes) -> List[dict]:
    """Parse and validate a manifest from bytes.

    Returns a list of dicts, each with ``path``, ``size``, ``hash``.
    """
    try:
        entries = json.loads(manifest_bytes.decode("ascii"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ManifestIntegrityError()

    if not isinstance(entries, list):
        raise ManifestIntegrityError()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestIntegrityError()

        required = {"path", "size", "hash"}
        if not required.issubset(entry.keys()):
            raise ManifestIntegrityError()

        if not isinstance(entry["path"], str):
            raise ManifestIntegrityError()
        if not isinstance(entry["size"], int) or entry["size"] < 0:
            raise ManifestIntegrityError()
        if not isinstance(entry["hash"], str) or len(entry["hash"]) != 64:
            raise ManifestIntegrityError()

        # Re-validate path safety on the receiving side
        validate_path_safety(entry["path"])

    # Must be sorted by path
    paths = [e["path"] for e in entries]
    if paths != sorted(paths):
        raise ManifestIntegrityError()

    # No duplicate paths
    if len(set(paths)) != len(paths):
        raise ManifestIntegrityError()

    return entries


def verify_file_against_manifest(
    path: str,
    data: bytes,
    expected_hash: str,
    expected_size: int,
) -> None:
    """Verify a file's data against its manifest entry."""
    if len(data) != expected_size:
        raise ManifestIntegrityError()
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ManifestIntegrityError()
