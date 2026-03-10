# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Key metadata and lifecycle management for signer identity.

Extends the trust store model with JSON-envelope key files that carry
metadata: creation/expiration timestamps, labels, and status.

Key file format (v1)
====================

A ``.pub`` file may be either:

- **Raw format** (backward compatible): raw public key bytes.
- **JSON envelope** (v3.1+)::

    {
        "version": 1,
        "algorithm": "ML-DSA-65",
        "public_key": "<base64-encoded raw public key>",
        "fingerprint": "<hex SHA-256 of raw public key>",
        "created_at": "2026-03-10T00:00:00Z",
        "expires_at": "2027-03-10T00:00:00Z",
        "label": "alice@ttpsec.com",
        "status": "active"
    }

Status values: ``"active"``, ``"revoked"``.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .exceptions import KeyExpiredError, KeyRevokedError


@dataclass(frozen=True)
class KeyMetadata:
    """Metadata associated with a signing public key."""
    public_key: bytes
    fingerprint: bytes
    algorithm: str = "ML-DSA-65"
    label: str = ""
    status: str = "active"
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    source_file: str = ""

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        return self.status == "revoked"

    @property
    def is_valid(self) -> bool:
        return self.status == "active" and not self.is_expired


def load_key_file(path: Path) -> KeyMetadata:
    """Load a public key file, auto-detecting raw vs JSON format."""
    data = path.read_bytes()

    # Try JSON envelope first
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and "version" in obj and "public_key" in obj:
            return _parse_json_key(obj, str(path))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Fall back to raw key bytes
    fp = hashlib.sha256(data).digest()
    return KeyMetadata(
        public_key=data,
        fingerprint=fp,
        source_file=str(path),
    )


def _parse_json_key(obj: dict, source: str) -> KeyMetadata:
    """Parse a JSON-envelope key file."""
    pk_b64 = obj["public_key"]
    pk = base64.b64decode(pk_b64)
    fp = hashlib.sha256(pk).digest()

    # Validate fingerprint if provided
    if "fingerprint" in obj:
        expected_fp = bytes.fromhex(obj["fingerprint"])
        if fp != expected_fp:
            raise ValueError(f"Key fingerprint mismatch in {source}")

    created_at = None
    if "created_at" in obj and obj["created_at"]:
        created_at = datetime.fromisoformat(obj["created_at"])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

    expires_at = None
    if "expires_at" in obj and obj["expires_at"]:
        expires_at = datetime.fromisoformat(obj["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

    return KeyMetadata(
        public_key=pk,
        fingerprint=fp,
        algorithm=obj.get("algorithm", "ML-DSA-65"),
        label=obj.get("label", ""),
        status=obj.get("status", "active"),
        created_at=created_at,
        expires_at=expires_at,
        source_file=source,
    )


def export_key_with_metadata(
    public_key: bytes,
    output_path: str,
    *,
    algorithm: str = "ML-DSA-65",
    label: str = "",
    expires_at: Optional[datetime] = None,
) -> None:
    """Export a signing public key as a JSON-envelope file."""
    fp = hashlib.sha256(public_key).digest()
    now = datetime.now(timezone.utc)

    obj = {
        "version": 1,
        "algorithm": algorithm,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "fingerprint": fp.hex(),
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "label": label,
        "status": "active",
    }

    Path(output_path).write_text(
        json.dumps(obj, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def validate_key_lifecycle(meta: KeyMetadata) -> None:
    """Check that a key is active and not expired. Raises on failure."""
    if meta.is_revoked:
        raise KeyRevokedError(meta.label or meta.fingerprint.hex()[:16])
    if meta.is_expired:
        raise KeyExpiredError(meta.label or meta.fingerprint.hex()[:16])
