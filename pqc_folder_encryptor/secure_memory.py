# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Best-effort secure memory handling for cryptographic material.

Provides :class:`SecureBuffer` — a context manager that:

- Stores sensitive data in a mutable ``bytearray`` (can be zeroed)
- Calls ``VirtualLock`` (Windows) or ``mlock`` (Unix) to prevent swapping
- Zeros memory on cleanup via ``ctypes.memset``

Limitations
===========
This is a **best-effort** mitigation in Python:

- Python's GC may have already copied data internally.
- Immutable ``bytes`` returned by C libraries cannot be retroactively zeroed.
- The underlying C extensions (pqcrypto, OpenSSL) may keep internal copies.

This raises the bar against swap-file leakage, memory dump forensics, and
lingering heap data, but does NOT provide the guarantees of a C/Rust
application using libsodium's ``sodium_malloc``/``sodium_mprotect``.
"""
from __future__ import annotations

import ctypes
import platform
import sys
from typing import Optional

_IS_WINDOWS = platform.system() == "Windows"


def _lock_memory(address: int, size: int) -> bool:
    """Lock memory pages to prevent swapping. Returns True on success."""
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            return bool(kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
    except (OSError, AttributeError):
        return False


def _unlock_memory(address: int, size: int) -> None:
    """Unlock previously locked memory pages."""
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
    except (OSError, AttributeError):
        pass


def _zero_buffer(buf: bytearray) -> None:
    """Zero a bytearray in-place using ctypes for reliability."""
    if not buf:
        return
    arr_type = ctypes.c_char * len(buf)
    arr = arr_type.from_buffer(buf)
    ctypes.memset(ctypes.addressof(arr), 0, len(buf))


class SecureBuffer:
    """Best-effort secure container for sensitive cryptographic material.

    Usage::

        with SecureBuffer(key_bytes) as sb:
            do_crypto(bytes(sb))
        # Memory is zeroed when exiting the context

    Or manual lifecycle::

        sb = SecureBuffer(key_bytes)
        do_crypto(bytes(sb))
        sb.destroy()
    """

    __slots__ = ("_buf", "_locked", "_destroyed")

    def __init__(self, data: bytes | bytearray) -> None:
        self._buf = bytearray(data)
        self._destroyed = False
        # Try to lock memory to prevent swapping
        if self._buf:
            arr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
            self._locked = _lock_memory(ctypes.addressof(arr), len(self._buf))
        else:
            self._locked = False

    def __bytes__(self) -> bytes:
        """Return contents as bytes. Note: creates an immutable copy."""
        if self._destroyed:
            raise RuntimeError("SecureBuffer has been destroyed")
        return bytes(self._buf)

    @property
    def raw(self) -> bytearray:
        """Direct access to the mutable buffer."""
        if self._destroyed:
            raise RuntimeError("SecureBuffer has been destroyed")
        return self._buf

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> SecureBuffer:
        return self

    def __exit__(self, *_: object) -> None:
        self.destroy()

    def destroy(self) -> None:
        """Zero the buffer and unlock memory."""
        if self._destroyed:
            return
        _zero_buffer(self._buf)
        if self._locked and self._buf:
            arr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
            _unlock_memory(ctypes.addressof(arr), len(self._buf))
        self._destroyed = True

    def __del__(self) -> None:
        self.destroy()


def secure_zero(data: bytearray) -> None:
    """Zero a bytearray in-place. No-op for empty or non-bytearray inputs."""
    if isinstance(data, bytearray) and data:
        _zero_buffer(data)
