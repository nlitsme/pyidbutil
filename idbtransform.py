# written by chatgpt GPT-6
"""Shared paths, record-sequence hashing, and checksums for IDB transformations."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import BinaryIO, Optional
import zlib

from idbwrite import Record


@dataclass(frozen=True)
class DatabasePaths:
    source: Path
    output: Optional[Path] = None


class RecordDigest:
    """Hash ordered records with unambiguous lengths, without retaining them."""

    def __init__(self) -> None:
        self.hash = hashlib.sha256()
        self.count = 0

    def add(self, record: Record) -> None:
        self.hash.update(struct.pack('<II', len(record.key), len(record.value)))
        self.hash.update(record.key)
        self.hash.update(record.value)
        self.count += 1

    def matches(self, other: RecordDigest) -> bool:
        return self.count == other.count and self.hash.digest() == other.hash.digest()


def stream_crc(source: BinaryIO, size: int) -> int:
    crc = 0
    while size:
        data = source.read(min(size, 1024 * 1024))
        if not data:
            raise ValueError('truncated stored section')
        crc = zlib.crc32(data, crc)
        size -= len(data)
    return crc & 0xffffffff
