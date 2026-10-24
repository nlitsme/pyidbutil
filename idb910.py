# written by chatgpt GPT-6
"""Materialize and verify v910's combined section payload."""
from __future__ import annotations

import struct
import tempfile
from typing import BinaryIO
import zlib


class V910Payload:
    """Own a seekable temporary file containing only verified section bytes.

    The CRC is the final little-endian uint32 of the decompressed stream;
    it covers all preceding decompressed bytes and is not section data.
    """

    CHUNK = 1024 * 1024

    def __init__(self, source: BinaryIO, offset: int, size: int, compression: int):
        if offset < 0x51:
            raise ValueError('v910 data starts inside the header')
        if compression not in (0, 3):
            raise ValueError('unsupported v910 compression: %d' % compression)
        self.fh: BinaryIO = tempfile.TemporaryFile()
        self.size = size
        self.written = 0
        self.trailer = bytearray()
        self.crc = 0
        self.computed_crc = 0
        try:
            source.seek(offset)
            if compression == 3:
                self._zstd(source)
            else:
                self._uncompressed(source)
            self._verify()
            self.fh.seek(0)
        except BaseException:
            self.fh.close()
            raise

    def _append(self, data: bytes) -> None:
        body = data[:max(0, self.size - self.written)]
        if self.fh.write(body) != len(body):
            raise OSError('short temporary-file write')
        self.computed_crc = zlib.crc32(body, self.computed_crc)
        self.written += len(body)
        self.trailer.extend(data[len(body):])
        if len(self.trailer) > 4:
            raise ValueError('v910 payload exceeds section sizes plus CRC')

    def _uncompressed(self, source: BinaryIO) -> None:
        while True:
            data = source.read(self.CHUNK)
            if not data:
                return
            self._append(data)

    def _zstd(self, source: BinaryIO) -> None:
        try:
            from compression.zstd import ZstdDecompressor
        except ImportError:
            try:
                from backports.zstd import ZstdDecompressor
            except ImportError as exc:
                raise ImportError('v910 zstd requires Python 3.14+ or backports.zstd') from exc
        pending = source.read(self.CHUNK)
        if not pending:
            raise ValueError('missing v910 zstd frame')
        # Concatenated frames are accepted; all must finish completely.
        while pending:
            decoder = ZstdDecompressor()
            while not decoder.eof:
                if decoder.needs_input:
                    data = pending or source.read(self.CHUNK)
                    pending = b''
                    if not data:
                        raise ValueError('truncated v910 zstd frame')
                else:
                    data = b''
                self._append(decoder.decompress(data, max_length=self.CHUNK))
            pending = decoder.unused_data or source.read(self.CHUNK)

    def _verify(self) -> None:
        if self.written != self.size:
            raise ValueError('truncated v910 section data')
        if len(self.trailer) != 4:
            raise ValueError('missing or truncated v910 CRC')
        self.crc, = struct.unpack('<L', self.trailer)
        self.computed_crc &= 0xffffffff
        if self.crc != self.computed_crc:
            raise ValueError('v910 payload CRC mismatch: %08x != %08x'
                             % (self.crc, self.computed_crc))

    def close(self) -> None:
        self.fh.close()
