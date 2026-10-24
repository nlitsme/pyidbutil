# written by chatgpt GPT-6
"""Streaming IDB v6 container and B-tree v2 bulk writers (Python 3.9+)."""
from __future__ import annotations

from dataclasses import dataclass
import struct
import tempfile
from types import TracebackType
from typing import BinaryIO, Optional, Protocol, Type, Union
import zlib


class SectionType(Protocol):
    INDEX: int


class DatabaseSource(Protocol):
    fh: BinaryIO
    magic: str
    fileversion: int
    headerdata: bytes

    def getsectioninfo(self, index: int) -> tuple[int, int, int, int]: ...

    def getstoredpart(self, index: int) -> Optional[BinaryIO]: ...


@dataclass(frozen=True)
class Record:
    key: bytes
    value: bytes

    def encode(self) -> bytes:
        return (struct.pack('<H', len(self.key)) + self.key
                + struct.pack('<H', len(self.value)) + self.value)


def write_exact(fh: BinaryIO, data: bytes) -> None:
    if fh.write(data) != len(data):
        raise OSError('short output write')


def read_exact(fh: BinaryIO, size: int) -> bytes:
    data = fh.read(size)
    if len(data) != size:
        raise ValueError('truncated input: wanted %d bytes, got %d'
                         % (size, len(data)))
    return data


@dataclass(frozen=True)
class PageEntry:
    record: Record
    prefix: int

    def encode(self) -> bytes:
        key = self.record.key[self.prefix:]
        return (struct.pack('<H', len(key)) + key
                + struct.pack('<H', len(self.record.value))
                + self.record.value)

    def weight(self) -> int:
        return 10 + len(self.record.key) - self.prefix + len(self.record.value)


@dataclass
class PageBuffer:
    records: list[Record]
    children: list[int]

    _size: Optional[int] = None

    def _entry(self, record: Record, previous: bytes) -> PageEntry:
        prefix = 0
        if not self.children:
            for a, b in zip(previous, record.key):
                if a != b:
                    break
                prefix += 1
        return PageEntry(record, prefix)

    def entries(self) -> list[PageEntry]:
        entries: list[PageEntry] = []
        previous = b''
        for record in self.records:
            entries.append(self._entry(record, previous))
            previous = record.key
        return entries

    def append(self, record: Record) -> None:
        previous = self.records[-1].key if self.records else b''
        self._size = self.used_size() + self._entry(record, previous).weight()
        self.records.append(record)

    def used_size(self) -> int:
        if self._size is None:
            self._size = 12 + sum(entry.weight() for entry in self.entries())
        return self._size

    def split(self, pagesize: int) -> tuple[PageBuffer, Record, PageBuffer]:
        entries = self.entries()
        sums = [0]
        for entry in entries:
            sums.append(sums[-1] + entry.weight())
        choices: list[tuple[int, int]] = []
        for pivot in range(1, len(entries) - 1):
            left = 12 + sums[pivot]
            right = 12 + sums[-1] - sums[pivot + 1]
            # The first key on the new right leaf cannot share a prefix.
            right += entries[pivot + 1].prefix
            if max(left, right) <= pagesize:
                choices.append((abs(left - right), pivot))
        if not choices:
            raise ValueError('cannot split an overflowing B-tree page')
        _, pivot = min(choices)
        left = PageBuffer(self.records[:pivot], self.children[:pivot + 1] if self.children else [])
        right = PageBuffer(self.records[pivot + 1:], self.children[pivot + 1:] if self.children else [])
        return left, self.records[pivot], right

    def encode(self, pagesize: int) -> bytes:
        if self.used_size() > pagesize:
            raise ValueError('B-tree page overflow')
        if self.children and (len(self.children) != len(self.records) + 1
                              or any(child == 0 for child in self.children)):
            raise ValueError('unfinished B-tree child pointer')
        page = bytearray(pagesize)
        struct.pack_into('<LH', page, 0, self.children[0] if self.children else 0, len(self.records))
        offset = pagesize
        for index, entry in enumerate(self.entries()):
            encoded = entry.encode()
            offset -= len(encoded)
            page[offset:offset + len(encoded)] = encoded
            if self.children:
                struct.pack_into('<LH', page, 6 * (index + 1), self.children[index + 1], offset)
            else:
                struct.pack_into('<HHH', page, 6 * (index + 1), entry.prefix, 0, offset)
        struct.pack_into('<LH', page, 6 * (len(self.records) + 1), 0, offset)
        return bytes(page)


class BTreeBuilder:
    """Append in key order, splitting a rightmost path of equal-depth pages."""

    def __init__(self, records: BinaryIO, output: BinaryIO, count: int, pagesize: int):
        self.records = records
        self.output = output
        self.count = count
        self.pagesize = pagesize
        self.next_page = 3  # Header=0, root=1, free-list management=2.
        self.pending: list[PageBuffer] = [PageBuffer([], [])]

    def build(self) -> None:
        self.records.seek(0)
        write_exact(self.output, bytes(3 * self.pagesize))
        for _ in range(self.count):
            self.pending[0].append(self._record())
            self._split_overflow(0)
        child = 0
        for level, page in enumerate(self.pending):
            if page.children:
                page.children[-1] = child
            child = self._write_page(page, 1 if level == len(self.pending) - 1 else None)
        header = bytearray(self.pagesize)
        struct.pack_into('<LHLLL', header, 0, 2, self.pagesize, 1, self.count, self.next_page - 2)
        header[0x13:0x1e] = b'B-tree v2\x00\x01'
        self.output.seek(0)
        write_exact(self.output, bytes(header))
        self.output.seek(0, 2)

    def _record(self) -> Record:
        keysize, = struct.unpack('<H', read_exact(self.records, 2))
        key = read_exact(self.records, keysize)
        valsize, = struct.unpack('<H', read_exact(self.records, 2))
        return Record(key, read_exact(self.records, valsize))

    def _split_overflow(self, level: int) -> None:
        while self.pending[level].used_size() > self.pagesize:
            left, middle, right = self.pending[level].split(self.pagesize)
            left_number = self._write_page(left)
            self.pending[level] = right
            level += 1
            if level == len(self.pending):
                self.pending.append(PageBuffer([], [left_number]))
            parent = self.pending[level]
            parent.children[-1] = left_number
            parent.append(middle)
            parent.children.append(0)  # Pending child at the level below.

    def _write_page(self, page: PageBuffer, number: Optional[int] = None) -> int:
        if number is None:
            number = self.next_page
            self.next_page += 1
        self.output.seek(number * self.pagesize)
        write_exact(self.output, page.encode(self.pagesize))
        return number


class SectionBuffer:
    """Spool a section; close retains its bytes for container finalization."""

    def __init__(self, owner: IDBWriter, index: int, compression: int, stored: bool = False):
        self.owner = owner
        self.index = index
        self.compression = compression
        self.stored = stored
        self.fh: BinaryIO = tempfile.TemporaryFile()
        self.closed = False

    def _check(self) -> None:
        if self.closed or self.owner.closed:
            raise ValueError('writer is closed')

    def close(self) -> None:
        if not self.closed:
            self._check()
            self.fh.flush()
            self.closed = True

    def dispose(self) -> None:
        self.fh.close()


class SectionWriter(SectionBuffer):
    """Accept raw section bytes without interpreting their contents."""

    def write(self, data: bytes) -> None:
        self._check()
        if not isinstance(data, bytes):
            raise TypeError('section data must be bytes')
        write_exact(self.fh, data)


class ID0Writer(SectionBuffer):
    """Accept strictly increasing raw keys, then construct a fresh ID0 tree."""

    def __init__(self, owner: IDBWriter, index: int, compression: int, pagesize: int):
        super().__init__(owner, index, compression)
        if not 128 <= pagesize <= 65535:
            self.fh.close()
            raise ValueError('page size must be between 128 and 65535')
        self.pagesize = pagesize
        self.records: BinaryIO = tempfile.TemporaryFile()
        self.previous: Optional[bytes] = None
        self.count = 0

    def write(self, key: bytes, value: bytes) -> None:
        self._check()
        if not isinstance(key, bytes) or not isinstance(value, bytes):
            raise TypeError('keys and values must be bytes')
        if self.previous is not None and key <= self.previous:
            raise ValueError('keys must be unique and strictly increasing')
        if len(key) > 65535 or len(value) > 65535:
            raise ValueError('key/value length exceeds the on-disk field')
        record = Record(key, value)
        encoded = record.encode()
        if 3 * (len(encoded) + 6) + 12 > self.pagesize:
            raise ValueError('record too large for selected B-tree page size')
        write_exact(self.records, encoded)
        self.previous = key
        self.count += 1

    def close(self) -> None:
        if not self.closed:
            self._check()
            BTreeBuilder(self.records, self.fh, self.count, self.pagesize).build()
            self.records.close()
            super().close()

    def dispose(self) -> None:
        self.records.close()
        super().dispose()


class IDBWriter:
    """Write a version-6 container to a seekable binary output file.

    Caller owns the output handle. Sections use temporary files, not RAM.
    close() requires all allocated sections to have been closed explicitly.
    """

    def __init__(self, fh: BinaryIO, fileversion: int = 6, magic: str = 'IDA2', header_template: bytes = b'', header_value: Optional[bytes] = None):
        if fileversion != 6:
            raise ValueError('only container version 6 can be written')
        if magic not in ('IDA1', 'IDA2'):
            raise ValueError('output magic must be IDA1 or IDA2')
        self.fh = fh
        self.magic = magic
        self.fileversion = fileversion
        self.closed = False
        self.sections: list[Optional[SectionBuffer]] = [None] * 6
        self.header = bytearray(0xfc)
        if header_template:
            if len(header_template) < 0xfc:
                raise ValueError('version-6 header template is truncated')
            self.header[:] = header_template[:0xfc]
        else:
            struct.pack_into('<L', self.header, 0x58, 0x7c)
        if header_value is not None:
            if not isinstance(header_value, bytes) or len(header_value) != 16:
                raise ValueError('opaque header value must be 16 bytes')
            self.header[0x6c:0x7c] = header_value

    def allocatesection(self, cls: Type[SectionType], compression: int = 0, pagesize: int = 8192) -> Union[ID0Writer, SectionWriter]:
        index = cls.INDEX
        self._available(index)
        if compression not in (0, 2):
            raise ValueError('compression must be 0 or 2')
        section: Union[ID0Writer, SectionWriter]
        if index == 0:
            section = ID0Writer(self, index, compression, pagesize)
        else:
            section = SectionWriter(self, index, compression)
        self.sections[index] = section
        return section

    def _available(self, index: int) -> None:
        if self.closed:
            raise ValueError('writer is closed')
        if not 0 <= index < 6:
            raise ValueError('invalid section index')
        if self.sections[index] is not None:
            raise ValueError('section already allocated')

    def copysection(self, src: DatabaseSource, cls: Type[SectionType]) -> None:
        index = cls.INDEX
        self._available(index)
        compression, offset, size, checksum = src.getsectioninfo(index)
        if not offset or (src.fileversion == 910 and size == 0):
            return
        source = src.getstoredpart(index)
        if source is None:
            raise ValueError('source section is unavailable')
        section = SectionWriter(self, index, compression, stored=True)
        self.sections[index] = section
        crc = 0
        remaining = size
        while remaining:
            data = read_exact(source, min(remaining, 1024 * 1024))
            section.write(data)
            crc = zlib.crc32(data, crc)
            remaining -= len(data)
        if checksum and (crc & 0xffffffff) != checksum:
            raise ValueError('source section %d checksum mismatch' % index)
        section.close()

    def _section(self, section: SectionBuffer) -> tuple[int, int]:
        offset = self.fh.tell()
        write_exact(self.fh, bytes(9))
        section.fh.seek(0)
        compressor = (zlib.compressobj() if section.compression == 2
                      and not section.stored else None)
        size = 0
        crc = 0
        while True:
            data = section.fh.read(1024 * 1024)
            if not data:
                break
            stored = compressor.compress(data) if compressor else data
            write_exact(self.fh, stored)
            size += len(stored)
            crc = zlib.crc32(stored, crc)
        if compressor:
            stored = compressor.flush()
            write_exact(self.fh, stored)
            size += len(stored)
            crc = zlib.crc32(stored, crc)
        end = self.fh.tell()
        self.fh.seek(offset)
        write_exact(self.fh, struct.pack('<BQ', section.compression, size))
        self.fh.seek(end)
        return offset, crc & 0xffffffff

    def close(self) -> None:
        if self.closed:
            return
        if any(section is not None and not section.closed
               for section in self.sections):
            raise ValueError('close every allocated section first')
        try:
            self._finish()
        finally:
            self.abort()

    def _finish(self) -> None:
        self.fh.seek(0)
        self.fh.truncate(0)
        write_exact(self.fh, bytes(len(self.header)))
        offsets: list[int] = [0] * 6
        checksums: list[int] = [0] * 6
        for index, section in enumerate(self.sections):
            if section is not None:
                offsets[index], checksums[index] = self._section(section)
        self.header[:6] = self.magic.encode('ascii') + b'\0\0'
        struct.pack_into('<QQLLHQQQ5LQL', self.header, 6, offsets[0], offsets[1], 0, 0xaabbccdd, 6, *offsets[2:5], *checksums[:5], offsets[5], checksums[5])
        self.fh.seek(0)
        write_exact(self.fh, bytes(self.header))
        self.fh.flush()
        self.fh.seek(0, 2)

    def abort(self) -> None:
        for section in self.sections:
            if section is not None:
                section.dispose()
        self.closed = True

    def __enter__(self) -> IDBWriter:
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        if exc_type is not None:
            self.abort()
            return
        try:
            self.close()
        except BaseException:
            self.abort()
            raise
