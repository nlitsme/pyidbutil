# written by chatgpt GPT-6
"""v910 whole-stream compression and decompressed-trailer CRC regressions."""
from dataclasses import dataclass
from io import BytesIO
import struct
from typing import Optional
import unittest
from unittest.mock import patch
import zlib

import idblib
from idb910 import V910Payload

try:
    from compression import zstd
except ImportError:
    try:
        from backports import zstd
    except ImportError:
        zstd = None


@dataclass(frozen=True)
class Fixture:
    sections: tuple[bytes, ...]

    def stream(self) -> bytes:
        data = b''.join(self.sections)
        return data + struct.pack('<L', zlib.crc32(data) & 0xffffffff)

    def container(self, compression: int = 0,
                  encoded: Optional[bytes] = None) -> BytesIO:
        header = bytearray(256)
        header[:4] = b'IDA2'
        struct.pack_into('<3QHB6Q', header, 6, 256, 256,
                         0xaabbccdd00000000, 910, compression,
                         *[len(section) for section in self.sections])
        if encoded is None:
            encoded = self.stream()
            if compression == 3:
                encoded = zstd.compress(encoded)
        return BytesIO(header + encoded)


class V910Tests(unittest.TestCase):
    def fixture(self) -> Fixture:
        return Fixture((b'first', b'next' * 100, b'', b'', b'til', b'id2'))

    def assert_sections(self, fixture: Fixture, compression: int) -> None:
        source = fixture.container(compression)
        db = idblib.IDBFile(source)
        try:
            for index, section in enumerate(fixture.sections):
                part = db.getpart(index)
                if section:
                    self.assertEqual(part.read(), section)
                else:
                    self.assertIsNone(part)
            self.assertEqual(db._payload.crc,
                             zlib.crc32(b''.join(fixture.sections)))
            # Interleave section reads sharing the temporary backing stream.
            first, second = db.getpart(0), db.getpart(1)
            if first is not None and second is not None:
                self.assertEqual(first.read(1), fixture.sections[0][:1])
                self.assertEqual(second.read(2), fixture.sections[1][:2])
                self.assertEqual(first.read(), fixture.sections[0][1:])
            self.assertEqual(db.getsectioninfo(6), (0, 0, 0, 0))
        finally:
            db.close()
        self.assertFalse(source.closed)
        self.assertTrue(db._payload.fh.closed)

    def test_uncompressed_sections_and_empty_stream(self) -> None:
        self.assert_sections(self.fixture(), 0)
        self.assert_sections(Fixture((b'',) * 6), 0)

    def test_empty_first_section(self) -> None:
        fixture = Fixture((b'', b'id1', b'nam', b'', b'', b''))
        self.assert_sections(fixture, 0)
        db = idblib.IDBFile(fixture.container())
        try:
            with idblib.IDBFile.create(BytesIO()) as dst:
                dst.copysection(db, idblib.ID1File)
                dst.copysection(db, idblib.ID0File)
        finally:
            db.close()

    def test_corrupt_uncompressed_streams(self) -> None:
        raw = self.fixture().stream()
        for encoded in (raw[:-1], raw[:-4], raw + b'X',
                        b'X' + raw[1:], raw[:-4] + bytes(4)):
            with self.subTest(size=len(encoded)):
                with self.assertRaises(ValueError):
                    idblib.IDBFile(self.fixture().container(encoded=encoded))

    def test_header_sizes_are_enforced(self) -> None:
        raw = self.fixture().container().getvalue()
        header = bytearray(raw[:256])
        for size in (1, 10**9):
            struct.pack_into('<Q', header, 0x21, size)
            with self.assertRaises(ValueError):
                idblib.IDBFile(BytesIO(header + raw[256:]))

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_zstd_sections_and_empty_stream(self) -> None:
        with patch.object(V910Payload, 'CHUNK', 7):
            self.assert_sections(self.fixture(), 3)
            self.assert_sections(Fixture((b'',) * 6), 3)

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_zstd_high_expansion(self) -> None:
        fixture = Fixture((b'a', b'z' * (3 * 1024 * 1024), b'', b'', b'', b''))
        self.assert_sections(fixture, 3)

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_zstd_truncated_frame_footer(self) -> None:
        options: dict[int, int] = {zstd.CompressionParameter.checksum_flag: 1}
        encoded = zstd.compress(self.fixture().stream(), options=options)
        for cut in (1, 4, 5, len(encoded)):
            with self.assertRaises((ValueError, zstd.ZstdError)):
                idblib.IDBFile(self.fixture().container(3, encoded[:-cut]))

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_zstd_payload_crc_is_validated(self) -> None:
        raw = self.fixture().stream()
        corrupt = raw[:-4] + bytes(4)
        with self.assertRaisesRegex(ValueError, 'CRC mismatch'):
            idblib.IDBFile(self.fixture().container(3, zstd.compress(corrupt)))
        with self.assertRaises((ValueError, zstd.ZstdError)):
            encoded = zstd.compress(raw) + b'junk'
            idblib.IDBFile(self.fixture().container(3, encoded))

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_concatenated_frames_split_crc(self) -> None:
        raw = self.fixture().stream()
        encoded = zstd.compress(raw[:-2]) + zstd.compress(raw[-2:])
        db = idblib.IDBFile(self.fixture().container(3, encoded))
        try:
            self.assertEqual(db.getpart(1).read(), self.fixture().sections[1])
        finally:
            db.close()

    @unittest.skipIf(zstd is None, 'requires compression.zstd/backports.zstd')
    def test_zstd_to_v6_rebuild_and_raw_copy(self) -> None:
        original = BytesIO()
        with idblib.IDBFile.create(original) as dst:
            section = dst.allocatesection(idblib.ID0File)
            for index in range(200):
                section.write(index.to_bytes(8, 'big'), b'val')
            section.close()
        src = idblib.IDBFile(original)
        fixture = Fixture((src.getpart(0).read(), b'id1', b'nam', b'',
                           b'opaque til', b'opaque id2'))
        output = BytesIO()
        idblib.updateidb(fixture.container(3), output, compression=2)
        result = idblib.IDBFile(output)
        tree = result.getsection(idblib.ID0File).btree
        for index in range(200):
            cursor = tree.find('eq', index.to_bytes(8, 'big'))
            self.assertEqual(cursor.getval(), b'val')
        for index in range(1, 6):
            part = result.getpart(index)
            if fixture.sections[index]:
                self.assertEqual(part.read(), fixture.sections[index])
            else:
                self.assertIsNone(part)
        db = idblib.IDBFile(fixture.container(3))
        try:
            copied = BytesIO()
            with idblib.IDBFile.create(copied) as dst:
                dst.copysection(db, idblib.ID0File)
            self.assertEqual(idblib.IDBFile(copied).getpart(0).read(),
                             fixture.sections[0])
        finally:
            db.close()
