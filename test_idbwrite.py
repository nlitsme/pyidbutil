# written by chatgpt GPT-6
"""Writer regressions, including on-disk layout and B-tree invariants."""
from io import BytesIO
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
import zlib

import idblib
from idbwrite import Record


class WriterTests(unittest.TestCase):
    @staticmethod
    def records(count: int) -> list[Record]:
        return [Record(index.to_bytes(4, 'big'), bytes([index % 256]))
                for index in range(count)]

    def database(self, count: int, compression: int = 0,
                 magic: str = 'IDA2', pagesize: int = 128) -> BytesIO:
        output = BytesIO()
        with idblib.IDBFile.create(output, magic=magic) as dst:
            section = dst.allocatesection(idblib.ID0File,
                                          compression=compression,
                                          pagesize=pagesize)
            for record in self.records(count):
                section.write(record.key, record.value)
            section.close()
        return output

    def assert_records(self, db: idblib.IDBFile, count: int) -> None:
        tree = db.getsection(idblib.ID0File).btree
        cursor = tree.find('ge', b'')
        for record in self.records(count):
            self.assertFalse(cursor.eof())
            self.assertEqual(cursor.getkey(), record.key)
            self.assertEqual(cursor.getval(), record.value)
            cursor.next()
        self.assertTrue(cursor.eof())
        if count:
            cursor = tree.find('le', b'\xff' * 8)
            for record in reversed(self.records(count)):
                self.assertEqual(cursor.getkey(), record.key)
                cursor.prev()
            self.assertTrue(cursor.eof())
        else:
            self.assertIsNone(tree.find('eq', b'absent'))

    def test_tree_boundaries_and_heights(self) -> None:
        for count in (0, 1, 7, 8, 15, 63, 64, 100, 511, 1000):
            with self.subTest(count=count):
                db = idblib.IDBFile(self.database(count))
                self.assert_records(db, count)
                tree = db.getsection(idblib.ID0File).btree
                self.assertEqual(tree.reccount, count)
                self.assertEqual((tree.pagecount + 2) * tree.pagesize,
                                 db.getsectioninfo(0)[2])
                seen: set[int] = set()
                depths: set[int] = set()
                self.check_pages(tree, tree.firstindex, seen, depths, 0)
                self.assertEqual(len(seen), tree.pagecount)
                self.assertEqual(len(depths), 1)

    def check_pages(self, tree: idblib.BTree, number: int, seen: set[int],
                    depths: set[int], depth: int) -> None:
        self.assertNotIn(number, seen)
        seen.add(number)
        page = tree.readpage(number)
        self.assertEqual(page.unknown, 0)
        if page.isleaf():
            depths.add(depth)
        else:
            for index in range(-1, page.count):
                self.check_pages(tree, page.getpage(index), seen,
                                 depths, depth + 1)

    def test_search_relations(self) -> None:
        db = idblib.IDBFile(self.database(100))
        tree = db.getsection(idblib.ID0File).btree
        for index in range(100):
            key = index.to_bytes(4, 'big')
            self.assertEqual(tree.find('eq', key).getkey(), key)
            self.assertEqual(tree.find('ge', key).getkey(), key)
            self.assertEqual(tree.find('le', key).getkey(), key)
            lesser = tree.find('lt', key)
            greater = tree.find('gt', key)
            self.assertEqual(lesser.eof(), index == 0)
            self.assertEqual(greater.eof(), index == 99)
            if index:
                self.assertEqual(lesser.getkey(),
                                 (index - 1).to_bytes(4, 'big'))
            if index < 99:
                self.assertEqual(greater.getkey(),
                                 (index + 1).to_bytes(4, 'big'))

    def test_checksums_width_and_compression(self) -> None:
        for magic in ('IDA1', 'IDA2'):
            for compression in (0, 2):
                output = self.database(100, compression, magic)
                db = idblib.IDBFile(output)
                self.assertEqual(db.magic, magic)
                comp, offset, size, checksum = db.getsectioninfo(0)
                self.assertEqual(comp, compression)
                stored = output.getvalue()[offset:offset + size]
                self.assertEqual(checksum, zlib.crc32(stored) & 0xffffffff)
                self.assert_records(db, 100)

    def test_copy_all_sections_and_header_extension(self) -> None:
        original = self.database(30)
        source = idblib.IDBFile(original)
        output = BytesIO()
        template = bytearray(source.headerdata)
        template[0x6c:0x7c] = bytes(range(16))
        with idblib.IDBFile.create(output, header_template=template) as dst:
            dst.copysection(source, idblib.ID0File)
            for cls in (idblib.ID1File, idblib.NAMFile, idblib.SEGFile,
                        idblib.TILFile, idblib.ID2File):
                section = dst.allocatesection(cls, compression=2)
                section.write(bytes([cls.INDEX]) * 150)
                section.close()
        rewritten = BytesIO()
        idblib.updateidb(output, rewritten, compression=2)
        result = idblib.IDBFile(rewritten)
        self.assert_records(result, 30)
        self.assertEqual(result.headerdata[0x6c:0x7c], bytes(range(16)))
        for index in range(1, 6):
            self.assertEqual(result.getpart(index).read(),
                             bytes([index]) * 150)
            old = idblib.IDBFile(output).getsectioninfo(index)
            new = result.getsectioninfo(index)
            self.assertEqual(old[2:], new[2:])

    def test_absent_and_empty_sections(self) -> None:
        output = BytesIO()
        with idblib.IDBFile.create(output) as dst:
            dst.allocatesection(idblib.TILFile).close()
        source = idblib.IDBFile(output)
        self.assertIsNone(source.getsection(idblib.ID0File))
        self.assertEqual(source.getpart(4).read(), b'')
        rewritten = BytesIO()
        idblib.updateidb(output, rewritten)
        db = idblib.IDBFile(rewritten)
        self.assertIsNone(db.getpart(0))
        self.assertIsNotNone(db.getpart(4))

    def test_version_910_conversion(self) -> None:
        source = idblib.IDBFile(self.database(10))
        data = source.getpart(0).read()
        header = bytearray(256)
        header[:4] = b'IDA2'
        struct.pack_into('<3QHB6Q', header, 6, 256, 256,
                         0xaabbccdd00000000, 910, 0,
                         len(data), 0, 0, 0, 0, 0)
        output = BytesIO()
        trailer = struct.pack('<L', zlib.crc32(data) & 0xffffffff)
        idblib.updateidb(BytesIO(header + data + trailer), output)
        result = idblib.IDBFile(output)
        self.assertEqual(result.fileversion, 6)
        self.assert_records(result, 10)
        self.assertEqual(result.offsets[1:], [0] * 5)

    def test_validation_and_lifecycle(self) -> None:
        output = BytesIO()
        dst = idblib.IDBFile.create(output)
        section = dst.allocatesection(idblib.ID0File)
        with self.assertRaises(ValueError):
            dst.close()
        section.write(b'b', b'1')
        for key in (b'a', b'b'):
            with self.assertRaises(ValueError):
                section.write(key, b'2')
        with self.assertRaises(ValueError):
            dst.allocatesection(idblib.ID0File)
        section.close()
        with self.assertRaises(ValueError):
            section.write(b'c', b'3')
        dst.close()
        dst.close()
        self.assertFalse(output.closed)
        with self.assertRaises(ValueError):
            idblib.updateidb(output, output)
        with self.assertRaises(ValueError):
            idblib.IDBFile.create(BytesIO(), fileversion=910)

    def test_corrupt_and_truncated_section_copy(self) -> None:
        original = self.database(10).getvalue()
        for damaged in (original[:-1], original[:-1] + b'X'):
            with idblib.IDBFile.create(BytesIO()) as dst:
                with self.assertRaises(ValueError):
                    dst.copysection(idblib.IDBFile(BytesIO(damaged)),
                                    idblib.ID0File)
                dst.abort()

    def test_key_and_page_size_limits(self) -> None:
        with idblib.IDBFile.create(BytesIO()) as dst:
            section = dst.allocatesection(idblib.ID0File, pagesize=128)
            for key, value in ((b'a', b'x' * 100), (b'b', b'x' * 65536)):
                with self.assertRaises(ValueError):
                    section.write(key, value)
            section.close()


    def test_cli_output_protection_and_cleanup(self) -> None:
        script = Path(__file__).with_name('idbrewrite.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.i64'
            output = root / 'output.i64'
            source.write_bytes(self.database(10).getvalue())
            command = [sys.executable, str(script),
                       str(source), str(output)]
            subprocess.run(command, check=True, capture_output=True)
            contents = output.read_bytes()
            result = subprocess.run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), contents)
            output.unlink()
            source.write_bytes(b'bad input')
            result = subprocess.run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_varied_record_lengths(self) -> None:
        output = BytesIO()
        records = [Record(index.to_bytes(8, 'big'),
                          bytes([index % 256]) * (index % 101))
                   for index in range(1500)]
        with idblib.IDBFile.create(output) as dst:
            section = dst.allocatesection(idblib.ID0File, pagesize=512)
            for record in records:
                section.write(record.key, record.value)
            section.close()
        tree = idblib.IDBFile(output).getsection(idblib.ID0File).btree
        for record in records:
            self.assertEqual(tree.find('eq', record.key).getval(),
                             record.value)


    def test_exact_v2_signature_and_closed_marker(self) -> None:
        # Exact bytes from the user-supplied IDA 8.4 and 9.x databases.
        for count in (0, 1, 1000):
            db = idblib.IDBFile(self.database(count))
            header = db.getpart(0).read(128)
            self.assertEqual(header[0x13:0x1e], b'B-tree v2\0\1')
            self.assertEqual(header[0x1e:], bytes(128 - 0x1e))


    def test_explicit_opaque_header_value(self) -> None:
        value = bytes(range(16))
        output = BytesIO()
        with idblib.IDBFile.create(output, header_value=value):
            pass
        self.assertEqual(idblib.IDBFile(output).header_value, value)
        for invalid in (b'', b'1' * 15, b'1' * 17, '1' * 16):
            with self.assertRaises(ValueError):
                idblib.IDBFile.create(BytesIO(), header_value=invalid)

    def test_v910_opaque_header_value_is_relocated(self) -> None:
        value = bytes(range(16))
        header = bytearray(256)
        header[:4] = b'IDA2'
        struct.pack_into('<3QHB6Q', header, 6, 109, 256,
                         0xaabbccdd00000000, 910, 0, 0, 0, 0, 0, 0, 0)
        header[0x5d:0x6d] = value
        source = BytesIO(header + struct.pack('<L', 0))
        result = BytesIO()
        idblib.updateidb(source, result)
        db = idblib.IDBFile(result)
        self.assertEqual(db.header_value, value)
        self.assertEqual(db.headerdata[0x6c:0x7c], value)
        self.assertEqual(db.headerdata[0x58:0x5c], b'\x7c\0\0\0')


    def test_nonzero_empty_free_list(self) -> None:
        for count in (0, 1, 1000):
            db = idblib.IDBFile(self.database(count))
            part = db.getpart(0)
            tree = idblib.BTree(part)
            self.assertNotEqual(tree.firstfree, 0)
            self.assertEqual(tree.firstfree, 2)
            self.assertEqual(tree.firstindex, 1)
            self.assertNotEqual(tree.firstindex, tree.firstfree)
            part.seek(tree.firstfree * tree.pagesize)
            self.assertEqual(part.read(tree.pagesize), bytes(tree.pagesize))
            seen: set[int] = set()
            depths: set[int] = set()
            self.check_pages(tree, tree.firstindex, seen, depths, 0)
            self.assertNotIn(tree.firstfree, seen)
            self.assertEqual(len(seen), tree.pagecount)


    def test_prefix_packing_and_balanced_variable_records(self) -> None:
        output = BytesIO()
        records = [Record(b'.' + b'\xff' * 7 + index.to_bytes(8, 'big'),
                          b'v' * (1024 if index % 173 == 0 else index % 13))
                   for index in range(1500)]
        with idblib.IDBFile.create(output) as dst:
            section = dst.allocatesection(idblib.ID0File)
            for record in records:
                section.write(record.key, record.value)
            section.close()
        db = idblib.IDBFile(output)
        tree = db.getsection(idblib.ID0File).btree
        self.assertEqual(tree.firstindex, 1)
        self.assertEqual(tree.firstfree, 2)
        self.assertLess(tree.pagecount, 16)
        seen: set[int] = set()
        depths: set[int] = set()
        self.check_pages(tree, tree.firstindex, seen, depths, 0)
        self.assertEqual(len(depths), 1)
        self.assertNotIn(2, seen)
        cursor = tree.find('ge', b'')
        for record in records:
            self.assertEqual(cursor.getkey(), record.key)
            self.assertEqual(cursor.getval(), record.value)
            cursor.next()
        self.assertTrue(cursor.eof())
        cursor = tree.find('le', b'\xff' * 20)
        for record in reversed(records):
            self.assertEqual(cursor.getkey(), record.key)
            self.assertEqual(cursor.getval(), record.value)
            cursor.prev()
        self.assertTrue(cursor.eof())
