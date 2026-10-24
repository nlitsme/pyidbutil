# written by chatgpt GPT-6
"""Tests of the downgrade transformation, verification, and CLI behavior."""
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

import idblib
from idbdowngrade import DatabasePaths, DowngradeError, DowngradeOptions, Downgrader, downgrade_file
from idbwrite import Record


@dataclass(frozen=True)
class Fixture:
    schema: int = 920
    label_number: int = 920
    label_string: bytes = b'9.3\0'
    magic: str = 'IDA2'

    def parameters(self) -> bytes:
        return b'IDA' + struct.pack('<H', self.schema) + b'\x06metapc\0opaque\xff\x00'

    def records(self) -> list[Record]:
        width = 8 if self.magic == 'IDA2' else 4
        root = (0xff << ((width - 1) * 8)) + 2
        prefix = b'.' + root.to_bytes(width, 'big')
        maximum = (1 << (8 * width)) - 1
        return sorted([
            Record(b'NRoot Node', root.to_bytes(width, 'little')),
            Record(prefix + b'A' + maximum.to_bytes(width, 'big'), self.label_number.to_bytes(width, 'little')),
            Record(prefix + b'S' + (1303).to_bytes(width, 'big'), self.label_string),
            Record(prefix + b'S' + (0x41b994).to_bytes(width, 'big'), self.parameters()),
            Record(b'.' + (0x1000).to_bytes(width, 'big') + b'S' + bytes(width), b'undecoded\0payload\xff'),
        ], key=lambda record: record.key)

    def write(self, path: Path, v910: bool = False) -> None:
        output = BytesIO()
        with idblib.IDBFile.create(output, magic=self.magic, header_value=bytes(range(16))) as dst:
            section = dst.allocatesection(idblib.ID0File)
            for record in self.records():
                section.write(record.key, record.value)
            section.close()
            section = dst.allocatesection(idblib.TILFile)
            section.write(b'opaque type contents - do not decode or drop')
            section.close()
        if not v910:
            path.write_bytes(output.getvalue())
            return
        db = idblib.IDBFile(output)
        sections: list[bytes] = []
        for index in range(6):
            part = db.getpart(index)
            sections.append(part.read() if part is not None else b'')
        header = bytearray(0xed)
        header[:4] = self.magic.encode('ascii')
        struct.pack_into('<3QHB6Q', header, 6, 0x6d, 0xed, 0xaabbccdd00000000, 910, 0, *[len(data) for data in sections])
        header[0x5d:0x6d] = bytes(range(16))
        body = b''.join(sections)
        path.write_bytes(header + body + struct.pack('<L', zlib.crc32(body)))


class DowngradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.paths = DatabasePaths(self.root / 'source.i64', self.root / 'output.i64')

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_output(self, fixture: Fixture, labels: bool = True) -> None:
        with self.paths.output.open('rb') as fh:
            db = idblib.IDBFile(fh)
            id0 = db.getsection(idblib.ID0File)
            self.assertEqual(db.fileversion, 6)
            self.assertEqual(db.magic, fixture.magic)
            self.assertEqual(db.header_value, bytes(range(16)))
            self.assertEqual(id0.idbparams[:5], b'IDAH\x03')
            self.assertEqual(id0.idbparams[5:], fixture.parameters()[5:])
            self.assertEqual(len(id0.idbparams), len(fixture.parameters()))
            self.assertEqual(id0.idaver, min(fixture.label_number, 840) if labels else fixture.label_number)
            expected_string = b'8.4' + (b'\0' if fixture.label_string.endswith(b'\0') else b'')
            self.assertEqual(id0.idaverstr.encode(), (expected_string if labels else fixture.label_string).rstrip(b'\0'))
            self.assertEqual(db.getpart(4).read(), b'opaque type contents - do not decode or drop')
            self.assertIsNone(db.getpart(1))
            self.assertEqual(id0.btree.reccount, len(fixture.records()))
            self.assertEqual(id0.btree.firstindex, 1)
            self.assertEqual(id0.btree.firstfree, 2)

    def test_v6_and_v910_fresh_database(self) -> None:
        for v910 in (False, True):
            with self.subTest(v910=v910):
                fixture = Fixture()
                fixture.write(self.paths.source, v910)
                result = downgrade_file(self.paths)
                self.assertEqual(len(result.plan.changes), 3)
                self.assertEqual(result.records, len(fixture.records()))
                self.assert_output(fixture)
                self.paths.output.unlink()

    def test_converted_database_only_changes_parameter_version(self) -> None:
        fixture = Fixture(label_number=840, label_string=b'8.4')
        fixture.write(self.paths.source, True)
        result = downgrade_file(self.paths)
        self.assertEqual(len(result.plan.changes), 1)
        self.assert_output(fixture)

    def test_preserve_labels_and_compress_id0(self) -> None:
        fixture = Fixture()
        fixture.write(self.paths.source)
        options = DowngradeOptions(compress_id0=True, preserve_version_labels=True)
        result = downgrade_file(self.paths, options)
        self.assertEqual(len(result.plan.changes), 1)
        self.assert_output(fixture, labels=False)
        with self.paths.output.open('rb') as fh:
            self.assertEqual(idblib.IDBFile(fh).getsectioninfo(0)[0], 2)

    def test_32bit_encoding_is_retained(self) -> None:
        fixture = Fixture(magic='IDA1')
        fixture.write(self.paths.source)
        downgrade_file(self.paths)
        self.assert_output(fixture)

    def test_dry_run_does_not_create_or_modify_output(self) -> None:
        Fixture().write(self.paths.source)
        result = downgrade_file(DatabasePaths(self.paths.source), dry_run=True)
        self.assertTrue(result.dry_run)
        self.assertFalse(self.paths.output.exists())
        self.paths.output.write_bytes(b'keep existing output')
        downgrade_file(self.paths, dry_run=True)
        self.assertEqual(self.paths.output.read_bytes(), b'keep existing output')

    def test_output_and_source_are_never_overwritten(self) -> None:
        Fixture().write(self.paths.source)
        original = self.paths.source.read_bytes()
        self.paths.output.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            downgrade_file(self.paths)
        with self.assertRaises(FileExistsError):
            downgrade_file(DatabasePaths(self.paths.source, self.paths.source))
        self.assertEqual(self.paths.source.read_bytes(), original)
        self.assertEqual(self.paths.output.read_bytes(), b'keep')

    def test_untested_schema_requires_explicit_option(self) -> None:
        fixture = Fixture(schema=930)
        fixture.write(self.paths.source)
        with self.assertRaisesRegex(DowngradeError, 'untested parameter version'):
            downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())
        result = downgrade_file(self.paths, DowngradeOptions(allow_untested_schema=True))
        self.assertTrue(any('Untested source schema' in note for note in result.plan.notes))
        self.assert_output(fixture)

    def test_older_schema_is_rejected_without_output(self) -> None:
        Fixture(schema=700).write(self.paths.source)
        with self.assertRaises(DowngradeError):
            downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())

    def test_already_84_is_idempotent(self) -> None:
        fixture = Fixture(schema=840, label_number=840, label_string=b'8.4')
        fixture.write(self.paths.source)
        result = downgrade_file(self.paths)
        self.assertEqual(len(result.plan.changes), 0)
        self.assert_output(fixture)

    def test_verification_failure_removes_partial_output(self) -> None:
        Fixture().write(self.paths.source)
        with patch.object(Downgrader, '_verify_output', side_effect=DowngradeError('injected verification failure')):
            with self.assertRaisesRegex(DowngradeError, 'verification failure'):
                downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())

    def test_corrupt_source_id0_is_rejected(self) -> None:
        Fixture().write(self.paths.source)
        raw = bytearray(self.paths.source.read_bytes())
        with self.paths.source.open('rb') as fh:
            _, offset, size, _ = idblib.IDBFile(fh).getsectioninfo(0)
        raw[offset + size - 1] ^= 1
        self.paths.source.write_bytes(raw)
        with self.assertRaisesRegex(DowngradeError, 'source ID0 checksum'):
            downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())

    def test_cli(self) -> None:
        Fixture().write(self.paths.source, True)
        script = Path(__file__).with_name('idbdowngrade.py')
        command = [sys.executable, str(script), str(self.paths.source)]
        result = subprocess.run(command + ['--dry-run'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Planned', result.stdout)
        result = subprocess.run(command + [str(self.paths.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Written and verified', result.stdout)
        result = subprocess.run(command + [str(self.paths.output)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)


    def test_older_labels_are_not_raised(self) -> None:
        Fixture(label_number=700, label_string=b'7.0').write(self.paths.source)
        result = downgrade_file(self.paths)
        self.assertEqual(len(result.plan.changes), 1)
        with self.paths.output.open('rb') as fh:
            id0 = idblib.IDBFile(fh).getsection(idblib.ID0File)
            self.assertEqual(id0.idaver, 700)
            self.assertEqual(id0.idaverstr, '7.0')

    def test_unknown_label_is_retained_and_reported(self) -> None:
        Fixture(label_string=b'unknown label').write(self.paths.source)
        result = downgrade_file(self.paths)
        self.assertTrue(any('undecoded' in note for note in result.plan.notes))
        with self.paths.output.open('rb') as fh:
            self.assertEqual(idblib.IDBFile(fh).getsection(idblib.ID0File).idaverstr, 'unknown label')

    def test_missing_root_and_bad_parameters_fail_before_creation(self) -> None:
        records = [record for record in Fixture().records() if record.key != b'NRoot Node']
        with patch.object(Fixture, 'records', return_value=records):
            Fixture().write(self.paths.source)
        with self.assertRaisesRegex(DowngradeError, 'Root Node is missing'):
            downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())
        with patch.object(Fixture, 'parameters', return_value=b'bad header'):
            Fixture().write(self.paths.source)
        with self.assertRaisesRegex(DowngradeError, 'invalid Root Node parameter record'):
            downgrade_file(self.paths)
        self.assertFalse(self.paths.output.exists())
