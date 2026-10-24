# written by chatgpt GPT-6
"""Anonymizer regression tests: record removal, filenames, comments, and residues."""
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
from idbanonymize import AnonymizeError, AnonymizeOptions, Anonymizer, anonymize_file
from idbtransform import DatabasePaths
from idbwrite import Record


LICENSE_PAYLOAD = b'license-marker: Alice Example <alice@example.test>; id=unique-license-test'
JSON_PAYLOAD = b'{"license":"unique-json-test","owner":"Alice Example"}'


@dataclass(frozen=True)
class Fixture:
    magic: str = 'IDA2'
    filename: bytes = b'/home/alice/private-project/sample.exe\0'
    comment: bytes = b'Input file: /home/alice/private-project/sample.exe; unrelated analysis stays'
    opaque: bytes = b'opaque types - preserve'
    user: bool = True

    def prefix(self, number: int) -> bytes:
        width = 8 if self.magic == 'IDA2' else 4
        return b'.' + ((0xff << ((width - 1) * 8)) + number).to_bytes(width, 'big')

    def key(self, prefix: bytes, tag: bytes, index: int) -> bytes:
        width = 8 if self.magic == 'IDA2' else 4
        return prefix + tag + index.to_bytes(width, 'big')

    def records(self) -> list[Record]:
        width = 8 if self.magic == 'IDA2' else 4
        root = self.prefix(2)
        address = b'.' + (0x1000).to_bytes(width, 'big')
        records = [
            Record(b'NRoot Node', int.from_bytes(root[1:], 'big').to_bytes(width, 'little')),
            Record(root + b'N', b'Root Node'),
            Record(root + b'V', self.filename),
            Record(self.key(root, b'S', 0x41b994), b'IDA\x98\x03opaque\0parameters\xff'),
            Record(self.key(address, b'S', 1000), self.comment),
            Record(self.key(address, b'S', 1), b'Unrelated repeatable comment\0'),
            Record(self.key(address, b'S', 2000), b'See sample.exe for source; analysis stays'),
        ]
        if self.user:
            for number, name in ((3, b'$ original user'), (4, b'$ user1')):
                prefix = self.prefix(number)
                records.extend([
                    Record(b'N' + name, int.from_bytes(prefix[1:], 'big').to_bytes(width, 'little')),
                    Record(prefix + b'N', name),
                    Record(self.key(prefix, b'S', 0), LICENSE_PAYLOAD),
                    Record(self.key(prefix, b'S', 1), b'\x12\x34\x56\x78\x9a\xbc'),
                    Record(self.key(prefix, b'S', 16), JSON_PAYLOAD),
                    Record(self.key(prefix, b'S', 17), b'json-fragment-tail'),
                ])
        return sorted(records, key=lambda record: record.key)

    def write(self, path: Path, v910: bool = False) -> None:
        output = BytesIO()
        with idblib.IDBFile.create(output, magic=self.magic, header_value=bytes(range(16))) as dst:
            writer = dst.allocatesection(idblib.ID0File)
            for record in self.records():
                writer.write(record.key, record.value)
            writer.close()
            raw = dst.allocatesection(idblib.TILFile)
            raw.write(self.opaque)
            raw.close()
        if not v910:
            path.write_bytes(output.getvalue())
            return
        db = idblib.IDBFile(output)
        id0 = db.getpart(0).read()
        header = bytearray(0xed)
        header[:4] = self.magic.encode()
        struct.pack_into('<3QHB6Q', header, 6, 0x6d, 0xed, 0xaabbccdd00000000, 910, 0, len(id0), 0, 0, 0, len(self.opaque), 0)
        header[0x5d:0x6d] = bytes(range(16))
        body = id0 + self.opaque
        path.write_bytes(header + body + struct.pack('<L', zlib.crc32(body)))


class AnonymizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.paths = DatabasePaths(self.root / 'source.i64', self.root / 'anonymous.i64')

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_output(self, fixture: Fixture, filename: bytes = b'input.bin') -> None:
        with self.paths.output.open('rb') as fh:
            db = idblib.IDBFile(fh)
            id0 = db.getsection(idblib.ID0File)
            self.assertEqual(db.magic, fixture.magic)
            self.assertEqual(db.header_value, bytes(range(16)))
            self.assertEqual(id0.bytes(id0.root, 'V'), filename + b'\0')
            self.assertEqual(id0.idbparams, b'IDA\x98\x03opaque\0parameters\xff')
            for name in ('$ original user', '$ user1'):
                node = id0.nodeByName(name)
                self.assertIsNotNone(node)
                cursor = id0.btree.find('ge', id0.makekey(node))
                while not cursor.eof() and cursor.getkey().startswith(id0.makekey(node)):
                    self.assertEqual(cursor.getkey(), id0.makekey(node, 'N'))
                    cursor.next()
            self.assertEqual(db.getpart(4).read(), fixture.opaque)
        raw = self.paths.output.read_bytes()
        self.assertNotIn(LICENSE_PAYLOAD, raw)
        self.assertNotIn(JSON_PAYLOAD, raw)
        self.assertNotIn(b'private-project', raw)

    def test_v6_v910_and_both_widths(self) -> None:
        for magic in ('IDA1', 'IDA2'):
            for v910 in (False, True):
                fixture = Fixture(magic=magic)
                fixture.write(self.paths.source, v910)
                result = anonymize_file(self.paths)
                self.assertEqual(len(result.plan.removed), 8)
                self.assertEqual(result.plan.changed_comments, 2)
                self.assertEqual(len(result.plan.changes), 3)
                self.assertEqual(result.input_records - result.output_records, 8)
                self.assertFalse(result.residual_sections)
                self.assert_output(fixture)
                self.paths.output.unlink()

    def test_old_free_page_payload_is_not_copied(self) -> None:
        fixture = Fixture()
        fixture.write(self.paths.source)
        raw = bytearray(self.paths.source.read_bytes())
        with self.paths.source.open('rb') as fh:
            db = idblib.IDBFile(fh)
            _, offset, size, _ = db.getsectioninfo(0)
            tree = db.getsection(idblib.ID0File).btree
            start = offset + tree.firstfree * tree.pagesize + 32
        raw[start:start + len(LICENSE_PAYLOAD)] = LICENSE_PAYLOAD
        struct.pack_into('<L', raw, 0x38, zlib.crc32(raw[offset:offset + size]))
        self.paths.source.write_bytes(raw)
        anonymize_file(self.paths)
        self.assert_output(fixture)

    def test_windows_paths_and_custom_filename(self) -> None:
        fixture = Fixture(filename=b'C:\\Users\\Alice\\sample.exe\0', comment=b'Input file: C:/Users/Alice/sample.exe; unrelated analysis stays')
        fixture.write(self.paths.source)
        anonymize_file(self.paths, AnonymizeOptions(filename='shared.exe'))
        self.assert_output(fixture, b'shared.exe')

    def test_dry_run_does_not_expose_values_or_write_output(self) -> None:
        Fixture().write(self.paths.source)
        result = anonymize_file(DatabasePaths(self.paths.source), dry_run=True)
        self.assertTrue(result.dry_run)
        self.assertFalse(self.paths.output.exists())
        script = Path(__file__).with_name('idbanonymize.py')
        completed = subprocess.run([sys.executable, str(script), '--dry-run', str(self.paths.source)], check=True, capture_output=True)
        self.assertNotIn(b'alice', completed.stdout.lower())
        self.assertNotIn(b'license-marker', completed.stdout)
        self.assertNotIn(b'private-project', completed.stdout)

    def test_residue_in_opaque_section_fails_and_cleans_up(self) -> None:
        Fixture(opaque=LICENSE_PAYLOAD).write(self.paths.source)
        with self.assertRaisesRegex(AnonymizeError, 'remain in sections 4'):
            anonymize_file(self.paths)
        self.assertFalse(self.paths.output.exists())
        result = anonymize_file(self.paths, AnonymizeOptions(allow_residuals=True))
        self.assertEqual(result.residual_sections, (4,))
        self.assertTrue(self.paths.output.exists())

    def test_opaque_binary_record_is_not_blindly_rewritten(self) -> None:
        fixture = Fixture()
        records = fixture.records() + [Record(fixture.key(fixture.prefix(2), b'S', 123), b'opaque /home/alice/private-project/sample.exe value')]
        with patch.object(Fixture, 'records', return_value=sorted(records, key=lambda record: record.key)):
            fixture.write(self.paths.source)
        with self.assertRaisesRegex(AnonymizeError, 'remain in sections 0'):
            anonymize_file(self.paths)
        self.assertFalse(self.paths.output.exists())

    def test_idempotence(self) -> None:
        Fixture().write(self.paths.source)
        anonymize_file(self.paths)
        second = self.root / 'second.i64'
        result = anonymize_file(DatabasePaths(self.paths.output, second))
        self.assertEqual(len(result.plan.removed), 0)
        self.assertEqual(len(result.plan.changes), 0)
        self.assertEqual(second.read_bytes(), self.paths.output.read_bytes())

    def test_existing_output_and_source_are_protected(self) -> None:
        Fixture().write(self.paths.source)
        self.paths.output.write_bytes(b'keep')
        before = self.paths.source.read_bytes()
        with self.assertRaises(FileExistsError):
            anonymize_file(self.paths)
        with self.assertRaises(FileExistsError):
            anonymize_file(DatabasePaths(self.paths.source, self.paths.source))
        self.assertEqual(self.paths.output.read_bytes(), b'keep')
        self.assertEqual(self.paths.source.read_bytes(), before)

    def test_verification_error_removes_partial_output(self) -> None:
        Fixture().write(self.paths.source)
        with patch.object(Anonymizer, '_verify', side_effect=AnonymizeError('injected verification failure')):
            with self.assertRaises(AnonymizeError):
                anonymize_file(self.paths)
        self.assertFalse(self.paths.output.exists())

    def test_invalid_filename_and_unknown_encoding(self) -> None:
        Fixture().write(self.paths.source)
        for name in ('', '../escape', 'C:\\escape', 'bad\0name'):
            with self.assertRaises(AnonymizeError):
                anonymize_file(self.paths, AnonymizeOptions(filename=name))
            self.assertFalse(self.paths.output.exists())
        Fixture(filename=b'\xff\0').write(self.paths.source)
        with self.assertRaisesRegex(AnonymizeError, 'undecoded filename'):
            anonymize_file(self.paths)

    def test_compressed_output_and_cli(self) -> None:
        fixture = Fixture()
        fixture.write(self.paths.source, True)
        script = Path(__file__).with_name('idbanonymize.py')
        result = subprocess.run([sys.executable, str(script), '--compress-id0', str(self.paths.source), str(self.paths.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Written and verified', result.stdout)
        with self.paths.output.open('rb') as fh:
            self.assertEqual(idblib.IDBFile(fh).getsectioninfo(0)[0], 2)
        self.assert_output(fixture)

    def test_residue_audit_across_copy_buffer_boundary(self) -> None:
        padding = b'x' * (1024 * 1024 - 5)
        Fixture(opaque=padding + b' ' + LICENSE_PAYLOAD).write(self.paths.source)
        with self.assertRaisesRegex(AnonymizeError, 'remain in sections 4'):
            anonymize_file(self.paths)
        self.assertFalse(self.paths.output.exists())


    def test_additional_metadata_node_is_explicitly_selected(self) -> None:
        fixture = Fixture()
        prefix = fixture.prefix(5)
        owner = b'Additional owner private metadata; not a known default node'
        records = fixture.records() + [
            Record(b'N$ author', int.from_bytes(prefix[1:], 'big').to_bytes(8, 'little')),
            Record(prefix + b'N', b'$ author'),
            Record(fixture.key(prefix, b'S', 0), owner),
        ]
        with patch.object(Fixture, 'records', return_value=sorted(records, key=lambda record: record.key)):
            fixture.write(self.paths.source)
        result = anonymize_file(self.paths, AnonymizeOptions(extra_nodes=('$ author',)))
        self.assertEqual(len(result.plan.removed), 9)
        self.assertNotIn(owner, self.paths.output.read_bytes())

    def test_explicit_comment_redaction_and_short_basename(self) -> None:
        fixture = Fixture(filename=b'a\0', comment=b'Input file: a; owner-token-abc')
        # The separate posterior comment deliberately retains sample.exe.
        fixture.write(self.paths.source)
        options = AnonymizeOptions(redact_text=('a', 'owner-token-abc'))
        result = anonymize_file(self.paths, options)
        self.assertEqual(result.plan.changed_comments, 1)
        with self.paths.output.open('rb') as fh:
            id0 = idblib.IDBFile(fh).getsection(idblib.ID0File)
            value = id0.bytes(0x1000, 'S', 1000)
            self.assertEqual(value, b'Input file: [redacted]; [redacted]')
            self.assertEqual(id0.bytes(id0.root, 'V'), b'input.bin\0')

    def test_downgrade_tool_remains_composable(self) -> None:
        from idbdowngrade import downgrade_file
        fixture = Fixture()
        fixture.write(self.paths.source, True)
        downgraded = self.root / 'downgraded.i64'
        downgrade_file(DatabasePaths(self.paths.source, downgraded))
        anonymize_file(DatabasePaths(downgraded, self.paths.output))
        with self.paths.output.open('rb') as fh:
            id0 = idblib.IDBFile(fh).getsection(idblib.ID0File)
            self.assertEqual(struct.unpack_from('<H', id0.idbparams, 3)[0], 840)
            self.assertIsNone(id0.bytes(id0.nodeByName('$ original user'), 'S', 0))
            self.assertEqual(id0.bytes(id0.root, 'V'), b'input.bin\0')

    def test_text_audit_does_not_match_prefix_at_buffer_boundary(self) -> None:
        # sample.exeX is not the filename token, even when X starts a new chunk.
        prefix = b'x' * (1024 * 1024 - len(b' sample.exe'))
        Fixture(opaque=prefix + b' sample.exeX ').write(self.paths.source)
        result = anonymize_file(self.paths)
        self.assertFalse(result.residual_sections)
