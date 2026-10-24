# written by chatgpt GPT-6
"""Downgrade the observed IDA 9.x parameter schema to an IDA 8.4 container.

This implements the tested MBR transformation. It does not migrate type
encodings, processor-specific records, or other undecoded database schemas.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import struct
import sys
from typing import BinaryIO, Optional

import idblib
from idbwrite import Record
from idbtransform import DatabasePaths, RecordDigest, stream_crc as _stream_crc


class DowngradeError(ValueError):
    """Input is outside the implemented downgrade profile."""


@dataclass(frozen=True)
class DowngradeOptions:
    compress_id0: bool = False
    preserve_version_labels: bool = False
    allow_untested_schema: bool = False

    def compression(self) -> int:
        return 2 if self.compress_id0 else 0


@dataclass(frozen=True)
class RecordChange:
    key: bytes
    before: bytes
    after: bytes
    description: str


@dataclass
class DowngradePlan:
    source_version: int
    changes: dict[bytes, RecordChange] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    TARGET = 840
    TESTED_SOURCE = 920
    PARAMETER_INDEX = 0x41b994

    @classmethod
    def inspect(cls, id0: idblib.ID0File, options: DowngradeOptions) -> DowngradePlan:
        if id0.root is None:
            raise DowngradeError('Root Node is missing')
        key = id0.makekey(id0.root, 'S', cls.PARAMETER_INDEX)
        data = id0.bytes(id0.root, 'S', cls.PARAMETER_INDEX)
        if data is None or len(data) < 5 or data[:3] != b'IDA':
            raise DowngradeError('missing or invalid Root Node parameter record')
        version, = struct.unpack_from('<H', data, 3)
        plan = cls(version)
        plan._check_schema(options)
        replacement = data[:3] + struct.pack('<H', cls.TARGET) + data[5:]
        plan.add(key, data, replacement, 'Root Node.S[0x41b994]: %d -> 840; remaining bytes retained' % version)
        if not options.preserve_version_labels:
            plan._version_number(id0)
            plan._version_string(id0)
        else:
            plan.notes.append('Root version labels retained by request.')
        plan.notes.append('Undecoded parameter bytes and other record payloads are retained; type schemas are not converted.')
        return plan

    def _check_schema(self, options: DowngradeOptions) -> None:
        if self.source_version == self.TARGET:
            self.notes.append('Parameter version is already 840; only newer version labels, if any, will change.')
            return
        if self.source_version < self.TARGET or self.source_version >= 1000:
            raise DowngradeError('unsupported parameter version %d' % self.source_version)
        if self.source_version != self.TESTED_SOURCE:
            if not options.allow_untested_schema:
                raise DowngradeError('untested parameter version %d; use --allow-untested-schema to attempt the version-only transformation' % self.source_version)
            self.notes.append('Untested source schema %d: only version metadata will be changed.' % self.source_version)

    def add(self, key: bytes, before: bytes, after: bytes, description: str) -> None:
        if before != after:
            self.changes[key] = RecordChange(key, before, after, description)

    def _version_number(self, id0: idblib.ID0File) -> None:
        data = id0.bytes(id0.root, 'A', -1)
        if data is None:
            self.notes.append('Root Node.A[-1] is absent; no record added.')
            return
        if len(data) not in (1, 2, 4, 8):
            raise DowngradeError('Root Node.A[-1] has an unsupported integer width')
        version = int.from_bytes(data, 'little')
        if version > self.TARGET:
            key = id0.makekey(id0.root, 'A', -1)
            value = self.TARGET.to_bytes(len(data), 'little')
            self.add(key, data, value, 'Root Node.A[-1]: %d -> 840' % version)

    def _version_string(self, id0: idblib.ID0File) -> None:
        data = id0.bytes(id0.root, 'S', 1303)
        if data is None:
            self.notes.append('Root Node.S[1303] is absent; no record added.')
            return
        match = re.match(rb'(\d+)\.(\d+)', data)
        if match is None:
            self.notes.append('Root Node.S[1303] is undecoded; label retained unchanged.')
            return
        version = (int(match[1]), int(match[2]))
        if version > (8, 4):
            terminator = data[len(data.rstrip(b'\0')):]
            key = id0.makekey(id0.root, 'S', 1303)
            self.add(key, data, b'8.4' + terminator, 'Root Node.S[1303]: version label -> 8.4')

    def apply(self, record: Record) -> Record:
        change = self.changes.get(record.key)
        if change is None:
            return record
        if record.value != change.before:
            raise DowngradeError('source record changed after inspection')
        return Record(record.key, change.after)


@dataclass(frozen=True)
class DowngradeResult:
    plan: DowngradePlan
    records: int
    dry_run: bool


class Downgrader:
    def __init__(self, source: idblib.IDBFile, options: DowngradeOptions):
        if source.fileversion not in (6, 910):
            raise DowngradeError('only v6 and v910 input containers are supported')
        if source.magic not in ('IDA1', 'IDA2'):
            raise DowngradeError('unsupported database address encoding')
        self.source = source
        self.options = options
        self.id0 = source.getsection(idblib.ID0File)
        if self.id0 is None:
            raise DowngradeError('ID0 section is missing')
        self.plan = DowngradePlan.inspect(self.id0, options)

    def write(self, output: BinaryIO) -> int:
        self._verify_input_crc()
        template = self.source.headerdata if self.source.fileversion == 6 else b''
        expected = RecordDigest()
        with idblib.IDBFile.create(output, magic=self.source.magic, header_template=template, header_value=self.source.header_value) as dst:
            writer = dst.allocatesection(idblib.ID0File, compression=self.options.compression())
            cursor = self.id0.btree.find('ge', b'')
            while not cursor.eof():
                record = self.plan.apply(Record(cursor.getkey(), cursor.getval()))
                writer.write(record.key, record.value)
                expected.add(record)
                cursor.next()
            if expected.count != self.id0.btree.reccount:
                raise DowngradeError('source ID0 record count mismatch')
            writer.close()
            for cls in (idblib.ID1File, idblib.NAMFile, idblib.SEGFile, idblib.TILFile, idblib.ID2File):
                dst.copysection(self.source, cls)
        self._verify_output(output, expected)
        return expected.count

    def _verify_input_crc(self) -> None:
        # v910 has already verified its entire decompressed payload.
        _, _, size, crc = self.source.getsectioninfo(0)
        if self.source.fileversion == 6 and crc:
            part = self.source.getstoredpart(0)
            if stream_crc(part, size) != crc:
                raise DowngradeError('source ID0 checksum mismatch')

    def _verify_output(self, output: BinaryIO, expected: RecordDigest) -> None:
        result = idblib.IDBFile(output)
        try:
            if result.fileversion != 6 or result.magic != self.source.magic:
                raise DowngradeError('output container format or address width changed unexpectedly')
            actual = RecordDigest()
            cursor = result.getsection(idblib.ID0File).btree.find('ge', b'')
            while not cursor.eof():
                actual.add(Record(cursor.getkey(), cursor.getval()))
                cursor.next()
            if not expected.matches(actual):
                raise DowngradeError('output record verification failed')
            if result.header_value != self.source.header_value:
                raise DowngradeError('opaque container header value was changed')
            for index in range(6):
                _, offset, size, crc = result.getsectioninfo(index)
                if offset and stream_crc(result.getstoredpart(index), size) != crc:
                    raise DowngradeError('output section %d checksum mismatch' % index)
        finally:
            result.close()


def stream_crc(source: BinaryIO, size: int) -> int:
    try:
        return _stream_crc(source, size)
    except ValueError as exc:
        raise DowngradeError(str(exc)) from exc


def downgrade_file(paths: DatabasePaths, options: DowngradeOptions = DowngradeOptions(), dry_run: bool = False) -> DowngradeResult:
    if not dry_run and paths.output is None:
        raise DowngradeError('an output path is required')
    with paths.source.open('rb') as fh:
        source = idblib.IDBFile(fh)
        try:
            operation = Downgrader(source, options)
            if dry_run:
                return DowngradeResult(operation.plan, operation.id0.btree.reccount, True)
            return _write_file(paths, operation)
        finally:
            source.close()


def _write_file(paths: DatabasePaths, operation: Downgrader) -> DowngradeResult:
    created = False
    try:
        with paths.output.open('xb+') as output:
            created = True
            count = operation.write(output)
        return DowngradeResult(operation.plan, count, False)
    except BaseException:
        if created:
            paths.output.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--dry-run', action='store_true', help='inspect and list changes without writing output')
    parser.add_argument('--compress-id0', action='store_true')
    parser.add_argument('--preserve-version-labels', action='store_true', help='retain Root A[-1] and S[1303], even if newer than 8.4')
    parser.add_argument('--allow-untested-schema', action='store_true', help='allow an untested parameter version; no extra schema migration is performed')
    args = parser.parse_args()
    paths = DatabasePaths(args.source, args.output)
    options = DowngradeOptions(args.compress_id0, args.preserve_version_labels, args.allow_untested_schema)
    try:
        result = downgrade_file(paths, options, args.dry_run)
    except Exception as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 1
    print('%s: parameter version %d -> 840; container -> v6' % ('Planned' if result.dry_run else 'Written and verified', result.plan.source_version))
    for change in result.plan.changes.values():
        print('  ' + change.description)
    print('%d records; %d changed values' % (result.records, len(result.plan.changes)))
    for note in result.plan.notes:
        print(note)
    return 0


if __name__ == '__main__':
    sys.exit(main())
