# written by chatgpt GPT-6
"""Remove known IDA user/license metadata and redact the input filename.

Rebuilds ID0 to discard old free pages. Other undecoded payloads are preserved;
this is a scoped metadata anonymizer, not a guarantee of full deidentification.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys
from typing import BinaryIO, Optional

import idblib
from idbtransform import DatabasePaths, RecordDigest, stream_crc
from idbwrite import Record


class AnonymizeError(ValueError):
    """The requested anonymization could not be completed or verified."""


@dataclass(frozen=True)
class AnonymizeOptions:
    filename: str = 'input.bin'
    compress_id0: bool = False
    extra_nodes: tuple[str, ...] = ()
    redact_text: tuple[str, ...] = ()
    allow_residuals: bool = False

    def validate(self) -> None:
        if not self.filename or any(char in self.filename for char in '/\\\0\r\n'):
            raise AnonymizeError('--filename must be a nonempty basename without path separators')
        if any(not text or '\0' in text for text in self.redact_text):
            raise AnonymizeError('--redact-text requires nonempty text without NUL bytes')


@dataclass(frozen=True)
class ValueChange:
    key: bytes
    before: bytes = field(repr=False)
    after: bytes = field(repr=False)


@dataclass
class MetadataNode:
    node_id: int
    names: list[str]
    records: list[Record] = field(default_factory=list, repr=False)

    def removed_bytes(self) -> int:
        return sum(len(record.value) for record in self.records)


class TextRedactor:
    """Replace whole literal filename/path tokens in known comment strings."""

    def __init__(self) -> None:
        self.rules: dict[bytes, bytes] = {}
        self.pattern: Optional[re.Pattern[bytes]] = None

    def add(self, before: bytes, after: bytes) -> None:
        if before and before != after:
            self.rules[before] = after
            self.pattern = None

    def _pattern(self) -> Optional[re.Pattern[bytes]]:
        if self.pattern is None and self.rules:
            alternatives = b'|'.join(re.escape(text) for text in sorted(self.rules, key=len, reverse=True))
            self.pattern = re.compile(rb'(?<![\w.-])(?:' + alternatives + rb')(?![\w.-])')
        return self.pattern

    def replace(self, data: bytes) -> bytes:
        pattern = self._pattern()
        return pattern.sub(lambda match: self.rules[match[0]], data) if pattern else data

    def contains(self, data: bytes, final: bool = True, skip_initial: bool = False) -> bool:
        pattern = self._pattern()
        if pattern is None:
            return False
        return any((not skip_initial or match.start() != 0) and (final or match.end() < len(data)) for match in pattern.finditer(data))


@dataclass
class AnonymizePlan:
    nodes: dict[int, MetadataNode] = field(default_factory=dict)
    removed: dict[bytes, Record] = field(default_factory=dict, repr=False)
    changes: dict[bytes, ValueChange] = field(default_factory=dict, repr=False)
    text: TextRedactor = field(default_factory=TextRedactor, repr=False)
    notes: list[str] = field(default_factory=list)
    changed_comments: int = 0
    undecoded_comments: int = 0
    filename_changed: bool = False

    @classmethod
    def inspect(cls, id0: idblib.ID0File, options: AnonymizeOptions) -> AnonymizePlan:
        options.validate()
        plan = cls()
        plan._metadata_nodes(id0, options)
        plan._filename(id0, options)
        plan._comments(id0)
        plan.notes.append('Opaque header value, input hashes, and unselected records are retained.')
        plan.notes.append('Only known address-comment encodings are edited; other opaque payloads are copied and checked for known residual identifiers.')
        return plan

    def _metadata_nodes(self, id0: idblib.ID0File, options: AnonymizeOptions) -> None:
        names = ('$ original user', '$ user1') + options.extra_nodes
        for name in names:
            node_id = id0.nodeByName(name)
            if node_id is None:
                continue
            if node_id < id0.nodebase:
                raise AnonymizeError('selected metadata node points outside the internal-node range')
            node = self.nodes.setdefault(node_id, MetadataNode(node_id, []))
            if name not in node.names:
                node.names.append(name)
        for node in self.nodes.values():
            prefix = id0.makekey(node.node_id)
            cursor = id0.btree.find('ge', prefix)
            while not cursor.eof() and cursor.getkey().startswith(prefix):
                record = Record(cursor.getkey(), cursor.getval())
                anchor = record.key == prefix + b'N' and record.value.rstrip(b'\0') in tuple(name.encode() for name in node.names)
                if not anchor:
                    node.records.append(record)
                    self.removed[record.key] = record
                cursor.next()
        if not self.removed:
            self.notes.append('No active payloads found in selected user nodes; ID0 is still rebuilt to discard free pages.')

    def _filename(self, id0: idblib.ID0File, options: AnonymizeOptions) -> None:
        for text in options.redact_text:
            self.text.add(text.encode('utf-8'), b'[redacted]')
        key = id0.makekey(id0.root, 'V')
        original = id0.bytes(id0.root, 'V')
        if original is None:
            self.notes.append('Root Node.V is absent; only explicit --redact-text values can identify filenames in comments.')
            return
        value = original.rstrip(b'\0')
        try:
            value.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise AnonymizeError('Root Node.V has an undecoded filename encoding') from exc
        if b'\0' in value:
            raise AnonymizeError('Root Node.V contains undecoded embedded NUL bytes')
        replacement = options.filename.encode('utf-8')
        self._filename_rules(value, replacement)
        result = replacement + original[len(value):]
        if original != result:
            self.changes[key] = ValueChange(key, original, result)
            self.filename_changed = True

    def _filename_rules(self, value: bytes, replacement: bytes) -> None:
        variants = {value, value.replace(b'\\', b'/'), value.replace(b'/', b'\\')}
        basename = value.replace(b'\\', b'/').rsplit(b'/', 1)[-1]
        if len(basename) >= 4:
            variants.add(basename)
        elif basename:
            variants.discard(basename)
            self.notes.append('Short input basename is not automatically matched in comments; use --redact-text to select it explicitly.')
        for variant in variants:
            self.text.add(variant, replacement)
            for suffix in (b'.idb', b'.i64'):
                self.text.add(variant + suffix, replacement + suffix)

    def _comments(self, id0: idblib.ID0File) -> None:
        cursor = id0.btree.find('ge', b'')
        while not cursor.eof():
            key, value = cursor.getkey(), cursor.getval()
            if self._is_comment(key, id0) and key not in self.removed:
                try:
                    value.decode('utf-8')
                except UnicodeDecodeError:
                    self.undecoded_comments += 1
                else:
                    after = self.text.replace(value)
                    if after != value:
                        self.changes[key] = ValueChange(key, value, after)
                        self.changed_comments += 1
            cursor.next()
        if self.undecoded_comments:
            self.notes.append('%d non-UTF-8 address comments were retained undecoded.' % self.undecoded_comments)

    @staticmethod
    def _is_comment(key: bytes, id0: idblib.ID0File) -> bool:
        width = id0.wordsize
        if len(key) != 2 + 2 * width or key[:1] != b'.' or key[1 + width:2 + width] != b'S':
            return False
        node = int.from_bytes(key[1:1 + width], 'big')
        index = int.from_bytes(key[2 + width:], 'big')
        return node < id0.nodebase and (index in (0, 1) or 1000 <= index < 3000)

    def apply(self, record: Record) -> Optional[Record]:
        removed = self.removed.get(record.key)
        change = self.changes.get(record.key)
        expected = removed.value if removed is not None else change.before if change is not None else None
        if expected is not None and expected != record.value:
            raise AnonymizeError('source metadata changed after inspection')
        if removed is not None:
            return None
        return Record(record.key, change.after) if change is not None else record


class ResidualAudit:
    """Search decoded output sections, including ID0 slack, for known residues."""

    def __init__(self, plan: AnonymizePlan):
        unique: set[bytes] = set()
        for record in plan.removed.values():
            if len(record.value) >= 32 and len(set(record.value)) > 1:
                unique.add(record.value)
        self.payloads = tuple(unique)
        self.text = plan.text
        self.overlap = max([len(data) for data in self.payloads] + [len(data) for data in self.text.rules] + [1])

    def contains(self, stream: BinaryIO) -> bool:
        if not self.payloads and not self.text.rules:
            return False
        tail = b''
        consumed = 0
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                return self.text.contains(tail, skip_initial=consumed > len(tail))
            window = tail + data
            if any(payload in window for payload in self.payloads):
                return True
            if self.text.contains(window, final=False, skip_initial=consumed > len(tail)):
                return True
            consumed += len(data)
            tail = window[-(self.overlap + 2):]


@dataclass(frozen=True)
class AnonymizeResult:
    plan: AnonymizePlan
    input_records: int
    output_records: int
    residual_sections: tuple[int, ...]
    dry_run: bool


class Anonymizer:
    def __init__(self, source: idblib.IDBFile, options: AnonymizeOptions):
        if source.fileversion not in (6, 910) or source.magic not in ('IDA1', 'IDA2'):
            raise AnonymizeError('only v6/v910 containers with IDA1/IDA2 encoding are supported')
        self.source = source
        self.options = options
        self.id0 = source.getsection(idblib.ID0File)
        if self.id0 is None or self.id0.root is None:
            raise AnonymizeError('ID0 or Root Node is missing')
        self.plan = AnonymizePlan.inspect(self.id0, options)

    def write(self, output: BinaryIO) -> AnonymizeResult:
        _, _, size, checksum = self.source.getsectioninfo(0)
        if self.source.fileversion == 6 and checksum:
            if stream_crc(self.source.getstoredpart(0), size) != checksum:
                raise AnonymizeError('source ID0 checksum mismatch')
        template = self.source.headerdata if self.source.fileversion == 6 else b''
        expected = RecordDigest()
        count = 0
        with idblib.IDBFile.create(output, magic=self.source.magic, header_template=template, header_value=self.source.header_value) as dst:
            writer = dst.allocatesection(idblib.ID0File, compression=2 if self.options.compress_id0 else 0)
            cursor = self.id0.btree.find('ge', b'')
            while not cursor.eof():
                record = self.plan.apply(Record(cursor.getkey(), cursor.getval()))
                if record is not None:
                    writer.write(record.key, record.value)
                    expected.add(record)
                count += 1
                cursor.next()
            if count != self.id0.btree.reccount or count - expected.count != len(self.plan.removed):
                raise AnonymizeError('source record count mismatch')
            writer.close()
            for cls in (idblib.ID1File, idblib.NAMFile, idblib.SEGFile, idblib.TILFile, idblib.ID2File):
                dst.copysection(self.source, cls)
        residuals = self._verify(output, expected)
        return AnonymizeResult(self.plan, count, expected.count, residuals, False)

    def _verify(self, output: BinaryIO, expected: RecordDigest) -> tuple[int, ...]:
        db = idblib.IDBFile(output)
        try:
            if db.fileversion != 6 or db.magic != self.source.magic or db.header_value != self.source.header_value:
                raise AnonymizeError('output container metadata changed unexpectedly')
            actual = RecordDigest()
            cursor = db.getsection(idblib.ID0File).btree.find('ge', b'')
            while not cursor.eof():
                if cursor.getkey() in self.plan.removed:
                    raise AnonymizeError('selected user metadata remains in output')
                actual.add(Record(cursor.getkey(), cursor.getval()))
                cursor.next()
            if not expected.matches(actual):
                raise AnonymizeError('output record verification failed')
            return self._verify_sections(db)
        finally:
            db.close()

    def _verify_sections(self, db: idblib.IDBFile) -> tuple[int, ...]:
        audit = ResidualAudit(self.plan)
        residuals: list[int] = []
        for index in range(6):
            _, offset, size, checksum = db.getsectioninfo(index)
            if not offset:
                continue
            if stream_crc(db.getstoredpart(index), size) != checksum:
                raise AnonymizeError('output section %d checksum mismatch' % index)
            if audit.contains(db.getpart(index)):
                residuals.append(index)
        if residuals and not self.options.allow_residuals:
            raise AnonymizeError('known metadata or filename bytes remain in sections %s; output discarded. Use --allow-residuals only to retain a partial result for review.' % ', '.join(map(str, residuals)))
        return tuple(residuals)


def anonymize_file(paths: DatabasePaths, options: AnonymizeOptions = AnonymizeOptions(), dry_run: bool = False) -> AnonymizeResult:
    if not dry_run and paths.output is None:
        raise AnonymizeError('an output path is required')
    with paths.source.open('rb') as fh:
        source = idblib.IDBFile(fh)
        try:
            operation = Anonymizer(source, options)
            if dry_run:
                count = operation.id0.btree.reccount
                return AnonymizeResult(operation.plan, count, count - len(operation.plan.removed), (), True)
            return _write_file(paths, operation)
        finally:
            source.close()


def _write_file(paths: DatabasePaths, operation: Anonymizer) -> AnonymizeResult:
    created = False
    try:
        with paths.output.open('xb+') as output:
            created = True
            return operation.write(output)
    except BaseException:
        if created:
            paths.output.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--filename', default='input.bin', help='replacement input basename (default: input.bin)')
    parser.add_argument('--node', action='append', default=[], help='also remove payloads of this explicitly selected named metadata node')
    parser.add_argument('--redact-text', action='append', default=[], help='additional literal identifier to redact in known address comments')
    parser.add_argument('--compress-id0', action='store_true')
    parser.add_argument('--allow-residuals', action='store_true', help='retain partial output despite known identifier residues; report their sections')
    args = parser.parse_args()
    options = AnonymizeOptions(args.filename, args.compress_id0, tuple(args.node), tuple(args.redact_text), args.allow_residuals)
    try:
        result = anonymize_file(DatabasePaths(args.source, args.output), options, args.dry_run)
    except Exception as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 1
    status = 'Planned' if result.dry_run else 'PARTIAL output retained' if result.residual_sections else 'Written and verified'
    print('%s: %d user/license payload records removed; %d filename/comment values changed' % (status, len(result.plan.removed), len(result.plan.changes)))
    for node in result.plan.nodes.values():
        print('  %s: %d payload records, %d bytes' % (', '.join(node.names), len(node.records), node.removed_bytes()))
    print('Root filename changed: %s; changed comments: %d' % (result.plan.filename_changed, result.plan.changed_comments))
    print('Records: %d -> %d' % (result.input_records, result.output_records))
    if result.residual_sections:
        print('PARTIAL RESULT: known identifier residues remain in sections %s' % (result.residual_sections,))
    for note in result.plan.notes:
        print(note)
    return 0


if __name__ == '__main__':
    sys.exit(main())
