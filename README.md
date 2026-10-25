# reading and modifying IDA databases

This repository contains tools for reading or writing databases from
the IDA disassembler.

* idbtool - inspect the innards of an ida database
* idbdowngrade - convert an ida 9.x database to 8.x
* idbanonymize - remove identifying information from a db

note that the sections in this document about writing databases were written by chatgpt,
and are a bit verbose.


IDBTOOL
=======

A tool for extracting information from IDA databases.
`idbtool` knows how to handle databases from all IDA versions since v2.0, both `i64` and `idb` files.
You can also use `idbtool` to recover information from unclosed databases.

`idbtool` works without change with IDA v7.0.


Much faster than loading a file in IDA
--------------------------------------

With idbtool you can search thousands of .idb files in seconds.

More precisely: on my laptop it takes:

 *  1.5 seconds to extract 143 idc scripts from 119 idb and i64 files.
 *  3.8 seconds to print idb info for 441 files.
 *  5.6 seconds to extract 281 enums containing 4726 members from 35 files.
 * 67.8 seconds to extract 5942 structs containing 33672 members from 265 files.

Loading a approximately 5 Gbyte idb file in IDA, takes about 45 minutes.
While idb3.h takes basically no time at all, no more than a few milliseconds.



Download
========

Two versions of this tool exist:

One written in python
 * https://github.com/nlitsme/pyidbutil

One written in C++
 * https://github.com/nlitsme/idbutil

Both repositories contain a library which can be used for reading `.idb` or `.i64` files.


Usage
=====

Usage: 

    idbtool [options] [database file(s)]

 * `-n` or `--names`  will list all named values in the database.
 * `-s` or `--scripts` will list all scripts stored in the database.
 * `-u` or `--structs` will list all structs stored in the database.
 * `-e` or `--enums` will list all enums stored in the database.
 * `--imports` will list all imported symbols from the database.
 * `--funcdirs` will list function folders stored in the database.
 * `-i` or `--info` will print some general info about the database. 
 * `-d` or `--pagedump`  dump btree page tree contents.
 * `--inc`, `--dec` list all records in ascending / descending order.
 * `-q` or `--query` search specific records in the database.
 * `-m` or `--limit` limit the number of results returned by `-q`.
 * `-id0`, `-id1` dump only one specific section.
 * `--i64`, `--i32` tell idbtool that the specified file is from a 64 or 32 bit database.
 * `--recover` group files from an unpacked database.
 * `--classify` summarizes node usage in the database
 * `--dump`  hexdump the original binary data

query
-----

Queries need to be specified last on the commandline.

example:

    idbtool [database file(s)]  --query  "Root Node;V"

Will list the source binary for all the databases specified on the commandline.

A query is a string with the following format:

 * [==,<=,>=,<,>]  - optional relation, default: ==
 * a base node key:
    * a DOT followed by the numeric value of the nodeid.
    * a HASH followed by the numeric value of the system-nodeid.
    * a QUESTION followed by the name of the node. -> a 'N'ame node
    * the name of the node.  -> the name is resolved, results in a '.'Dot node
 * an optional tag ( A for Alt, S for Supval, etc )
 * an optional index value

example queries:
 * `Root Node;V` -> prints record containing the source binary name
 * `?Root Node` -> prints the Name record pointing to the root
 * `>Root Node` -> prints the first 10 records starting with the root node id.
 * `<Root Node` -> prints the 10 records startng with the recordsbefore the rootnode.
 * `.0xff000001;N` -> prints the rootnode name entry.
 * `#1;N` -> prints the rootnode name entry.

List the highest node and following record in the database in two different ways,
the first: starting at the first record below `ffc00000`, and listing the next.
The second: starting at the first record after `ffc00000`, and listing the previous:
 * `--query "<#0xc00000"  --limit 2 --inc -v`
 * `--query ">#0xc00000"  --limit 2 --dec -v`

Note that this should be the nodeid in the `$ MAX NODE` record.

List the last two records:
 * `--limit 2 --dec  -v`

List the first two records, the `$ MAX LINK` and `$ MAX NODE` records:
 * `--limit 2 --inc -v`


A full database dump
--------------------

Several methods exist for printing all records in the database. This may be useful if
you want to investigate more of IDA''s internals. But can also be useful in recovering
data from corrupted databases.

 * `--inc`, `--dec` can be used to enumerate all b-tree records in either forward, or backward direction.
    * add `-v` to get a prettier key/value output
 * `--id0`  walks the page tree, instead of the record tree, printing the contents of each page
 * `--pagedump` linearly skip through the file, this will also reveal information in deleted pages.

naked files
===========

When IDA or your computer crashed while working on a disassembly, and you did not yet save the database,
you are left with a couple of files with extensions like `.id0`, `.id1`, `.nam`, etc.

These files are the unpacked database, i call them `naked` files.

Using the `--filetype` and `--i64` or `--i32` options you can inspect these `naked` files individually.
or use the `--recover` option to view them as a complete database together.
`idbtool` will figure out automatically which files would belong together.

`idbtool` can figure out the bitsize of the database from an `.id0` file, but not(yet) from the others.



Writing and rewriting databases (Python 3.9+)
============================================

`idblib.IDBFile.create()` creates a version-6 container writer. The first
implementation writes B-tree v2 ID0 sections and preserves the database's
32/64-bit encoding. It does not change semantic IDA version records, downgrade
type encodings, or remove license metadata.

To rebuild ID0 and copy every other section:

```python
import idblib

with open("source.i64", "rb") as source:
    with open("rewritten.i64", "xb+") as output:
        idblib.updateidb(source, output, compression=2)
```

Or use the command-line wrapper (existing output files are refused):

```sh
python3 idbrewrite.py --compress-id0 source.i64 rewritten.i64
```

For individual edits, resolve the records to modify before the ordered copy:

```python
import idblib

with open("source.i64", "rb") as source:
    src = idblib.IDBFile(source)
    with open("rewritten.i64", "xb+") as output:
        template = src.headerdata if src.fileversion == 6 else b""
        with idblib.IDBFile.create(
            output, fileversion=6, magic=src.magic,
            header_template=template,
        ) as dst:
            tree = src.getsection(idblib.ID0File).btree
            writer = dst.allocatesection(idblib.ID0File, compression=2)
            cursor = tree.find("ge", b"")
            while not cursor.eof():
                key, value = cursor.getkey(), cursor.getval()
                # Change value here, or omit writer.write() to delete a record.
                writer.write(key, value)
                cursor.next()
            writer.close()
            for cls in (
                idblib.ID1File, idblib.NAMFile, idblib.SEGFile,
                idblib.TILFile, idblib.ID2File,
            ):
                dst.copysection(src, cls)
```

Writer API
----------

* `IDBFile.create(fh, fileversion=6, magic="IDA2", header_template=b"")`:
  output must support write, seek, tell, truncate, and flush. `IDA1` means
  32-bit database encoding; `IDA2` means 64-bit database encoding. This is
  independent of the bitness of the analyzed executable.
* `dst.allocatesection(cls, compression=0, pagesize=8192)`: allocate a section
  once. ID0 returns a writer with `write(key, value)`; other sections return
  raw byte writers with `write(data)`. `pagesize` applies only to ID0.
* ID0 accepts immutable bytes and strictly increasing, unique keys. Internal
  B-tree records are promoted, not duplicated. Leaf keys use prefix compression.
  The builder packs actual encoded bytes and splits overflowing pages by byte
  weight, keeping all leaves at equal depth. Root page 1 and free-list page 2
  are reserved; other pages are allocated from page 3.
* `section.close()`: finish this section. Every allocated section must be
  closed before `dst.close()`. Missing sections stay absent; allocated empty
  raw sections remain present.
* `dst.copysection(src, cls)`: copy the exact stored section payload and its
  compression method without decoding opaque contents for legacy containers.
  For v910 it copies verified, decompressed section bytes. Legacy source CRC-32
  is checked when nonzero; the v910 global CRC is always checked, including zero.
  Truncated payloads raise an error. Source must be an `IDBFile`.
* `dst.close()`: write sections, calculate CRC-32 over their stored bytes, then
  write the final header. It does not close the caller's file handle.
* `dst.abort()`: discard temporary section files without finalizing output.
  Context managers call it automatically on failure.

Sections and ordered ID0 input use temporary files, keeping writer RAM bounded
by page size, tree height, and fixed-size copy buffers. The existing reader
still decompresses compressed ID0 sections into memory. Fresh ID0 pages are
zero-filled; deleted records and old free pages are not copied. Unknown values
in retained records and opaque sections are preserved, not interpreted.

Version-6 header extension bytes can be retained through `header_template`;
`updateidb` does this automatically for version-6 input. New headers otherwise
initialize unknown/reserved fields to zero and set the conventional extension
size marker. This is not a conversion of unknown metadata between versions.
v910 input can be uncompressed (type 0) or whole-stream zstd (type 3). Its six
section sizes refer to the decompressed concatenation. The reader verifies the
final little-endian CRC-32 over all preceding decompressed bytes before exposing
any sections. The CRC itself is excluded from section contents. Missing CRCs,
size mismatches, incomplete zstd frames, and invalid CRCs are rejected. This
also corrects the earlier synthetic uncompressed-v910 fixture, which omitted
the required trailer.

For v910, `getsectioninfo()` reports logical section offsets rather than physical
compressed-file offsets. `getstoredpart()` is the interface for reading section
bytes; it retains legacy per-section compression, but excludes v910's outer
compression and CRC. The combined v910 payload is decompressed into a temporary
file using bounded buffers. `IDBFile.close()` releases that temporary file while
leaving the caller's source handle open. `updateidb()` releases it automatically.

Zstd input requires Python 3.14+ (`compression.zstd`) or the `backports.zstd`
package on older Python. Other formats do not require a zstd dependency. The
zstd decoder also checks for complete frames, including their optional frame
checksums; concatenated frames are supported. v910 output is not implemented.
The user confirmed a rebuilt MBR candidate opens in IDA 8.4. Broader native
validation and real compressed-v910 sample validation remain outstanding.

Run the unit tests with `python3 -m unittest discover -v`.


Opaque header value
-------------------

`IDBFile.header_value` exposes the 16 uninterpreted bytes at v6 offset 0x6c
or v910 offset 0x5d. Its meaning is unknown: in the supplied examples it is
preserved by an IDA version upgrade, differs in a freshly created database,
and does not equal the input-file MD5 stored in Root Node.

`IDBFile.create(..., header_value=src.header_value)` preserves this value
while converting container versions. `updateidb()` passes it automatically.
Version-6-to-version-6 rewrites also preserve the full extension through the
existing header template. An explicit value overrides the template field;
`None` retains the template or the default zeros for a new file. Unknown
reserved bytes are not mapped between different header formats.


Free-list page
--------------

The writer emits `firstfree=2`, pointing to a real, zero-filled
free-list page, and `root=1`. Its count and next-page pointer are both zero. This page is
not a tree page: the B-tree header's page count tracks only active tree pages.
A freshly rebuilt ID0 therefore contains one header page, the active tree
pages, and one free-list page. This follows the empty free-list representation
in the supplied converted database. It replaces the previous zero `firstfree`;
that output was readable by our parser but IDA reported an empty database.
The zero-firstfree correction alone did not resolve native IDA acceptance.
The revised builder also uses IDA's root/free-list allocation positions and
actual-byte packing. The user confirmed this packed rebuild opens successfully in IDA 8.4 for the supplied MBR sample.

Downgrade command: IDA 9.x to IDA 8.4
====================================

WARNING: downgrade seems to work fine as far as i can tell, but no guarantees,
there may be nescesary changes which I have missed.

This tool downgrades a 9.x database such that it can be used with IDA 8.x.


`idbdowngrade.py` implements the version-metadata transformation that worked
on the supplied 8.4-to-9.x MBR database. It targets 8.4 and writes a version-6
container using the working B-tree builder.

```sh
python3 idbdowngrade.py input.i64 output.i64
python3 idbdowngrade.py --dry-run input.i64
python3 idbdowngrade.py --compress-id0 input.i64 output.i64
```

The tool modifies the uint16 version at bytes 3-4 of Root Node's
`S[0x41b994]` record to 840. Every other parameter byte, including the extra
undecoded trailing byte observed in the 9.x samples, is retained. Newer
`Root Node.A[-1]` and `Root Node.S[1303]` version labels are lowered to 840
and `8.4`; older labels are retained. Missing labels are not invented, and
undecoded version strings are retained and reported.

All remaining ID0 key/value records and opaque sections are preserved. No
node renaming, node deletion, type-schema conversion or anonymization occurs.
The opaque 16-byte container-header value and database address width are
preserved. The command verifies the complete output record sequence and the
stored section CRCs before reporting success. Existing output files, including
the source path, are refused. A failed conversion removes its incomplete output.

The observed source parameter schema is **920**, including the supplied files
labelled 9.4. Application version labels are not a reliable parameter-schema
identifier. Already-840 input is accepted; other newer schemas are refused
unless `--allow-untested-schema` is supplied. That option only permits the
same version-metadata edits; it does not implement migration of that schema.
Older-than-840 input is refused.

Options:

* `--dry-run`: list the planned changes without creating an output file.
* `--compress-id0`: zlib-compress the rebuilt ID0 section. Other section
  compression methods are preserved by the container writer.
* `--preserve-version-labels`: change the embedded parameter version but leave
  Root A[-1] and S[1303] unchanged, even if their values are newer than 8.4.
* `--allow-untested-schema`: explicitly attempt the version-only transformation
  for an untested newer parameter schema. Output compatibility is not implied.

Python API:

```python
from pathlib import Path
from idbdowngrade import DatabasePaths, DowngradeOptions, downgrade_file

paths = DatabasePaths(Path("input.i64"), Path("output.i64"))
options = DowngradeOptions(compress_id0=True)
result = downgrade_file(paths, options)
```

Python 3.9+ is required. Zstd-compressed v910 input uses Python 3.14's
`compression.zstd` or `backports.zstd` on earlier Python.

Validation: the command's output for the supplied converted MBR sample is
byte-for-byte identical to the packed-rebuild candidate the user successfully
opened in IDA 8.4. Fresh-9.x output additionally changes the two newer version
labels; that specific output has not yet been opened in IDA. These small samples
do not establish compatibility for arbitrary type libraries, processor-specific
records, plugin state, or newer schemas. Those payloads remain undecoded and
are copied unchanged, not silently discarded.

Anonymizer command
==================

This tool removes license information, and original file paths.


```sh
python3 idbanonymize.py source.i64 anonymous.i64
python3 idbanonymize.py --dry-run source.i64
python3 idbanonymize.py --filename shared.bin source.i64 anonymous.i64
```

The default scope is known user/license metadata and the input filename:

* Remove payload records from `$ original user` and `$ user1`. This covers the
  legacy license blob, newer JSON fragments, and other tags/indices on those
  dedicated nodes. Generic node-name records and name-index anchors remain;
  unrelated records, references, and node-allocation counters are retained.
* Replace `Root Node.V` with `input.bin`, or `--filename`'s chosen basename,
  preserving its existing NUL termination. An undecoded filename encoding
  raises an error rather than silently retaining a potentially private path.
* Redact known filename/path tokens in ordinary/repeatable address comments
  (`S[0]`, `S[1]`) and anterior/posterior address-comment lines
  (`S[1000..2999]`). Full-path separator variants, the basename, and derived
  `.idb`/`.i64` names are recognized. Remaining comment bytes are preserved.
* Rebuild ID0 from retained records into new zero-filled pages. Old free pages
  and slack are not copied, so deleting a license record does not leave its
  old bytes in those areas of the output.

Only literal, case-sensitive filename/path tokens are replaced. Short input
basenames under four bytes are not guessed in comments; select them explicitly
with `--redact-text`. Non-UTF-8 address comments are reported and retained
undecoded. Internal-node comments, function-specific comment encodings, paths
stored by plugins, type records, scripts, and unknown structures are not
silently rewritten as though they were ordinary comments.

Additional controls:

* `--node NAME`: additionally remove payloads from a specifically selected
  named metadata node. It must resolve to an internal node, not a code address.
* `--redact-text TEXT`: additionally redact this literal identifier in the
  supported comment records, replacing it with `[redacted]`. Repeatable.
* `--compress-id0`: compress the rebuilt section.
* `--allow-residuals`: retain a **partial result for review** if the residual
  audit finds known identifiers outside the transformed records. Their section
  numbers are printed; the unidentified data is not overwritten blindly.

Verification checks all retained output records and section checksums. A
residual audit searches decoded section bytes, including ID0 page slack, for
known filename tokens and removed complete metadata values of at least 32
bytes (excluding single-byte repeated patterns). Short values and arbitrary
substrings of removed payloads are not fingerprinted: a successful audit is
not proof that every possible identity representation has been found.
If known residues remain, the default operation fails and removes its output.
The command does not log license payloads or original input paths.

Opaque sections are copied without semantic decoding. The opaque 16-byte
container-header value, input-file hashes, timestamps, analysis data and
unselected records are retained. This is scoped metadata removal, not a
promise that the database is unlinkable or contains no personal information.
The original source is unchanged; existing output paths are refused.

Output uses the working v6 container and retains semantic version metadata.
For both operations, downgrade first and anonymize the result:

```sh
python3 idbdowngrade.py source.i64 downgraded.i64
python3 idbanonymize.py downgraded.i64 anonymous.i64
```

Opening and saving in IDA may repopulate user/license information. Recheck
metadata in the saved result before distributing it. Native IDA acceptance
of the anonymized output still needs testing.

Python API uses `idbtransform.DatabasePaths`,
`idbanonymize.AnonymizeOptions`, and `idbanonymize.anonymize_file()`.
The previously exported `DatabasePaths` and `RecordDigest` names remain
available through `idbdowngrade` for compatibility.

TODO
====

 * add option to list all comments stored in the database
 * add option to list flags for a list of addresses.

Author
======

Willem Hengeveld <itsme@xs4all.nl>

The downgrade and anonymizer tools were created with help from chatgpt.

