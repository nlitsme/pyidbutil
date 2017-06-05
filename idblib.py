"""
idblib - a module for reading hex-rays Interactive DisAssembler databases

Supports database versions starting with IDA v2.0

IDA v1.x  is not supported, that was an entirely different file format.
IDA v2.x  databases are organised as several files, in a directory
IDA v3.x  databases are bundled into .idb files
IDA v4 .. v6  various improvements, like databases larger than 4Gig, and 64 bit support.

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>


An IDB file can contain up to 6 sections:
    id0  the main database
    id1  contains flags for each byte - what is returned by idc.GetFlags(ea)
    nam  contains a list of addresses of named items
    seg  .. only in older databases
    til  type info
    id2  ?

The id0 database is a simple key/value database, much like leveldb

types of records:

Some bookkeeping:

    "$ MAX NODE" -> the highest numbered node value in use.

A list of names:

    "N" + name  -> the node id for that name.

names are both user/disassembler symbols assigned to addresses
in the disassembled code, and IDA internals, like lists of items,
For example: '$ structs', or 'Root Node'.

The main part:

    "." + nodeid + tag + index

This maps directly onto the idasdk netnode interface.
The size of the nodeid and index is 32bits for .idb files and 64 bits for .i64 files.
The nodeid and index are encoded as bigendian numbers in the key, and as little endian
numbers in (most of) the values.


"""
from __future__ import division, print_function, absolute_import, unicode_literals
import struct
import binascii
import re
import os

#############################################################################
# some code to make this library run with both python2 and python3
#############################################################################

import sys
if sys.version_info[0] == 3:
    long = int
else:
    bytes = bytearray

try:
    cmp(1, 2)
except:
    # python3 does not have cmp
    def cmp(a, b): return (a > b) - (a < b)


def makeStringIO(data):
    if sys.version_info[0] == 2:
        from StringIO import StringIO
        return StringIO(data)
    else:
        from io import BytesIO
        return BytesIO(data)


#############################################################################
# some utility functions
#############################################################################


def nonefmt(fmt, item):
    # helper for outputting None without raising an error
    if item is None:
        return "-"
    return fmt % item


def hexdump(data):
    if data is None:
        return
    return binascii.b2a_hex(data).decode('utf-8')


#############################################################################


class FileSection(object):
    """
    Presents a file like object which is a section of a larger file.

    `fh` is expected to have a seek and read method.


    This class is used to access a section (e.g. the .id0 file) of a larger file (e.g. the .idb file)
    and make read/seek behave as if it were a seperate file.
    """
    def __init__(self, fh, start, end):
        self.fh = fh
        self.start = start
        self.end = end

        self.curpos = 0
        self.fh.seek(self.start)

    def read(self, size=None):
        want = self.end - self.start - self.curpos
        if size is not None and want > size:
            want = size

        if want <= 0:
            return b""

        # make sure filepointer is at correct position since we are sharing the fh object with others.
        self.fh.seek(self.curpos + self.start)
        data = self.fh.read(want)
        self.curpos += len(data)
        return data

    def seek(self, offset, *args):
        def isvalidpos(offset):
            return 0 <= offset <= self.end - self.start

        if len(args) == 0:
            whence = 0
        else:
            whence = args[0]
        if whence == 0:
            if not isvalidpos(offset):
                print("invalid seek: from %x to SET:%x" % (self.curpos, offset))
                raise Exception("illegal offset")
            self.curpos = offset
        elif whence == 1:
            if not isvalidpos(self.curpos + offset):
                raise Exception("illegal offset")
            self.curpos += offset
        elif whence == 2:
            if not isvalidpos(self.end - self.start + offset):
                raise Exception("illegal offset")
            self.curpos = self.end - self.start + offset
        self.fh.seek(self.curpos + self.start)

    def tell(self):
        return self.curpos


def idaunpack(buf):
    """
    Special data packing format, used in struct definitions, and .id2 files

    sdk functions: pack_dd etc.
    """
    buf = bytearray(buf)

    def nextval(o):
        val = buf[o] ; o += 1
        if val == 0xff:  # 32 bit value
            val, = struct.unpack_from(">L", buf, o)
            o += 4
            return val, o
        if val < 0x80:  # 7 bit value
            return val, o
        val <<= 8
        val |= buf[o] ; o += 1
        if val < 0xc000:  # 14 bit value
            return val & 0x3fff, o

        # 29 bit value
        val <<= 8
        val |= buf[o] ; o += 1
        val <<= 8
        val |= buf[o] ; o += 1
        return val & 0x1fffffff, o

    values = []
    o = 0
    while o < len(buf):
        val, o = nextval(o)
        values.append(val)
    return values


class IDBFile(object):
    """
    Provide access to the various sections in an .idb file.

    Usage:

    idb = IDBFile(fhandle)
    id0 = idb.getsection(ID0File)

    ID0File is expected to have a class property 'INDEX'

# v1..v5  id1 and nam files start with 'Va0' .. 'Va4'
# v6      id1 and nam files start with 'VA*'
# til files start with 'IDATIL'
# id2 files start with 'IDAS\x1d\xa5\x55\x55'

    """
    def __init__(self, fh):
        """ constructor takes a filehandle """
        self.fh = fh
        self.fh.seek(0)
        hdrdata = self.fh.read(0x100)

        self.magic = hdrdata[0:4].decode('utf-8', 'ignore')
        if self.magic not in ('IDA0', 'IDA1', 'IDA2'):
            raise Exception("invalid file magic")

        values = struct.unpack_from("<6LH6L", hdrdata, 6)
        if values[5] != 0xaabbccdd:
            fileversion = 0
            offsets = list(values[0:5])
            offsets.append(0)
            checksums = [0 for _ in range(6)]
        else:
            fileversion = values[6]

            if fileversion < 5:
                offsets = list(values[0:5])
                checksums = list(values[8:13])
                idsofs, idscheck = struct.unpack_from("<LH" if fileversion == 1 else "<LL", hdrdata, 56)
                offsets.append(idsofs)
                checksums.append(idscheck)

                # note: filever 4  has '0x5c', zeros, md5, more zeroes
            else:
                values = struct.unpack_from("<QQLLHQQQ5LQL", hdrdata, 6)
                offsets = [values[_] for _ in (0, 1, 5, 6, 7, 13)]
                checksums = [values[_] for _ in (8, 9, 10, 11, 12, 14)]

        # offsets now has offsets to the various idb parts
        #  id0, id1, nam, seg, til, id2 ( = sparse file )
        self.offsets = offsets
        self.checksums = checksums
        self.fileversion = fileversion

    def getsectioninfo(self, i):
        """
        Returns a tuple with section parameters by index.

        The parameteres are:
         * compression flag
         * data offset
         * data size
         * data checksum

        Sections are stored in a fixed order: id0, id1, nam, seg, til, id2
        """
        if not 0 <= i < len(self.offsets):
            return 0, 0, 0, 0

        if self.offsets[i] == 0:
            return 0, 0, 0, 0

        self.fh.seek(self.offsets[i])
        if self.fileversion < 5:
            comp, size = struct.unpack("<BL", self.fh.read(5))
            ofs = self.offsets[i] + 5
        else:
            comp, size = struct.unpack("<BQ", self.fh.read(9))
            ofs = self.offsets[i] + 9
        return comp, ofs, size, self.checksums[i]

    def getpart(self, ix):
        """
        Returns a fileobject for the specified section.

        This method optionally decompresses the data found in the .idb file,
        and returns a file-like object, with seek, read, tell.
        """
        if self.offsets[ix] == 0:
            return

        comp, ofs, size, checksum = self.getsectioninfo(ix)

        fh = FileSection(self.fh, ofs, ofs + size)
        if comp == 2:
            import zlib
            # very old databases used a different compression scheme:
            wbits = -15 if self.magic == 'IDA0' else 15

            fh = makeStringIO(zlib.decompress(fh.read(size), wbits))
        elif comp == 0:
            pass
        else:
            raise Exception("unsupported section encoding: %02x" % comp)
        return fh

    def getsection(self, cls):
        """
        Constructs an object for the specified section.
        """
        return cls(self, self.getpart(cls.INDEX))


class RecoverIDBFile:
    """
    RecoverIDBFile has the same interface as IDBFile, but expects the database to be split over several files.

    This is useful for opening  IDAv2.x databases, or for recovering data from unclosed databases.
    """
    id2ext = ['.id0', '.id1', '.nam', '.seg', '.til', '.id2']

    def __init__(self, args, basepath, dbfiles):
        if args.i64:
            self.magic = 'IDA2'
        else:
            self.magic = 'IDA1'
        self.basepath = basepath
        self.dbfiles = dbfiles
        self.fileversion = 0

    def getsectioninfo(self, i):
        if not 0 <= i < len(self.id2ext):
            return 0, 0, 0, 0
        ext = self.id2ext[i]
        if ext not in self.dbfiles:
            return 0, 0, 0, 0
        return 0, 0, os.path.getsize(self.dbfiles[ext]), 0

    def getpart(self, ix):
        if not 0 <= ix < len(self.id2ext):
            return None
        ext = self.id2ext[ix]
        if ext not in self.dbfiles:
            print("can't find %s" % ext)
            return None
        return open(self.dbfiles[ext], "rb")

    def getsection(self, cls):
        part = self.getpart(cls.INDEX)
        if part:
            return cls(self, part)


def binary_search(a, k):
    """
    Do a binary search in an array of objects ordered by '.key'

    returns the largest index for which:  a[i].key <= k

    like c++: a.upperbound(k)--
    """
    first, last = 0, len(a)
    while first < last:
        mid = (first + last) >> 1
        if k < a[mid].key:
            last = mid
        else:
            first = mid + 1
    return first - 1


"""
################################################################################

I would have liked to make these classes a nested class of BTree, but
the problem is than there is no way for a nested-nested class
of BTree to refer back to a toplevel nested class of BTree.
So moving these outside of BTree so i can use them as baseclasses
in the various page implementations

class BTree:
    class BaseEntry(object): pass
    class BasePage(object): pass
    class Page15(BasePage):
        class Entry(BTree.BaseEntry):
            pass

>>> NameError: name 'BTree' is not defined

"""


class BaseIndexEntry(object):
    """
    Baseclass for Index Entries.

    Index entries have a key + value, and a page containing keys larger than that key
    in this index entry.

    """
    def __init__(self, data):
        ofs = self.recofs
        if self.recofs < 6:
            # reading an invalid page...
            self.val = self.key = None
            return

        keylen, = struct.unpack_from("<H", data, ofs) ; ofs += 2
        self.key = data[ofs:ofs + keylen]  ; ofs += keylen
        vallen, = struct.unpack_from("<H", data, ofs) ; ofs += 2
        self.val = data[ofs:ofs + vallen]  ; ofs += vallen

    def __repr__(self):
        return "%06x: %s = %s" % (self.page, hexdump(self.key), hexdump(self.val))


class BaseLeafEntry(BaseIndexEntry):
    """
    Baseclass for Leaf Entries

    Leaf entries have a key + value, and an `indent`

    The `indent` is there to save space in the index, since subsequent keys
    usually are very similar.
    The indent specifies the offset where this key is different from the previous key
    """
    def __init__(self, key, data):
        """ leaf entries get the previous key a an argument. """
        super(BaseLeafEntry, self).__init__(data)
        self.key = key[:self.indent] + self.key

    def __repr__(self):
        return " %02x:%02x: %s = %s" % (self.unknown1, self.unknown, hexdump(self.key), hexdump(self.val))


class BTree(object):
    """
    BTree is the IDA main database engine.
    It allows the user to do a binary search for records with
    a specified key relation ( >, <, ==, >=, <= )
    """
    class BasePage(object):
        """
        Baseclass for Pages. for the various btree versions ( 1.5, 1.6 and 2.0 )
        there are subclasses which specify the exact layout of the page header,
        and index / leaf entries.

        Leaf pages don't have a 'preceeding' page pointer.

        """
        def __init__(self, data, entsize, entfmt):
            self.preceeding, self.count = struct.unpack_from(entfmt, data)
            if self.preceeding:
                entrytype = self.IndexEntry
            else:
                entrytype = self.LeafEntry

            self.index = []
            key = b""
            for i in range(self.count):
                ent = entrytype(key, data, entsize * (1 + i))
                self.index.append(ent)
                key = ent.key
            self.unknown, self.freeptr = struct.unpack_from(entfmt, data, entsize * (1 + self.count))

        def find(self, key):
            """
            Searches pages for key, returns relation to key:

            recurse -> found a next level index page to search for key.
                       also returns the next level page nr
            gt -> found a value with a key greater than the one searched for.
            lt -> found a value with a key less than the one searched for.
            eq -> found a value with a key equal to the one searched for.
                       gt, lt and eq return the index for the key found.

            # for an index entry: the key is 'less' than anything in the page pointed to.
            """
            i = binary_search(self.index, key)
            if i < 0:
                if self.isindex():
                    return ('recurse', -1)
                return ('gt', 0)
            if self.index[i].key == key:
                return ('eq', i)
            if self.isindex():
                return ('recurse', i)
            return ('lt', i)

        def getpage(self, ix):
            """ For Indexpages, returns the page ptr for the specified entry """
            return self.preceeding if ix < 0 else self.index[ix].page

        def getkey(self, ix):
            """ For all page types, returns the key for the specified entry """
            return self.index[ix].key

        def getval(self, ix):
            """ For all page types, returns the value for the specified entry """
            return self.index[ix].val

        def isleaf(self):
            """ True when this is a Leaf Page """
            return self.preceeding == 0

        def isindex(self):
            """ True when this is an Index Page """
            return self.preceeding != 0

        def __repr__(self):
            return ("leaf" if self.isleaf() else ("index<%d>" % self.preceeding)) + repr(self.index)

    ######################################################
    # Page objects for the various versions of the database
    ######################################################
    class Page15(BasePage):
        """ v1.5 b-tree page """
        class IndexEntry(BaseIndexEntry):
            def __init__(self, key, data, ofs):
                self.page, self.recofs = struct.unpack_from("<HH", data, ofs)
                self.recofs += 1   # skip unused zero byte in each key/value record
                super(self.__class__, self).__init__(data)

        class LeafEntry(BaseLeafEntry):
            def __init__(self, key, data, ofs):
                self.indent, self.unknown, self.recofs = struct.unpack_from("<BBH", data, ofs)
                self.unknown1 = 0
                self.recofs += 1   # skip unused zero byte in each key/value record
                super(self.__class__, self).__init__(key, data)

        def __init__(self, data):
            super(self.__class__, self).__init__(data, 4, "<HH")

    class Page16(BasePage):
        """ v1.6 b-tree page """
        class IndexEntry(BaseIndexEntry):
            def __init__(self, key, data, ofs):
                self.page, self.recofs = struct.unpack_from("<LH", data, ofs)
                self.recofs += 1   # skip unused zero byte in each key/value record
                super(self.__class__, self).__init__(data)

        class LeafEntry(BaseLeafEntry):
            def __init__(self, key, data, ofs):
                self.indent, self.unknown1, self.unknown, self.recofs = struct.unpack_from("<BBHH", data, ofs)
                self.recofs += 1   # skip unused zero byte in each key/value record
                super(self.__class__, self).__init__(key, data)

        def __init__(self, data):
            super(self.__class__, self).__init__(data, 6, "<LH")

    class Page20(BasePage):
        """ v2.0 b-tree page """
        class IndexEntry(BaseIndexEntry):
            def __init__(self, key, data, ofs):
                self.page, self.recofs = struct.unpack_from("<LH", data, ofs)
                # unused zero byte is no longer there in v2.0 b-tree
                super(self.__class__, self).__init__(data)

        class LeafEntry(BaseLeafEntry):
            def __init__(self, key, data, ofs):
                self.indent, self.unknown, self.recofs = struct.unpack_from("<HHH", data, ofs)
                self.unknown1 = 0
                super(self.__class__, self).__init__(key, data)

        def __init__(self, data):
            super(self.__class__, self).__init__(data, 6, "<LH")

    class Cursor:
        """
        A Cursor object represents a position in the b-tree.

        It has methods for moving to the next or previous item.
        And methods for retrieving the key and value of the current position

        The position is represented as a list of (page, index) tuples
        """
        def __init__(self, db, stack):
            self.db = db
            self.stack = stack

        def next(self):
            """ move cursor to next entry """
            page, ix = self.stack.pop()
            if page.isleaf():
                # from leaf move towards root
                ix += 1
                while self.stack and ix == len(page.index):
                    page, ix = self.stack.pop()
                    ix += 1
                if ix < len(page.index):
                    self.stack.append((page, ix))
            else:
                # from node move towards leaf
                self.stack.append((page, ix))
                page = self.db.readpage(page.getpage(ix))
                while page.isindex():
                    ix = -1
                    self.stack.append((page, ix))
                    page = self.db.readpage(page.getpage(ix))
                ix = 0
                self.stack.append((page, ix))

        def prev(self):
            """ move cursor to the previous entry """
            page, ix = self.stack.pop()
            ix -= 1
            if page.isleaf():
                # move towards root, until non 'prec' item found
                while self.stack and ix < 0:
                    page, ix = self.stack.pop()
                if ix >= 0:
                    self.stack.append((page, ix))
            else:
                # move towards leaf
                self.stack.append((page, ix))
                while page.isindex():
                    page = self.db.readpage(page.getpage(ix))
                    ix = len(page.index) - 1
                    self.stack.append((page, ix))

        def eof(self):
            return len(self.stack) == 0

        def getkey(self):
            """ return the key value pointed to by the cursor """
            page, ix = self.stack[-1]
            return page.getkey(ix)

        def getval(self):
            """ return the data value pointed to by the cursor """
            page, ix = self.stack[-1]
            return page.getval(ix)

        def __repr__(self):
            return "cursor:" + repr(self.stack)

    def __init__(self, fh):
        """ BTree constructor - takes a filehandle """
        self.fh = fh

        self.fh.seek(0)
        data = self.fh.read(64)

        if data[13:].startswith(b"B-tree v 1.5 (C) Pol 1990"):
            self.parseheader15(data)
            self.page = self.Page15
            self.version = 15
        elif data[19:].startswith(b"B-tree v 1.6 (C) Pol 1990"):
            self.parseheader16(data)
            self.page = self.Page16
            self.version = 16
        elif data[19:].startswith(b"B-tree v2"):
            self.parseheader16(data)
            self.page = self.Page20
            self.version = 20
        else:
            print("unknown btree: %s" % hexdump(data))
            raise Exception("unknown b-tree")

    def parseheader15(self, data):
        self.firstfree, self.pagesize, self.firstindex, self.reccount, self.pagecount = struct.unpack_from("<HHHLH", data, 0)

    def parseheader16(self, data):
        # v16 and v20 both have the same header format
        self.firstfree, self.pagesize, self.firstindex, self.reccount, self.pagecount = struct.unpack_from("<LHLLL", data, 0)

    def readpage(self, nr):
        self.fh.seek(nr * self.pagesize)
        return self.page(self.fh.read(self.pagesize))

    def find(self, rel, key):
        """
        Searches for a record with the specified relation to the key

        A cursor object is returned, the user can call getkey, getval on the cursor
        to retrieve the actual value.
        or call cursor.next() / cursor.prev() to enumerate values.

        'eq'  -> record equal to the key, None when not found
        'le'  -> last record with key <= to key
        'ge'  -> first record with key >= to key
        'lt'  -> last record with key < to key
        'gt'  -> first record with key > to key
        """

        # descend tree to leaf nearest to the `key`
        page = self.readpage(self.firstindex)
        stack = []
        while len(stack) < 256:
            act, ix = page.find(key)
            stack.append((page, ix))
            if act != 'recurse':
                break
            page = self.readpage(page.getpage(ix))

        if len(stack) == 256:
            raise Exception("b-tree corrupted")
        cursor = BTree.Cursor(self, stack)

        # now correct for what was actually asked.
        if act == rel:
            pass
        elif rel == 'eq' and act != 'eq':
            return None
        elif rel in ('ge', 'le') and act == 'eq':
            pass
        elif rel in ('gt', 'ge') and act == 'lt':
            cursor.next()
        elif rel == 'gt' and act == 'eq':
            cursor.next()
        elif rel in ('lt', 'le') and act == 'gt':
            cursor.prev()
        elif rel == 'lt' and act == 'eq':
            cursor.prev()

        return cursor

    def dump(self):
        """ raw dump of all records in the b-tree """
        print("pagesize=%08x, reccount=%08x, pagecount=%08x" % (self.pagesize, self.reccount, self.pagecount))
        self.dumpfree()
        self.dumptree(self.firstindex)

    def dumpfree(self):
        """ list all free pages """
        fmt = "L" if self.version > 15 else "H"
        hdrsize = 8 if self.version > 15 else 4
        pn = self.firstfree
        if pn == 0:
            print("no free pages")
            return
        while pn:
            self.fh.seek(pn * self.pagesize)
            data = self.fh.read(self.pagesize)
            if len(data) == 0:
                print("could not read FREE data at page %06x" % pn)
                break
            count, nextfree = struct.unpack_from("<" + (fmt * 2), data)
            freepages = list(struct.unpack_from("<" + (fmt * count), data, hdrsize))
            freepages.insert(0, pn)
            for pn in freepages:
                self.fh.seek(pn * self.pagesize)
                data = self.fh.read(self.pagesize)
                print("%06x: free: %s" % (pn, hexdump(data[:64])))
            pn = nextfree

    def dumpindented(self, pn, indent=0):
        """
        Dump all nodes of the current page with keys indented, showing how the `indent`
        feature works
        """
        page = self.readpage(pn)
        print("  " * indent, page)
        if page.isindex():
            print("  " * indent, end="")
            self.dumpindented(page.preceeding, indent + 1)
            for p in range(len(page.index)):
                print("  " * indent, end="")
                self.dumpindented(page.getpage(p), indent + 1)

    def dumptree(self, pn):
        """
        Walks entire tree, dumping all records on each page
        in sequential order
        """
        page = self.readpage(pn)
        print("%06x: preceeding = %06x, reccount = %04x" % (pn, page.preceeding, page.count))
        for ent in page.index:
            print("    %s" % ent)
        if page.preceeding:
            self.dumptree(page.preceeding)
            for ent in page.index:
                self.dumptree(ent.page)

    def pagedump(self):
        """
        dump the contents of all pages, ignoring links between pages,
        this will enable you to view contents of pages which have become
        lost due to datacorruption.
        """
        self.fh.seek(self.pagesize)
        pn = 1
        while True:
            try:
                pagedata = self.fh.read(self.pagesize)
                if len(pagedata) == 0:
                    break
                elif len(pagedata) != self.pagesize:
                    print("%06x: incomplete - %d bytes ( pagesize = %d )" % (pn, len(pagedata), self.pagesize))
                    break
                elif pagedata == b'\x00' * self.pagesize:
                    print("%06x: empty" % (pn))
                else:
                    page = self.page(pagedata)

                    print("%06x: preceeding = %06x, reccount = %04x" % (pn, page.preceeding, page.count))
                    for ent in page.index:
                        print("    %s" % ent)
            except Exception as e:
                print("%06x: ERROR decoding as B-tree page: %s" % (pn, e))
            pn += 1


class ID0File(object):
    """
    Reads .id0 or 0.ida  files, containing a v1.5, v1.6 or v2.0 b-tree database.

    This is basically the low level netnode interface from the idasdk.

    There are two major groups of nodes in the database:

    key = "N"+name  -> value = littleendian(nodeid)
    key = "."+bigendian(nodeid)+char(tag)+bigendian(value)
    key = "."+bigendian(nodeid)+char(tag)+string

    key = "."+bigendian(nodeid)+char(tag)

    and some special nodes for bookkeeping:
    "$ MAX LINK"
    "$ MAX NODE"
    "$ NET DESC"

    Very old databases also have name entries with a lowercase 'n',
    and corresponding '-'+value nodes.
    I am not sure what those are for.

    several items have specially named nodes, like "$ structs", "$ enums", "Root Node"

    nodeByName(name)  returns the nodeid for a name
    bytes(nodeid, tag, val)  returns the value for a specific node.

    """
    INDEX = 0

    def __init__(self, idb, fh):
        self.btree = BTree(fh)

        self.wordsize = None

        if idb.magic == 'IDA2':
            # .i64 files use 64 bit values for some things.
            self.wordsize = 8
        elif idb.magic in ('IDA0', 'IDA1'):
            self.wordsize = 4
        else:
            # determine wordsize from value of '$ MAX NODE'
            c = self.btree.find('eq', b'$ MAX NODE')
            if c and not c.eof():
                self.wordsize = len(c.getval())

        if self.wordsize not in (4, 8):
            print("Can not determine wordsize for database - assuming 32 bit")
            self.wordsize = 4

        if self.wordsize == 4:
            self.nodebase = 0xFF000000
            self.fmt = "L"
        else:
            self.nodebase = 0xFF00000000000000
            self.fmt = "Q"

        # set the keyformat for this database
        self.keyfmt = ">s" + self.fmt + "s" + self.fmt

    def prettykey(self, key):
        """
        returns the key in a readable format.
        """
        f = list(self.decodekey(key))
        f[0] = f[0].decode('utf-8')
        if len(f) > 2 and type(f[2]) == bytes:
            f[2] = f[2].decode('utf-8')

        if f[0] == '.':
            if len(f) == 2:
                return "%s%16x" % tuple(f)
            elif len(f) == 3:
                return "%s%16x %s" % tuple(f)
            elif len(f) == 4:
                if f[2] == 'H' and type(f[3]) in (str, bytes):
                    f[3] = f[3].decode('utf-8')
                    return "%s%16x %s '%s'" % tuple(f)
                elif type(f[3]) in (int, long):
                    return "%s%16x %s %x" % tuple(f)
                else:
                    f[3] = hexdump(f[3])
                    return "%s%16x %s %s" % tuple(f)
        elif f[0] in ('N', 'n', '$'):
            if type(f[1]) in (int, long):
                return "%s %x %16x" % tuple(f)
            else:
                return "%s'%s'" % tuple(f)
        elif f[0] == '-':
            return "%s %x" % tuple(f)

        return hexdump(key)

    def prettyval(self, val):
        """
        returns the value in a readable format.
        """
        if len(val) == self.wordsize and val[-1:] in (b'\x00', b'\xff'):
            return "%x" % struct.unpack("<" + self.fmt, val)
        if len(val) == self.wordsize and re.search(b'[\x00-\x08\x0b\x0c\x0e-\x1f]', val, re.DOTALL):
            return "%x" % struct.unpack("<" + self.fmt, val)
        if len(val) < 2 or not re.match(b'^[\x09\x0a\x0d\x20-\xff]+.$', val, re.DOTALL):
            return hexdump(val)
        val = val.replace(b"\n", b"\\n")
        return "'%s'" % val.decode('utf-8', 'ignore')

    def nodeByName(self, name):
        """ Return a nodeid by name """
        # note: really long names are encoded differently:
        #  'N'+'\x00'+pack('Q', nameid)  => ofs
        #  and  (ofs, 'N') -> nameid

        # at nodebase ( 0xFF000000, 'S', 0x100*nameid )  there is a series of blobs for max 0x80000 sized names.
        cur = self.btree.find('eq', self.namekey(name))
        if cur:
            return struct.unpack('<' + self.fmt, cur.getval())[0]

    def namekey(self, name):
        if type(name) in (int, long):
            return struct.pack("<sB" + self.fmt, b'N', 0, name)
        return b'N' + name.encode('utf-8')

    def makekey(self, *args):
        """ return a binary key for the nodeid, tag and optional value """
        if len(args) > 1:
            args = args[:1] + (args[1].encode('utf-8'),) + args[2:]
        if len(args) == 3 and type(args[-1]) == str:
            # node.tag.string type keys
            return struct.pack(self.keyfmt[:1 + len(args)], b'.', *args[:-1]) + args[-1].encode('utf-8')
        elif len(args) == 3 and type(args[-1]) == type(-1) and args[-1] < 0:
            # negative values -> need lowercase fmt char
            return struct.pack(self.keyfmt[:1 + len(args)] + self.fmt.lower(), b'.', *args)
        else:
            # node.tag.value type keys
            return struct.pack(self.keyfmt[:2 + len(args)], b'.', *args)

    def decodekey(self, key):
        """
        splits a key in a tuple, one of:
           ( [ 'N', 'n', '$' ],  0,   bignameid )
           ( [ 'N', 'n', '$' ],  name  )
           ( '-',  id )
           ( '.',  id )
           ( '.',  id,  tag )
           ( '.',  id,  tag, value )
           ( '.',  id,  'H', name  )
        """
        if key[:1] in (b'n', b'N', b'$'):
            if key[1:2] == b"\x00" and len(key) == 2 + self.wordsize:
                return struct.unpack(">sB" + self.fmt, key)
            else:
                return key[:1], key[1:].decode('utf-8', 'ignore')
        if key[:1] == b'-':
            return struct.unpack(">s" + self.fmt, key)
        if len(key) == 1 + self.wordsize:
            return struct.unpack(self.keyfmt[:3], key)
        if len(key) == 1 + self.wordsize + 1:
            return struct.unpack(self.keyfmt[:4], key)
        if len(key) == 1 + 2 * self.wordsize + 1:
            return struct.unpack(self.keyfmt[:5], key)
        if len(key) > 1 + self.wordsize + 1:
            f = struct.unpack_from(self.keyfmt[:4], key)
            return f + (key[2 + self.wordsize:], )
        raise Exception("unknown key format")

    def bytes(self, *args):
        """ return a raw value for the given arguments """
        if len(args) == 1 and isinstance(args[0], BTree.Cursor):
            cur = args[0]
        else:
            cur = self.btree.find('eq', self.makekey(*args))

        if cur:
            return cur.getval()

    def int(self, *args):
        """
        Return the integer stored in the specified node.

        Any type of integer will be decoded: byte, short, long, long long

        """
        data = self.bytes(*args)
        if data is not None:
            if len(data) == 1:
                return struct.unpack("<B", data)[0]
            if len(data) == 2:
                return struct.unpack("<H", data)[0]
            if len(data) == 4:
                return struct.unpack("<L", data)[0]
            if len(data) == 8:
                return struct.unpack("<Q", data)[0]
            print("can't get int from %s" % hexdump(data))

    def string(self, *args):
        """ return string stored in node """
        data = self.bytes(*args)
        if data is not None:
            return data.rstrip(b"\x00").decode('utf-8')

    def name(self, id):
        """
        resolves a name, both short and long names.
        """
        data = self.bytes(id, 'N')
        if not data:
            print("%x has no name" % id)
            return
        if data[:1] == b'\x00':
            nameid, = struct.unpack_from(">" + self.fmt, data, 1)
            nameblob = self.blob(self.nodebase, 'S', nameid * 256, nameid * 256 + 32)
            return nameblob.rstrip(b"\x00").decode('utf-8')
        return data.rstrip(b"\x00").decode('utf-8')

    def blob(self, nodeid, tag, start=0, end=0xFFFFFFFF):
        """
        Blobs are stored in sequential nodes
        with increasing index values.

        most blobs, like scripts start at index
        0, long names start at a specified
        offset.

        """
        startkey = self.makekey(nodeid, tag, start)
        endkey = self.makekey(nodeid, tag, end)
        cur = self.btree.find('ge', startkey)
        data = b''
        while cur.getkey() <= endkey:
            data += cur.getval()
            cur.next()
        return data


class ID1File(object):
    """
    Reads .id1 or 1.IDA files, containing byte flags

    This is basically the information for the .idc GetFlags(ea),
    FirstSeg(), NextSeg(ea), SegStart(ea), SegEnd(ea) functions
    """
    INDEX = 1

    class SegInfo:
        def __init__(self, startea, endea, offset):
            self.startea = startea
            self.endea = endea
            self.offset = offset

    def __init__(self, idb, fh):
        if idb.magic == 'IDA2':
            wordsize, fmt = 8, "Q"
        else:
            wordsize, fmt = 4, "L"
        # todo: verify wordsize using the following heuristic:
        #  L -> starting at: seglistofs + nsegs*seginfosize  are all zero
        #  L -> starting at seglistofs .. nsegs*seginfosize every even word must be unique

        self.fh = fh
        fh.seek(0)
        hdrdata = fh.read(32)
        magic = hdrdata[:4]
        if magic in (b'Va4\x00', b'Va3\x00', b'Va2\x00', b'Va1\x00', b'Va0\x00'):
            nsegments, npages = struct.unpack_from("<HH", hdrdata, 4)
            #  filesize / npages == 0x2000  for all cases
            seglistofs = 8
            seginfosize = 3
        elif magic == b'VA*\x00':
            always3, nsegments, always2k, npages = struct.unpack_from("<LLLL", hdrdata, 4)
            if always3 != 3:
                print("ID1: first dword != 3: %08x" % always3)
            if always2k != 0x800:
                print("ID1: third dword != 2k: %08x" % always2k)
            seglistofs = 20
            seginfosize = 2
        else:
            raise Exception("unknown id1 magic: %s" % hexdump(magic))

        self.seglist = []
        # Va0  - ida v3.0.5
        # Va3  - ida v3.6
        fh.seek(seglistofs)
        if magic in (b'Va4\x00', b'Va3\x00', b'Va2\x00', b'Va1\x00', b'Va0\x00'):
            segdata = fh.read(nsegments * 3 * wordsize)
            for o in range(nsegments):
                startea, endea, id1ofs = struct.unpack_from("<" + fmt + fmt + fmt, segdata, o * seginfosize * wordsize)
                self.seglist.append(self.SegInfo(startea, endea, id1ofs))
        elif magic == b'VA*\x00':
            segdata = fh.read(nsegments * 2 * wordsize)
            id1ofs = 0x2000
            for o in range(nsegments):
                startea, endea = struct.unpack_from("<" + fmt + fmt, segdata, o * seginfosize * wordsize)
                self.seglist.append(self.SegInfo(startea, endea, id1ofs))
                id1ofs += 4 * (endea - startea)

    def is32bit_heuristic(self, fh, seglistofs):
        fh.seek(seglistofs)
        # todo: verify wordsize using the following heuristic:
        #  L -> starting at: seglistofs + nsegs*seginfosize  are all zero
        #  L -> starting at seglistofs .. nsegs*seginfosize every even word must be unique

    def dump(self):
        """ print first and last bits for each segment """
        for seg in self.seglist:
            print("==== %08x-%08x" % (seg.startea, seg.endea))
            if seg.endea - seg.startea < 30:
                for ea in range(seg.startea, seg.endea):
                    print("    %08x: %08x" % (ea, self.getFlags(ea)))
            else:
                for ea in range(seg.startea, seg.startea + 10):
                    print("    %08x: %08x" % (ea, self.getFlags(ea)))
                print("...")
                for ea in range(seg.endea - 10, seg.endea):
                    print("    %08x: %08x" % (ea, self.getFlags(ea)))

    def find_segment(self, ea):
        """ do a linear search for the given address in the segment list """
        for seg in self.seglist:
            if seg.startea <= ea < seg.endea:
                return seg

    def getFlags(self, ea):
        seg = self.find_segment(ea)
        self.fh.seek(seg.offset + 4 * (ea - seg.startea))
        return struct.unpack("<L", self.fh.read(4))[0]

    def firstSeg(self):
        return self.seglist[0].startea

    def nextSeg(self, ea):
        for i, seg in enumerate(self.seglist):
            if seg.startea <= ea < seg.endea:
                if i + 1 < len(self.seglist):
                    return self.seglist[i + 1].startea
                else:
                    return

    def segStart(self, ea):
        seg = self.find_segment(ea)
        return seg.startea

    def segEnd(self, ea):
        seg = self.find_segment(ea)
        return seg.endea


class NAMFile(object):
    """ reads .nam or NAMES.IDA files, containing ptrs to named items """
    INDEX = 2

    def __init__(self, idb, fh):
        if idb.magic == 'IDA2':
            wordsize, fmt = 8, "Q"
        else:
            wordsize, fmt = 4, "L"

        self.fh = fh
        fh.seek(0)
        hdrdata = fh.read(64)
        magic = hdrdata[:4]
        # Va0  - ida v3.0.5
        # Va1  - ida v3.6
        if magic in (b'Va4\x00', b'Va3\x00', b'Va2\x00', b'Va1\x00', b'Va0\x00'):
            always1, npages, always0, nnames, pagesize = struct.unpack_from("<HH" + fmt + fmt + "L", hdrdata, 4)
            if always1 != 1: print("nam: first hw = %d" % always1)
            if always0 != 0: print("nam: third dw = %d" % always0)
        elif magic == b'VA*\x00':
            always3, always1, always2k, npages, always0, nnames = struct.unpack_from("<LLLL" + fmt + "L", hdrdata, 4)
            if always3 != 3: print("nam: 3 hw = %d" % always3)
            if always1 != 1: print("nam: 1 hw = %d" % always1)
            if always0 != 0: print("nam: 0 dw = %d" % always0)
            if always2k != 0x800: print("nam: 2k dw = %d" % always2k)
            pagesize = 0x2000
        else:
            raise Exception("unknown nam magic: %s" % hexdump(magic))
        if idb.magic == 'IDA2':
            nnames >>= 1
        self.wordsize = wordsize
        self.wordfmt = fmt
        self.nnames = nnames
        self.pagesize = pagesize

    def dump(self):
        print("nam: nnames=%d, npages=%d, pagesize=%08x" % (self.nnames, self.npages, self.pagesize))

    def allnames(self):
        self.fh.seek(self.pagesize)
        n = 0
        while n < self.nnames:
            data = self.fh.read(self.pagesize)
            want = min(self.nnames - n, int(self.pagesize / self.wordsize))
            ofslist = struct.unpack_from("<%d%s" % (want, self.wordfmt), data, 0)
            for ea in ofslist:
                yield ea
            n += want


class SEGFile(object):
    """ reads .seg or $SEGS.IDA files.  """
    INDEX = 3

    def __init__(self, idb, fh):
        pass


class TILFile(object):
    """ reads .til files """
    INDEX = 4

    def __init__(self, idb, fh):
        pass
# note: v3 databases had a .reg instead of .til


class ID2File(object):
    """
    Reads .id2 files

    ID2 sections contain packed data, resulting in tripples
    of unknown use.
    """
    INDEX = 5

    def __init__(self, idb, fh):
        pass
