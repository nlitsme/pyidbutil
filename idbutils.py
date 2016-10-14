from __future__ import division, print_function, absolute_import, unicode_literals
import struct
import binascii

try:
    cmp(1,2)
except:
    def cmp(a,b): return (a>b)-(a<b)


class FileSection(object):
    """
    Presents a file like object which is a section of a larger file.

    `fh` is expected to have a seek and read method.

    """
    def __init__(self, fh, start, end):
        self.fh = fh
        self.start = start
        self.end = end

        self.curpos = 0
        self.fh.seek(self.start)

    def read(self, size):
        want = min(size, self.end-self.start - self.curpos)
        if want<=0:
            return b""

        data = self.fh.read(want)
        self.curpos += len(data)
        return data

    def seek(self, offset, *args):

        def isvalidpos(offset):
            return 0 <= offset <= self.end-self.start

        if len(args)==0:
            whence = 0
        else:
            whence = args[0]
        if whence==0:
            if not isvalidpos(offset):
                print("invalid seek: from %x to SET:%x" % ( self.curpos, offset ))
                raise Exception("illegal offset")
            self.curpos = offset
        elif whence==1:
            if not isvalidpos(self.curpos + offset):
                raise Exception("illegal offset")
            self.curpos += offset
        elif whence==2:
            if not isvalidpos(self.end - self.start + offset):
                raise Exception("illegal offset")
            self.curpos = self.end - self.start + offset
        self.fh.seek(self.curpos + self.start)

    def tell(self):
        return self.curpos


class CompressedStream(object):
    # todo: random access to compressed stream - see zran.c
    def __init__(self, fh):
        self.fh = fh
        self.curpos = 0
    def read(self, size):
        # todo
        return b""
    def seek(self, offset, *args):

        if len(args)==0:
            whence = 0
        else:
            whence = args[0]
        if whence==0:
            self.curpos = offset
        elif whence==1:
            self.curpos += offset
        elif whence==2:
            self.curpos = self.end - self.start + offset

    def tell(self):
        return self.curpos


import unittest
class TestFileSection(unittest.TestCase):
    def test_file(self):
        import StringIO
        s = StringIO.StringIO("0123456789abcdef")
        fh = FileSection(s, 3, 11)
        self.assertEqual(fh.read(3), "345")
        self.assertEqual(fh.read(8), "6789a")
        self.assertEqual(fh.read(8), "")

        fh.seek(-1,2)
        self.assertEqual(fh.read(8), "a")
        fh.seek(3)
        self.assertEqual(fh.read(2), "67")
        fh.seek(-2,1)
        self.assertEqual(fh.read(2), "67")
        fh.seek(2,1)
        self.assertEqual(fh.read(2), "a")

        fh.seek(8)
        self.assertEqual(fh.read(1), "")
        with self.assertRaises(Exception):
            fh.seek(9)

class IDBFile(object):
    def __init__(self, fh):
        self.fh = fh
        self.fh.seek(0)
        hdrdata = self.fh.read(0x100)

        self.magic = hdrdata[0:4]
        if self.magic not in (b'IDA0', b'IDA1', b'IDA2'):
            raise Exception("invalid file magic")

        values = struct.unpack_from("<6LH6L", hdrdata, 6)
        if values[5]!=0xaabbccdd:
            fileversion = 0
            offsets = list(values[0:5])
            offsets.append(0)
            checksums = [0 for _ in range(6)]
        else:
            fileversion = values[6]

            if fileversion<5:
                offsets = list(values[0:5])
                checksums = list(values[8:13])
                idsofs, idscheck = struct.unpack_from("<LH" if fileversion==1 else "<LL", hdrdata, 56)
                offsets.append(idsofs)
                checksums.append(idscheck)

                # note: filever 4  has '0x5c', zeros, md5, more zeroes
            else:
                values = struct.unpack_from("<QQLLHQQQQ5LQL", hdrdata, 6)
                offsets = [values[_] for _ in (0,1,5,6,7,13)]
                checksums = [values[_] for _ in (8,9,10,11,12,14)]

        # offsets now has offsets to the various idb parts
        #  id0, id1, nam, seg, til, id2 ( = sparse file )
        self.offsets = offsets
        self.checksums = checksums
        self.fileversion = fileversion

    def getsectioninfo(self, i):
        if not 0<=i<len(self.offsets):
            return 0,0,0

        if self.offsets[i]==0:
            return 0,0,0

        self.fh.seek(self.offsets[i])
        if self.fileversion<5:
            comp, size = struct.unpack("<BL", self.fh.read(5))
            ofs = self.offsets[i]+5
        else:
            comp, size = struct.unpack("<BQ", self.fh.read(9))
            ofs = self.offsets[i]+9
        return comp, ofs, size

    def getpart(self, ix):
        if self.offsets[ix]==0:
            return

        comp, ofs, size = self.getsectioninfo(ix)

        fh = FileSection(self.fh, ofs, ofs+size)
        if comp==2:
            fh = CompressedStream(fh)
        elif comp==0:
            pass
        else:
            raise Exception("unsupported section encoding: %02x" % comp)
        return fh

    def getsection(self, cls):
        return cls(self, self.getpart(cls.INDEX))


# v1..v5  id1 and nam files start with 'Va4'
# v6      id1 and nam files start with 'VA*'
# til files start with 'IDATIL'
# id2 files start with 'IDAS\x1d\xa5\x55\x55'

###### moving these outside of BTree
###### so i can use them as baseclasses in the variou page implementations
def binary_search(a, k):
    # c++: a.upperbound(k)--
    first, last = 0, len(a)
    while first<last:
        mid = (first+last)>>1
        if k < a[mid].key:
            last = mid
        else:
            first = mid+1
    return first-1

class TestBinarySearch(unittest.TestCase):
    class Object:
        def __init__(self, num):
            self.key = num
        def __repr__(self):
            return "o(%d)" % self.num

    def test_bs(self):
        obj = self.Object
        lst = [obj(_) for _ in (2,3,5,6)]
        self.assertEqual(binary_search(lst, 1), -1)
        self.assertEqual(binary_search(lst, 2), 0)
        self.assertEqual(binary_search(lst, 3), 1)
        self.assertEqual(binary_search(lst, 4), 1)
        self.assertEqual(binary_search(lst, 5), 2)
        self.assertEqual(binary_search(lst, 6), 3)
        self.assertEqual(binary_search(lst, 7), 3)

    def test_emptylist(self):
        obj = self.Object
        lst = []
        self.assertEqual(binary_search(lst, 1), -1)
    def test_oneelem(self):
        obj = self.Object
        lst = [obj(1)]
        self.assertEqual(binary_search(lst, 0), -1)
        self.assertEqual(binary_search(lst, 1), 0)
        self.assertEqual(binary_search(lst, 2), 0)
    def test_twoelem(self):
        obj = self.Object
        lst = [obj(1), obj(3)]
        self.assertEqual(binary_search(lst, 0), -1)
        self.assertEqual(binary_search(lst, 1), 0)
        self.assertEqual(binary_search(lst, 2), 0)
        self.assertEqual(binary_search(lst, 3), 1)
        self.assertEqual(binary_search(lst, 4), 1)

    def test_listsize(self):
        obj = self.Object
        for l in range(3,32):
            lst = [obj(_+1) for _ in range(l)]
            lst = lst[:1] + lst[2:]
            self.assertEqual(binary_search(lst, 0), -1)
            self.assertEqual(binary_search(lst, 1), 0)
            self.assertEqual(binary_search(lst, 2), 0)
            self.assertEqual(binary_search(lst, 3), 1)
            self.assertEqual(binary_search(lst, l-1), l-3)
            self.assertEqual(binary_search(lst, l), l-2)
            self.assertEqual(binary_search(lst, l+1), l-2)
            self.assertEqual(binary_search(lst, l+2), l-2)


class BaseIndexEntry(object):
    def __init__(self, data):
        ofs = self.recofs
        keylen, = struct.unpack_from("<H", data, ofs) ; ofs += 2
        self.key = data[ofs:ofs+keylen]  ; ofs += keylen
        vallen, = struct.unpack_from("<H", data, ofs) ; ofs += 2
        self.val = data[ofs:ofs+vallen]  ; ofs += vallen
    def __repr__(self):
        return "%06x: %s = %s" % (self.page, binascii.b2a_hex(self.key), binascii.b2a_hex(self.val))


class BaseLeafEntry(BaseIndexEntry):
    def __init__(self, key, data):
        """ leaf entries get the previous key a an argument. """
        super(BaseLeafEntry, self).__init__(data)
        self.key = key[:self.indent] + self.key
    def __repr__(self):
        return "    %02x: %s = %s" % (self.unknown, binascii.b2a_hex(self.key), binascii.b2a_hex(self.val))


class BTree(object):
    class BasePage(object):
        def __init__(self, data, entsize, entfmt):
            self.preceeding, self.count = struct.unpack_from(entfmt, data)
            if self.preceeding:
                entrytype = self.IndexEntry
            else:
                entrytype = self.LeafEntry

            self.index = []
            key = b""
            for i in range(self.count):
                ent = entrytype(key, data, entsize*(1+i))
                self.index.append(ent)
                key = ent.key
            self.unknown, self.freeptr = struct.unpack_from(entfmt, data, entsize*(1+self.count))
        def find(self, key):
            """
            Searches pages for key, returns relation to key:

            recurse -> found a next level index page to search for key.
                       also returns the next level page nr
            gt -> found a value with a key greater than the one searched for.
            lt -> found a value with a key less than the one searched for.
            eq -> found a value with a key equal to the one searched for.
                       gt, lt and eq return the index for the key found.
            """

            # for an index entry: the key is 'less' than anything in the page pointed to.

            i = binary_search(self.index, key)
            if i<0:
                if self.isindex():
                    return ('recurse', -1)
                #print("leaf page, searching for %s, found: %s at %d, cmp=%d  -> gt" % (binascii.b2a_hex(key), binascii.b2a_hex(self.index[0].key), i, cmp(self.index[0].key, key)))
                return ('gt', 0)
            if self.index[i].key==key:
                return ('eq', i)
            if self.isindex():
                return ('recurse', i)
            #print("leaf page, searching for %s, found: %s at %d, cmp=%d  -> lt" % (binascii.b2a_hex(key), binascii.b2a_hex(self.index[i].key), i, cmp(self.index[i].key, key)))
            return ('lt', i)

        def getpage(self, ix):
            return self.preceeding if ix<0 else self.index[ix].page
        def getkey(self, ix):
            return self.index[ix].key
        def getval(self, ix):
            return self.index[ix].val
        def isleaf(self):
            return self.preceeding == 0
        def isindex(self):
            return self.preceeding != 0
        def __repr__(self):
            return ("leaf" if self.isleaf() else ("index<%d>" % self.preceeding))+repr(self.index)



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
                self.indent, self.unknown, self.recofs = struct.unpack_from("<HHH", data, ofs)
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
                super(self.__class__, self).__init__(key, data)

        def __init__(self, data):
            super(self.__class__, self).__init__(data, 6, "<LH")

    class Cursor:
        """
        A Cursor object represents a position in the b-tree.

        It has methods for moving to the next or previous item.
        And methods for retrieving the key and value of the current position
        """
        def __init__(self, db, stack):
            self.db = db
            self.stack = stack
        def next(self):
            page, ix = self.stack.pop()
            if page.isleaf():
                # from leaf move towards root
                ix += 1
                while self.stack and ix==len(page.index):
                    page, ix = self.stack.pop()
                    ix += 1
                if ix<len(page.index):
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
            page, ix = self.stack.pop()
            ix -= 1
            if page.isleaf():
                # move towards root, until non 'prec' item found
                while self.stack and ix<0:
                    page, ix = self.stack.pop()
                if ix>=0:
                    self.stack.append((page, ix))
            else:
                # move towards leaf
                self.stack.append((page, ix))
                while page.isindex():
                    page = self.db.readpage(page.getpage(ix))
                    ix = len(page.index)-1
                    self.stack.append((page, ix))

        def eof(self):
            return len(self.stack)==0
        def getkey(self):
            page, ix = self.stack[-1]
            return page.getkey(ix)
        def getval(self):
            page, ix = self.stack[-1]
            return page.getval(ix)
        def __repr__(self):
            return "cursor:"+repr(self.stack)



    def __init__(self, fh):
        self.fh = fh

        self.fh.seek(0)
        data = self.fh.read(64)

        if data[13:].startswith(b"B-tree v 1.5 (C) Pol 1990"):
            self.parseheader15(data)
            self.page = self.Page15
            self.version = 15
            print("btree v1.5")
        elif data[19:].startswith(b"B-tree v 1.6 (C) Pol 1990"):
            self.parseheader16(data)
            self.page = self.Page16
            self.version = 16
            print("btree v1.6")
        elif data[19:].startswith(b"B-tree v2"):
            self.parseheader16(data)
            self.page = self.Page20
            self.version = 20
            print("btree v2.0")
        else:
            print("unknown btree: %s" % binascii.b2a_hex(data))
            raise Exception("unknown b-tree")

    def parseheader15(self, data):
        self.firstfree, self.pagesize, self.firstindex, self.reccount, self.pagecount = struct.unpack_from("<HHHLH", data, 0)
    def parseheader16(self, data):
        self.firstfree, self.pagesize, self.firstindex, self.reccount, self.pagecount = struct.unpack_from("<LHLLL", data, 0)

    def readpage(self, nr):
        self.fh.seek(nr*self.pagesize)
        return self.page(self.fh.read(self.pagesize))

    def find(self, rel, key):
        """
        Searches for a record with the specified relation to the key

        'eq'  -> record equal to the key, None when not found
        'le'  -> last record with key <= to key
        'ge'  -> first record with key >= to key
        'lt'  -> last record with key < to key
        'gt'  -> first record with key > to key
        """

        #print("searching for rec %s to %s" % (rel, binascii.b2a_hex(key)))
        page = self.readpage(self.firstindex)
        stack = []
        while True:
            act, ix = page.find(key)
            stack.append((page, ix))
            if act!='recurse':
                break
            page = self.readpage(page.getpage(ix))

        cursor = BTree.Cursor(self, stack)
        print("found %s" % act)

        if act==rel:
            pass
        elif rel=='eq' and act!='eq':
            return None
        elif rel in ('ge', 'le') and act == 'eq':
            pass
        elif rel in ('gt', 'ge') and act=='lt':
            cursor.next()
        elif rel == 'gt' and act=='eq':
            cursor.next()
        elif rel in ('lt', 'le') and act=='gt':
            cursor.prev()
        elif rel == 'lt' and act=='eq':
            cursor.prev()

        return cursor

    def dump(self):
        print("pagesize=%08x, reccount=%08x, pagecount=%08x" % (self.pagesize, self.reccount, self.pagecount))
        self.dumpfree()
        self.dumptree(self.firstindex)

    def dumpfree(self):
        fmt = "L" if self.version>15 else "H"
        hdrsize = 8 if self.version>15 else 4
        pn = self.firstfree
        if pn==0:
            print("no free pages")
            return
        while pn:
            self.fh.seek(pn*self.pagesize)
            data = self.fh.read(self.pagesize)
            if len(data)==0:
                print("could not read FREE data at page %06x" % pn)
                break
            count, nextfree = struct.unpack_from("<"+(fmt*2), data)
            freepages = list(struct.unpack_from("<"+(fmt*count), data, hdrsize))
            freepages.insert(0, pn)
            for pn in freepages:
                self.fh.seek(pn*self.pagesize)
                data = self.fh.read(self.pagesize)
                print("%06x: free: %s" % (pn, binascii.b2a_hex(data[:64])))
            pn = nextfree

    def dumpindented(self, pn, indent=0):
        """ dump all nodes of the current b-indented """
        page = self.readpage(pn)
        print("  "*indent, page)
        if page.isindex():
            print("  "*indent, end="")
            self.dumpindented(page.preceeding, indent+1)
            for p in range(len(page.index)):
                print("  "*indent, end="")
                self.dumpindented(page.getpage(p), indent+1)

    def dumptree(self, pn):
        page = self.readpage(pn)
        print("%06x: preceeding = %06x, reccount = %04x" % (pn, page.preceeding, page.count))
        for ent in page.index:
            print("    %s" % ent)
        if page.preceeding:
            self.dumptree(page.preceeding)
            for ent in page.index:
                self.dumptree(ent.page)




class ID0File(object):
    INDEX = 0
    def __init__(self, idb, fh):
        self.btree = BTree(fh)

"""
"$ MAX LINK"
"$ MAX NODE"
"$ NET DESC"

"-%08x"
".%08x%c%s"
"N%s"
"N$ %s"
"n$ %s"
"""




class ID1File(object):
    INDEX = 1
    def __init__(self, idb, fh):
        if idb.magic == b'IDA2':
            wordsize, fmt = 8, "Q"
        else:
            wordsize, fmt = 4, "L"

        self.fh = fh
        fh.seek(0)
        hdrdata = fh.read(32)
        magic = hdrdata[:4]
        if magic == b'Va4\x00':
            nsegments, npages = struct.unpack_from("<HH", hdrdata, 4)
            #  filesize / npages == 0x2000  for all cases
        elif magic == b'VA*\x00':
            always3, nsegments, always2k, npages = struct.unpack_from("<LLLL", hdrdata, 4)
        else:
            raise Exception("unknown id1 magic: %s" % binascii.b2a_hex(magic))

        self.seglist = []
        # Va0  - ida v3.0.5
        # Va3  - ida v3.6
        if magic == b'Va4\x00':
            fh.seek(8)
            segdata = fh.read(nsegments * 3 * wordsize)
            for o in range(nsegments):
                startea, endea, id1ofs = struct.unpack_from("<"+fmt+fmt+fmt, segdata, i * 3 * wordsize)
                self.seglist.append((startea, endea, id1ofs))

        elif magic == b'VA*\x00':
            fh.seek(20)
            segdata = fh.read(nsegments * 2 * wordsize)
            id1ofs = 0x2000
            for o in range(nsegments):
                startea, endea = struct.unpack_from("<"+fmt+fmt, segdata, i * 2 * wordsize)
                self.seglist.append((startea, endea, id1ofs))
                id1ofs += 4*(endea-startea)

    def find_segment(self, ea):
        for seg in self.seglist:
            if seg.startea <= ea < self.endea:
                return seg

    def getFlags(self, ea):
        seg = self.find_segment(ea)
        self.fh.seek(seg.ofs+4*(ea-seg.startea))
        return struct.unpack("<L", self.fh.read(4))
    def FirstSeg(self):
        return self.seglist[0][0]
    def NextSeg(self, ea):
        for i, seg in enumerate(self.seglist):
            if seg.startea <= ea < self.endea:
                if i+1<len(self.seglist):
                    return self.seglist[i+1][0]
                else:
                    return
    def SegStart(self, ea):
        seg = self.find_segment(ea)
        return seg[0]
    def SegEnd(self, ea):
        seg = self.find_segment(ea)
        return seg[1]

class NAMFile(object):
    INDEX = 2
    def __init__(self, idb, fh):
        pass
        if idb.magic == b'IDA2':
            wordsize, fmt = 8, "Q"
        else:
            wordsize, fmt = 4, "L"

        self.fh = fh
        fh.seek(0)
        hdrdata = fh.read(64)
        magic = hdrdata[:4]
        # Va0  - ida v3.0.5
        # Va1  - ida v3.6
        if magic == b'Va4\x00':
            always1, npages, always0, nnames, pagesize = struct.unpack_from("<HH"+fmt+fmt+"L", hdrdata, 4)
        elif magic == b'VA*\x00':
            always3, always1, always2k, npages, always0, nnames = struct.unpack_from("<LLLL"+fmt+"L", hdrdata, 4)
        else:
            raise Exception("unknown id1 magic: %s" % binascii.b2a_hex(magic))
        if idb.magic == b'IDA2':
            nnames /= 2
        self.wordsize = wordsize
        self.wordfmt = fmt




class SEGFile(object):
    INDEX = 3
    def __init__(self, idb, fh):
        pass

class TILFile(object):
    INDEX = 4
    def __init__(self, idb, fh):
        pass

class ID2File(object):
    INDEX = 5

    # contains 'packed' data ( like struct information )
    def __init__(self, idb, fh):
        pass

