"""
Tool for querying information from Hexrays .idb and .i64 files
without launching IDA.

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""

# todo:
#  '$ segs'
#      S <segaddr> = packed(startea, size, ....)
#  '$ srareas'
#      a <addr>    = packed(startea, size, flag, flag)  -- includes functions
#      b <addr>    = packed(startea, size, flag, flag)  -- segment
#      c <addr>    = packed(startea, size, flag, flag)  -- same as 'b'
#       
from __future__ import division, print_function, absolute_import, unicode_literals
import sys
import os
if sys.version_info[0] == 2:
    import scandir
    os.scandir = scandir.scandir
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

if sys.version_info[0] == 2:
    stdout = sys.stdout
else:
    stdout = sys.stdout.buffer

import struct
import binascii
import argparse
import itertools
from collections import defaultdict

import re

from datetime import datetime

import idblib
from idblib import hexdump


def timestring(t):
    if t == 0:
        return "....-..-.. ..:..:.."
    return datetime.strftime(datetime.fromtimestamp(t), "%Y-%m-%d %H:%M:%S")


def strz(b, o):
    return b[o:b.find(b'\x00', o)].decode('utf-8', 'ignore')

def nonefmt(fmt, num):
    if num is None:
        return "-"
    return fmt % num

######### license encoding ################


def decryptuser(data):
    """
    The '$ original user' node is encrypted with hexray's private key.
    Hence we can easily decrypt it, but not change it to something else.
    We can however copy the entry from another database, or just replace it with garbage.

    The node contains 128 bytes encrypted license, followed by 32 bytes zero.

    Note: i found several ida55 databases online where this does not work.
    possible these were created using a cracked version of IDA.
    """
    data = int(binascii.b2a_hex(data[127::-1]), 16)
    user = pow(data, 0x13, 0x93AF7A8E3A6EB93D1B4D1FB7EC29299D2BC8F3CE5F84BFE88E47DDBDD5550C3CE3D2B16A2E2FBD0FBD919E8038BB05752EC92DD1498CB283AA087A93184F1DD9DD5D5DF7857322DFCD70890F814B58448071BBABB0FC8A7868B62EB29CC2664C8FE61DFBC5DB0EE8BF6ECF0B65250514576C4384582211896E5478F95C42FDED)
    user = binascii.a2b_hex("%0256x" % user)
    return user[1:]


def licensestring(lic):
    """ decode a license blob """
    if not lic:
        return
    if len(lic) != 127:
        print("unknown license format: %s" % hexdump(lic))
        return
    if struct.unpack_from("<L", lic, 106)[0]:
        print("unknown license format: %s" % hexdump(lic))
        return

    # note: first 2 bytes probably a checksum

    licver, = struct.unpack_from("<H", lic, 2)
    if licver == 0:

        # todo: new 'Evaluation version'  has licver == 0 as well, but is new format anyway

        # up to ida v5.2
        time, = struct.unpack_from("<L", lic, 4)
        # then 8 zero bytes
        licflags, = struct.unpack_from("<L", lic, 16)
        licensee = strz(lic, 20)
        return "%s [%08x]  %s" % (timestring(time), licflags, licensee)
    else:
        # since ida v5.3
        # licflags from 8 .. 16
        time1, = struct.unpack_from("<L", lic, 16)
        time2, = struct.unpack_from("<L", lic, 16 + 8)
        licid = "%02X-%02X%02X-%02X%02X-%02X" % struct.unpack_from("6B", lic, 28)
        licensee = strz(lic, 34)
        return "v%04d %s .. %s  %s  %s" % (licver, timestring(time1), timestring(time2), licid, licensee)


def dumpuser(id0):
    """ dump the original, and current database user """
    orignode = id0.nodeByName('$ original user')
    if orignode:
        user0 = id0.bytes(orignode, 'S', 0)
        if user0.find(b'\x00\x00\x00\x00') >= 128:
            user0 = decryptuser(user0)
        else:
            user0 = user0[:127]
        # user0 has 128 bytes rsa encrypted license, followed by 32 bytes zero
        print("orig: %s" % licensestring(user0))
    curnode = id0.nodeByName('$ user1')
    if curnode:
        user1 = id0.bytes(curnode, 'S', 0)
        print("user: %s" % licensestring(user1))


######### idb summary #########


filetypelist = [
    "MS DOS EXE File",
    "MS DOS COM File",
    "Binary File",
    "MS DOS Driver",
    "New Executable (NE)",
    "Intel Hex Object File",
    "MOS Technology Hex Object File",
    "Linear Executable (LX)",
    "Linear Executable (LE)",
    "Netware Loadable Module (NLM)",
    "Common Object File Format (COFF)",
    "Portable Executable (PE)",
    "Object Module Format",
    "R-records",
    "ZIP file (this file is never loaded to IDA database)",
    "Library of OMF Modules",
    "ar library",
    "file is loaded using LOADER DLL",
    "Executable and Linkable Format (ELF)",
    "Watcom DOS32 Extender (W32RUN)",
    "Linux a.out (AOUT)",
    "PalmPilot program file",
    "MS DOS EXE File",
    "MS DOS COM File",
    "AIX ar library",
    "Mac OS X Mach-O file",
]


def dumpinfo(id0):
    """ print various infos on the idb file """
    def ftstring(ft):
        if 0 < ft < len(filetypelist):
            return "%02x:%s" % (ft, filetypelist[ft])
        return "%02x:unknown" % ft

    def decodebitmask(fl, bitnames):
        l = []
        knownbits = 0
        for bit, name in enumerate(bitnames):
            if fl & (1 << bit) and name is not None:
                l.append(name)
                knownbits |= 1 << bit
        if fl & ~knownbits:
            l.append("unknown_%x" % (fl & ~knownbits))
        return ",".join(l)

    def osstring(fl):
        return decodebitmask(fl, ['msdos', 'win', 'os2', 'netw', 'unix', 'other'])

    def appstring(fl):
        return decodebitmask(fl, ['console', 'graphics', 'exe', 'dll', 'driver', '1thread', 'mthread', '16bit', '32bit', '64bit'])

    ldr = id0.nodeByName("$ loader name")
    if ldr:
        print("loader: %s %s" % (id0.string(ldr, 'S', 0), id0.string(ldr, 'S', 1)))

    if not id0.root:
        print("database has no RootNode")
        return

    if id0.idbparams:
        params = idblib.IDBParams(id0, id0.idbparams)
        print("cpu: %s, version=%d, filetype=%s, ostype=%s, apptype=%s, core:%x, size:%x" % (params.cpu, params.version, ftstring(params.filetype), osstring(params.ostype), appstring(params.apptype), params.corestart, params.coresize))

    print("idaver=%s: %s" % (nonefmt("%04d", id0.idaver), id0.idaverstr))

    srcmd5 = id0.originmd5
    print("nopens=%s, ctime=%s, crc=%s, md5=%s" % (nonefmt("%d", id0.nropens), nonefmt("%08x", id0.creationtime), nonefmt("%08x", id0.somecrc), hexdump(srcmd5) if srcmd5 else "-"))

    dumpuser(id0)


def dumpnames(args, id0, nam):
    for ea in nam.allnames():
        print("%08x: %s" % (ea, id0.name(ea)))


def dumpscript(id0, node):
    """ dump all stored scripts """
    s = idblib.Script(id0, node)

    print("======= %s %s =======" % (s.language, s.name))
    print(s.body)


def dumpstructmember(m):
    """
    Dump info for a struct member.
    """
    print("     %02x %02x %08x %02x: %-40s" % (m.skip, m.size, m.flags, m.props, m.name), end="")
    if m.enumid:
        print(" enum %08x" % m.enumid, end="")
    if m.structid:
        print(" struct %08x" % m.structid, end="")
    if m.ptrinfo:
        # packed
        # note: 64bit nrs are stored low32, high32
        #  flags1, target, base, delta, flags2

        # flags1:
        #   0=off8  1=off16 2=off32 3=low8  4=low16 5=high8 6=high16 9=off64
        #   0x10 = targetaddr, 0x20 = baseaddr, 0x40 = delta, 0x80 = base is plainnum
        # flags2:
        #   1=image is off, 0x10 = subtract, 0x20 = signed operand
        print(" ptr %s" % m.ptrinfo, end="")
    if m.typeinfo:
        print(" type %s" % m.typeinfo, end="")
    print()


def dumpstruct(id0, node):
    """
    dump all info for the struct defined by `node`
    """
    s = idblib.Struct(id0, node)


    print("struct %s, 0x%x" % (s.name, s.flags))
    for m in s:
        dumpstructmember(m)

def dumpbitmember(m):
    print("        %08x %s" % (m.value or 0, m.name))
def dumpmask(m):
    print("    mask %08x %s" % (m.mask, m.name))
    for m in m:
        dumpbitmember(m)
def dumpbitfield(id0, node):
    b = idblib.Bitfield(id0, node)
    print("bitfield %s, %s, %s, %s" % (b.name, nonefmt("0x%x", b.count), nonefmt("0x%x", b.representation), nonefmt("0x%x", b.flags)))
    for m in b:
        dumpmask(m)

def dumpenummember(m):
    """
    Print information on a single enum member
    """
    print("    %08x %s" % (m.value or 0, m.name))

def dumpenum(id0, node):
    """
    Dump all info for the enum defined by `node`
    """
    e = idblib.Enum(id0, node)
    if e.flags and e.flags&1:
        dumpbitfield(id0, node)
        return
    print("enum %s, %s, %s, %s" % (e.name, nonefmt("0x%x", e.count), nonefmt("0x%x", e.representation), nonefmt("0x%x", e.flags)))

    for m in e:
        dumpenummember(m)


def dumpimport(id0, node):
    startkey = id0.makekey(node, 'A')
    endkey = id0.makekey(node, 'B')
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        ea = id0.int(cur)
        print("%08x: %s" % (ea, id0.name(ea)))
        cur.next()


def enumlist(id0, listname, callback):
    """
    Lists are all stored in a similar way.

    (listnode, 'N')           = listname
    (listnode, 'A', -1)       = list size      <-- not for '$ scriptsnippets'
    (listnode, 'A', seqnr)    = itemnode+1

    (listnode, 'Y', itemnode) = seqnr          <-- only with '$ enums'

    (listnode, 'Y', 0)        = list size      <-- only '$ scriptsnippets'
    (listnode, 'Y', 1)        = ?              <-- only '$ scriptsnippets'

    (listnode, 'S', seqnr)    = dllname        <-- only '$ imports'

    """
    listnode = id0.nodeByName(listname)
    if not listnode:
        return

    startkey = id0.makekey(listnode, 'A')
    endkey = id0.makekey(listnode, 'A', 0xFFFFFFFF)
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        item = id0.int(cur)
        callback(id0, item - 1)
        cur.next()


def printent(args, id0, c):
    if args.verbose:
        print("%s = %s" % (id0.prettykey(c.getkey()), id0.prettyval(c.getval())))
    else:
        print("%s = %s" % (hexdump(c.getkey()), hexdump(c.getval())))


def createkey(args, id0, base, tag, ix):
    """

    parse base node specification:

    '?<name>' -> explicit N<name> key
    '#<number>' -> relative to nodebase
    '.<number>' -> absolute nodeid

    '<name>'  -> lookup by name.

    """
    if base[:1] == '?':
        return id0.namekey(base[1:])

    if re.match(r'^#(?:0[xX][0-9a-fA-F]+|\d+)$', base):
        nodeid = int(base[1:], 0) + id0.nodebase
    elif re.match(r'^\.(?:0[xX][0-9a-fA-F]+|\d+)$', base):
        nodeid = int(base[1:], 0)
    else:
        nodeid = id0.nodeByName(base)
        if nodeid and args.verbose > 1:
            print("found node %x for %s" % (nodeid, base))
    if nodeid is None:
        print("Could not find '%s'" % base)
        return

    s = [nodeid]
    if tag is not None:
        s.append(tag)
        if ix is not None:
            try:
                ix = int(ix, 0)
            except:
                pass
            s.append(ix)

    return id0.makekey(*s)


def enumeratecursor(args, c, onerec, callback):
    """
    Enumerate cursor in direction specified by `--dec` or `--inc`,
    taking into account the optional limit set by `--limit`

    Output according to verbosity level set by `--verbose`.
    """
    limit = args.limit
    while c and not c.eof() and (limit is None or limit > 0):
        callback(c)
        if args.dec:
            c.prev()
        else:
            c.next()
        if limit is not None:
            limit -= 1
        elif onerec:
            break


def id0query(args, id0, query):
    """
    queries start with an optional operator: <,<=,>,>=,==

    followed by either a name or address or nodeid

    Addresses are specified as a sequence of hexadecimal charaters.
    Nodeid's may be specified either as the full node id, starting with ff00,
    or starting with a '_'
    Names are anything which can be found under the name tree in the database.

    after the name/addr/node there is optionally a slash, followed by a node tag,
    and another slash, followed by a index or hash string.

    """

    xlatop = {'=': 'eq', '==': 'eq', '>': 'gt', '<': 'lt', '>=': 'ge', '<=': 'le'}

    SEP = ";"
    m = re.match(r'^([=<>]=?)?(.+?)(?:' + SEP + '(\w+)(?:' + SEP + '(.+))?)?$', query)
    op = m.group(1) or "=="
    base = m.group(2)
    tag = m.group(3)
    ix = m.group(4)

    op = xlatop[op]

    c = id0.btree.find(op, createkey(args, id0, base, tag, ix))

    enumeratecursor(args, c, op=='eq', lambda c:printent(args, id0, c))


def getsegs(id0):
    """
    Returns a list of all segments.
    """
    seglist = []
    node = id0.nodeByName('$ segs')
    if not node:
        return
    startkey = id0.makekey(node, 'S')
    endkey = id0.makekey(node, 'T')
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        s = idblib.Segment(id0, cur.getval())
        seglist.append(s)
        cur.next()

    return seglist


def listsegments(id0):
    """
    Print a summary of all segments found in the IDB.
    """
    ssnode = id0.nodeByName('$ segstrings')
    segstrings = id0.blob(ssnode, 'S')
    p = idblib.IdaUnpacker(id0.wordsize, segstrings)
    unk = p.next32()
    nextid = p.next32()
    slist = []
    while not p.eof():
        slen = p.next32()
        if slen is None:
            break
        name = p.bytes(slen)
        if name is None:
            break
        slist.append(name.decode('utf-8', 'ignore'))

    segs = getsegs(id0)
    for s in segs:
        print("%08x - %08x  %s" % (s.startea, s.startea+s.size, slist[s.name_id-1]))

def classifynodes(args, id0):
    """
    Attempt to classify all nodes in the IDA database.

    Note: this does not work for very old dbs
    """
    nodetype = {}
    tagstats = defaultdict(lambda : defaultdict(int))

    segs = getsegs(id0)

    print("node: %x .. %x" % (id0.nodebase, id0.maxnode))

    def addstat(nodetype, k):
        if len(k)<3:
            print("??? strange, expected longer key - %s" % k)
            return
        tag = k[2].decode('utf-8')
        if len(k)==3:
            tagstats[nodetype][(tag, )] += 1
        elif len(k)==4:
            value = k[3]
            if type(value)==int:
                if isaddress(value):
                    tagstats[nodetype][(tag, 'addr')] += 1
                elif isnode(value):
                    tagstats[nodetype][(tag, 'node')] += 1
                else:
                    if value >= id0.maxnode:
                        value -= pow(0x100, id0.wordsize)
                    tagstats[nodetype][(tag, value)] += 1
            else:
                tagstats[nodetype][(tag, 'string')] += 1
        else:
            print("??? strange, expected shorter key - %s" % k)
            return

    def isaddress(addr):
        for s in segs:
            if s.startea <= addr < s.startea+s.size:
                return True

    def isnode(addr):
        return id0.nodebase <= addr <= id0.maxnode

    def processbitfieldvalue(v):
        nodetype[v._nodeid] = 'bitfieldvalue'

    def processbitfieldmask(m):
        nodetype[m._nodeid] = 'bitfieldmask'

        for m in m:
            processbitfieldvalue(m)

    def processbitfield(id0, node):
        nodetype[node] = 'bitfield'

        b = idblib.Bitfield(id0, node)
        for m in b:
            processbitfieldmask(m)


    def processenummember(m):
        nodetype[m._nodeid] = 'enummember'

    def processenums(id0, node):
        nodetype[node] = 'enum'

        e = idblib.Enum(id0, node)
        if e.flags&1:
            processbitfield(id0, node)
            return

        for m in e:
            processenummember(m)

    def processstructmember(m, typename):
        nodetype[m._nodeid] = typename

    def processstructs(id0, node, typename):
        nodetype[node] = typename
        s = idblib.Struct(id0, node)

        for m in s:
            processstructmember(m, typename+"member")

    def processscripts(id0, node):
        nodetype[node] = 'script'

    def processaddr(id0, cur):
        k = id0.decodekey(cur.getkey())
        if len(k)==4 and k[2:4] == (b'A', 2):
            nodetype[id0.int(cur)-1] = 'hexrays'

        addstat('addr', k)

    def processfunc(id0, funcspec):
        p = idblib.IdaUnpacker(id0.wordsize, funcspec)

        funcstart = p.nextword()
        funcsize = p.nextword()
        flags = p.next16()
        if flags is None:
            return
        if flags&0x8000:   # is tail
            return

        node = p.nextword()

        if node<0xFFFFFF and node!=0:
            processstructs(id0, node + id0.nodebase, "frame")

    def processimport(id0, node):
        print("imp %08x" % node)
        startkey = id0.makekey(node+1, 'A')
        endkey = id0.makekey(node+1, 'B')
        cur = id0.btree.find('ge', startkey)
        while cur.getkey() < endkey:
            dllnode = id0.int(cur)
            nodetype[dllnode] = 'import'
            cur.next()


    # mark enums, structs, scripts.
    enumlist(id0, '$ enums', processenums)
    enumlist(id0, '$ structs', lambda id0, node : processstructs(id0, node, "struct"))
    enumlist(id0, '$ scriptsnippets', processscripts)
    enumlist(id0, '$ imports', processimport)

    # enum functions, scan for stackframes
    funcsnode = id0.nodeByName('$ funcs')
    startkey = id0.makekey(funcsnode, 'S')
    endkey = id0.makekey(funcsnode, 'T')
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        processfunc(id0, cur.getval())
        cur.next()

    clinode = id0.nodeByName('$ cli')
    if clinode:
        for letter in "ABCDEFGHIJKMcio":
            startkey = id0.makekey(clinode, letter)
            endkey = id0.makekey(clinode, chr(ord(letter)+1))
            cur = id0.btree.find('ge', startkey)
            while cur.getkey() < endkey:
                nodetype[id0.int(cur)] = 'cli.'+letter
                cur.next()


    # enum addresses, scan for hex-rays nodes
    startkey = b'.'
    endkey = id0.makekey(id0.nodebase)
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        processaddr(id0, cur)
        cur.next()

    # addresses above node list
    startkey = id0.makekey(id0.maxnode+1)
    endkey = b'/'
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        processaddr(id0, cur)
        cur.next()

    # scan for unmarked nodes
    #  $ fr[0-9a-f]+\.\w+
    #  $ fr[0-9a-f]+\. [rs]
    #  $ F[0-9A-F]+\.\w+
    #  $ Stack of \w+
    #  Stack[0000007C]
    #  xrefs to \w+

    startkey = id0.makekey(id0.nodebase)
    endkey = id0.makekey(id0.maxnode+1)
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        k = id0.decodekey(cur.getkey())
        node = k[1]
        if node not in nodetype:
            nodetype[node] = "unknown"
        if nodetype[node] == "unknown" and k[2] == b'N':
            name = cur.getval().rstrip(b'\x00')
            if re.match(br'\$ fr[0-9a-f]+\.\w+$', name):
                name = 'fr-type-functionframe'
            elif re.match(br'\$ fr[0-9a-f]+\. [rs]$', name):
                name = 'fr-type-functionframe'
            elif re.match(br'\$ F[0-9A-F]+\.\w+$', name):
                name = 'F-type-functionframe'
            elif name.startswith(b'Stack of '):
                name = 'stack-type-functionframe'
            elif name.startswith(b'Stack['):
                name = 'old-stack-type-functionframe'
            elif name.startswith(b'xrefs to '):
                name = 'old-xrefs'
            else:
                name = name.decode('utf-8', 'ignore')
            nodetype[node] = name

        cur.next()

    # output node classification
    if args.verbose:
        for k, v in sorted(nodetype.items(), key=lambda kv:kv[0]):
            print("%08x: %s" % (k, v))

    # summarize tags per nodetype
    startkey = id0.makekey(id0.nodebase)
    endkey = id0.makekey(id0.maxnode+1)
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        k = id0.decodekey(cur.getkey())
        node = k[1]
        nt = nodetype[node]

        addstat(nt, k)

        cur.next()

    # output tag statistics
    for nt, ntstats in sorted(tagstats.items(), key=lambda kv:kv[0]):
        print("====== %s =====" % nt)
        for k, v in ntstats.items():
            if len(k)==1:
                print("%5d - %s" % (v, k[0]))
            elif len(k)==2 and type(k[1])==type(1):
                print("%5d - %s %8x" % (v, k[0], k[1]))
            elif type(k[1])==type(1):
                print("%5d - %s %8x %s" % (v, k[0], k[1], k[2:]))
            else:
                print("%5d - %s %s %s" % (v, k[0], k[1], k[2:]))


def processid0(args, id0):
    if args.info:
        dumpinfo(id0)

    if args.pagedump:
        id0.btree.pagedump()

    if args.query:
        for query in args.query:
            id0query(args, id0, query)
    elif args.id0:
        id0.btree.dump()
    elif args.inc:
        c = id0.btree.find('ge', b'')
        enumeratecursor(args, c, False, lambda c:printent(args, id0, c))
    elif args.dec:
        c = id0.btree.find('le', b'\x80')
        enumeratecursor(args, c, False, lambda c:printent(args, id0, c))


def hexascdumprange(id1, a, b):
    line = asc = ""
    for ea in range(a, b):
        if len(line)==0:
            line = "%08x:" % ea
        byte = id1.getFlags(ea)&0xFF
        line += " %02x" % byte
        asc += chr(byte) if 32<byte<127 else '.'

        if len(line) == 9 + 3*16:
            line += " " + asc
            print(line)
            line = asc = ""
    if len(line):
        while len(line) < 9 + 3*16:
            line += "   "
        line += " " + asc
        print(line)


def saverange(id1, a, b, fh):
    buf = bytes()
    for ea in range(a, b):
        byte = id1.getFlags(ea)&0xFF
        buf += struct.pack("B", byte)

        if len(buf) == 65536:
            fh.write(buf)
            buf = bytes()

    if buf:
        fh.write(buf)


def processid1(args, id1):
    if args.id1:
        id1.dump()
    elif args.dump or args.dumpraw:
        m = re.match(r'^(\d\w*)-(\d\w*)?$', args.dump or args.dumpraw)
        if not m:
            raise Exception("--dump requires a byte range")
        a = int(m.group(1), 0)
        b = int(m.group(2), 0)

        if args.dumpraw:
            saverange(id1, a, b, stdout)
        else:
            hexascdumprange(id1, a, b)


def processid2(args, id2):
    pass


def processnam(args, nam):
    pass


def processtil(args, til):
    pass


def processseg(args, seg):
    pass


def processidb(args, idb):
    if args.verbose > 1:
        print("magic=%s, filever=%d" % (idb.magic, idb.fileversion))
        for i in range(6):
            comp, ofs, size, checksum = idb.getsectioninfo(i)
            if ofs:
                part = idb.getpart(i)
                print("%2d: %02x, %08x %8x [%08x]:  %s" % (i, comp, ofs, size, checksum, hexdump(part.read(256))))

    nam = idb.getsection(idblib.NAMFile)
    id0 = idb.getsection(idblib.ID0File)
    id1 = idb.getsection(idblib.ID1File)
    processid0(args, id0)
    processid1(args, id1)
    processid2(args, idb.getsection(idblib.ID2File))
    processnam(args, nam)
    processtil(args, idb.getsection(idblib.TILFile))
    processseg(args, idb.getsection(idblib.SEGFile))

    if args.names:
        dumpnames(args, id0, nam)
    if args.classify:
        classifynodes(args, id0)

    if args.scripts:
        enumlist(id0, '$ scriptsnippets', dumpscript)
    if args.structs:
        enumlist(id0, '$ structs', dumpstruct)
    if args.enums:
        enumlist(id0, '$ enums', dumpenum)
    if args.imports:
        enumlist(id0, '$ imports', dumpimport)
    if args.segs:
        listsegments(id0)


def processfile(args, filetypehint, fh):
    class DummyIDB:
        def __init__(idb, args):
            if args.i64:
                idb.magic = 'IDA2'
            elif args.i32:
                idb.magic = 'IDA1'
            else:
                idb.magic = None

    try:
        magic = fh.read(64)
        fh.seek(-64, 1)
        if magic.startswith(b"Va") or magic.startswith(b"VA"):
            idb = DummyIDB(args)
            if filetypehint == 'id1':
                processid1(args, idblib.ID1File(idb, fh))
            elif filetypehint == 'nam':
                processnam(args, idblib.NAMFile(idb, fh))
            elif filetypehint == 'seg':
                processseg(args, idblib.SEGFile(idb, fh))
            else:
                print("unknown VA type file: %s" % hexdump(magic))
        elif magic.startswith(b"IDAS"):
            processid2(args, idblib.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDATIL"):
            processtil(args, idblib.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDA"):
            processidb(args, idblib.IDBFile(fh))
        elif magic.find(b'B-tree v') > 0:
            processid0(args, idblib.ID0File(DummyIDB(args), fh))

    except Exception as e:
        print("ERROR %s" % e)
        if args.debug:
            raise


def recover_database(args, basepath, dbfiles):
    processidb(args, idblib.RecoverIDBFile(args, basepath, dbfiles))


def DirEnumerator(args, path):
    """
    Enumerate all files / links in a directory,
    optionally recursing into subdirectories,
    or ignoring links.
    """
    for d in os.scandir(path):
        try:
            if d.name == '.' or d.name == '..':
                pass
            elif d.is_symlink() and args.skiplinks:
                pass
            elif d.is_file():
                yield d.path
            elif d.is_dir() and args.recurse:
                for f in DirEnumerator(args, d.path):
                    yield f
        except Exception as e:
            print("EXCEPTION %s accessing %s/%s" % (e, path, d.name))


def EnumeratePaths(args, paths):
    """
    Enumerate all paths, files from the commandline
    optionally recursing into subdirectories.
    """
    for fn in paths:
        try:
            # 3 - for ftp://, 4 for http://, 5 for https://
            if fn.find("://") in (3, 4, 5):
                yield fn
            if os.path.islink(fn) and args.skiplinks:
                pass
            elif os.path.isdir(fn) and args.recurse:
                for f in DirEnumerator(args, fn):
                    yield f
            elif os.path.isfile(fn):
                yield fn
        except Exception as e:
            print("EXCEPTION %s accessing %s" % (e, fn))


def filetype_from_name(fn):
    i = max(fn.rfind('.'), fn.rfind('/'))
    return fn[i + 1:].lower()


def isv2name(name):
    return name.lower() in ('$segregs.ida', '$segs.ida', '0.ida', '1.ida', 'ida.idl', 'names.ida')


def isv3ext(ext):
    return ext.lower() in ('.id0', '.id1', '.id2', '.nam', '.til')


def xlatv2name(name):
    oldnames = {
        '$segregs.ida': 'reg',
        '$segs.ida': 'seg',
        '0.ida': 'id0',
        '1.ida': 'id1',
        'ida.idl': 'idl',
        'names.ida': 'nam',
    }

    return oldnames.get(name.lower())


def main():
    parser = argparse.ArgumentParser(description='idbtool - print info from hex-rays IDA .idb and .i64 files',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""
idbtool can process complete .idb and .i64 files, but also naked .id0, .id1, .nam, .til files.
All versions since IDA v2.0 are supported.

Queries start with an optional operator: <,<=,>,>=,==.
Followed by either a name or address or nodeid.
Addresses are specified as a sequence of hexadecimal charaters.
Nodeid's may be specified either as the full node id, starting with ff00,
or starting with a '_'.
Names are anything which can be found under the name tree in the database.

After the name/addr/node there is optionally a slash, followed by a node tag,
and another slash, followed by a index or hash string.

Multiple queries can be specified, terminated by another option, or `--`.
Add `-v` for pretty printed keys and values.

Examples:

  idbtool -v --query "$ user1;S;0" -- x.idb
  idbtool -v --limit 4 --query ">#0xa" -- x.idb
  idbtool -v --limit 5 --query ">Root Node;S;0" -- x.idb
  idbtool -v --limit 10 --query ">Root Node;S" -- x.idb
  idbtool -v --query ".0xff000001;N" -- x.idb
""")
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('--filetype', '-t', type=str, help='specify filetype when loading `naked` id1,nam or seg files')
    parser.add_argument('--i64', '-i64', action='store_true', help='specify that `naked` file is from a 64 bit database')
    parser.add_argument('--i32', '-i32', action='store_true', help='specify that `naked` file is from a 32 bit database')

    parser.add_argument('--names', '-n', action='store_true', help='print names')
    parser.add_argument('--scripts', '-s', action='store_true', help='print scripts')
    parser.add_argument('--structs', '-u', action='store_true', help='print structs')
    # parser.add_argument('--comments', '-c', action='store_true', help='print comments')
    parser.add_argument('--enums', '-e', action='store_true', help='print enums and bitfields')
    parser.add_argument('--imports', action='store_true', help='print imports')
    parser.add_argument('--segs', action='store_true', help='print segments')
    parser.add_argument('--info', '-i', action='store_true', help='database info')
    parser.add_argument('--inc', action='store_true', help='dump id0 records by cursor increment')
    parser.add_argument('--dec', action='store_true', help='dump id0 records by cursor decrement')
    parser.add_argument('--id0', "-id0", action='store_true', help='dump id0 records, by walking the page tree')
    parser.add_argument('--id1', "-id1", action='store_true', help='dump id1 records')
    parser.add_argument('--dump', type=str, help='hexdump id1 bytes', metavar='FROM-UNTIL')
    parser.add_argument('--dumpraw', type=str, help='output id1 bytes', metavar='FROM-UNTIL')
    parser.add_argument('--pagedump', "-d", action='store_true', help='dump all btree pages, including any that might have become inaccessible due to datacorruption.')
    parser.add_argument('--classify', action='store_true', help='Classify nodes found in the database.')

    parser.add_argument('--query', "-q", type=str, nargs='*', help='search the id0 file for a specific record.')
    parser.add_argument('--limit', '-m', type=int, help='Max nr of records to return for a query.')

    parser.add_argument('--recover', action='store_true', help='recover idb from unpacked files, of v2 database')
    parser.add_argument('--debug', action='store_true')

    parser.add_argument('FILES', type=str, nargs='*', help='Files')

    args = parser.parse_args()

    if args.FILES:
        dbs = dict()

        for fn in EnumeratePaths(args, args.FILES):
            basepath, filename = os.path.split(fn)
            if isv2name(filename):
                d = dbs.setdefault(basepath, dict())
                d[xlatv2name(filename)] = fn
                print("%s -> %s : %s" % (xlatv2name(filename), basepath, filename))
            else:
                basepath, ext = os.path.splitext(fn)
                if isv3ext(ext):
                    d = dbs.setdefault(basepath, dict())
                    d[ext.lower()] = fn

            if not args.dumpraw:
                print("\n==> " + fn + " <==\n")

            try:
                filetype = args.filetype or filetype_from_name(fn)
                with open(fn, "rb") as fh:
                    processfile(args, filetype, fh)
            except Exception as e:
                print("ERROR: %s" % e)
                if args.debug:
                    raise

        if args.recover:
            for basepath, dbfiles in dbs.items():
                if len(dbfiles) > 1:
                    try:
                        print("\n==> " + basepath + " <==\n")
                        recover_database(args, basepath, dbfiles)
                    except Exception as e:
                        print("ERROR: %s" % e)
    else:
        print("==> STDIN <==")
        processfile(args, args.filetype, sys.stdin.buffer)


if __name__ == '__main__':
    main()
