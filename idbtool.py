"""
Tool for querying information from Hexrays .idb and .i64 files
without launching IDA.

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function, absolute_import, unicode_literals
import sys
#reload(sys)
#sys.setdefaultencoding('utf8')
import os
if sys.version_info[0] == 2:
    import scandir
    os.scandir = scandir.scandir
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

import struct
import binascii
import argparse
import itertools

import re

from datetime import datetime

import idblib
from idblib import hexdump

######### ida value packing ######### 


def idaunpack(buf):
    """ special data packing format, used in struct definitions, and .id2 files """
    buf = bytearray(buf)

    def nextval(o):
        val = buf[o] ; o += 1
        if val==0xff: # 32 bit value
            val, = struct.unpack_from("<L", buf, o)
            o += 4
            return val, o
        if val<0x80:  # 8 bit value
            return val, o
        val <<= 8
        val |= buf[o] ; o += 1
        if val<0xc000: # 15 bit value
            return val&0x7fff, o

        # 30 bit value
        val <<= 8
        val |= buf[o] ; o += 1
        val <<= 8
        val |= buf[o] ; o += 1
        return val&0x3fffffff, o

    values = []
    o = 0
    while o < len(buf):
        val, o = nextval(o)
        values.append(val)
    return values


def timestring(t):
    if t==0:
        return "....-..-.. ..:..:.."
    return datetime.strftime(datetime.fromtimestamp(t), "%Y-%m-%d %H:%M:%S")


def strz(b, o):
    return b[o:b.find(b'\x00', o)].decode('utf-8', 'ignore')


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
    data = int(binascii.b2a_hex(data[127::-1]),16)
    user = pow(data, 0x13, 0x93AF7A8E3A6EB93D1B4D1FB7EC29299D2BC8F3CE5F84BFE88E47DDBDD5550C3CE3D2B16A2E2FBD0FBD919E8038BB05752EC92DD1498CB283AA087A93184F1DD9DD5D5DF7857322DFCD70890F814B58448071BBABB0FC8A7868B62EB29CC2664C8FE61DFBC5DB0EE8BF6ECF0B65250514576C4384582211896E5478F95C42FDED)
    user = binascii.a2b_hex("%0256x" % user)
    return user[1:]


def licensestring(lic):
    """ decode a license blob """
    if len(lic)!=127:
        print("unknown license format: %s" % hexdump(lic))
        return
    if struct.unpack_from("<L", lic, 106)[0]:
        print("unknown license format: %s" % hexdump(lic))
        return

    # note: first 2 bytes probably a checksum

    licver, = struct.unpack_from("<H", lic, 2)
    if licver==0:

        # todo: new 'Evaluation version'  has licver==0 as well, but is new format anyway

        # up to ida v5.2
        time, = struct.unpack_from("<L", lic, 4)
        # then 8 zero bytes
        licflags, = struct.unpack_from("<L", lic, 16)
        licensee = strz(lic,20)
        return "%s [%08x]  %s" % (timestring(time), licflags, licensee)
    else:
        # since ida v5.3
        # licflags from 8 .. 16
        time1, = struct.unpack_from("<L", lic, 16)
        time2, = struct.unpack_from("<L", lic, 16+8)
        licid = "%02X-%02X%02X-%02X%02X-%02X" % struct.unpack_from("6B", lic, 28)
        licensee = strz(lic,34)
        return "v%04d %s .. %s  %s  %s" % (licver, timestring(time1), timestring(time2), licid, licensee)


def dumpuser(id0):
    """ dump the original, and current database user """
    orignode = id0.nodeByName('$ original user')
    if orignode:
        user0 = id0.bytes(orignode, 'S', 0)
        if user0.find(b'\x00\x00\x00\x00')>=128:
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


filetypelist= [
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
    def nonefmt(fmt, num):
        if num is None:
            return "-"
        return fmt % num

    def ftstring(ft):
        if 0<ft<len(filetypelist):
            return "%02x:%s" % (ft, filetypelist[ft])
        return "%02x:unknown" % ft

    def osstring(fl):
        l = []
        if fl&1 : l.append('msdos')
        if fl&2 : l.append('win')
        if fl&4 : l.append('os2')
        if fl&8 : l.append('netw')
        if fl&16 : l.append('unix')
        if fl&32 : l.append('other')
        if fl&~63 : l.append("unknown_%x" % (fl&~63))
        return ",".join(l)

    def appstring(fl):
        l = []
        if fl&1 : l.append('console')
        if fl&2 : l.append('graphics')
        if fl&4 : l.append('exe')
        if fl&8 : l.append('dll')
        if fl&16 : l.append('driver')
        if fl&32 : l.append('1thread')
        if fl&64 : l.append('mthread')
        if fl&128 : l.append('16bit')
        if fl&256 : l.append('32bit')
        if fl&512 : l.append('64bit')
        if fl&~0x3ff : l.append("unknown_%x" % (fl&~0x3ff))
        return ",".join(l)

    ldr = id0.nodeByName("$ loader name")
    if ldr:
        print("loader: %s %s" % (id0.string(ldr, 'S', 0), id0.string(ldr, 'S', 1)))

    root = id0.nodeByName("Root Node")

    params = id0.bytes(root, 'S', 0x41b994)
    if params:
        magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype = struct.unpack_from("<3sH8sBBH"+(id0.fmt*2)+"HH", params, 0)
        cpu = strz(cpu, 0)
        print("cpu: %s, version=%d, filetype=%s, ostype=%s, apptype=%s, core:%x, size:%x" % (cpu, version, ftstring(filetype), osstring(ostype), appstring(apptype), corestart, coresize))

    idaver = id0.int(root, 'A', -1)
    # note: versions before 4.7 used a short instead of a long
    # and stored the versions with one minor digit ( 43 ) , instead of two ( 480 )
    idaver2 = id0.string(root, 'S', 1303)
    print("idaver=%s: %s" % (nonefmt("%04d", idaver), idaver2))

    nopens = id0.int(root, 'A', -4)
    ctime = id0.int(root, 'A', -2)
    crc = id0.int(root, 'A', -5)
    srcmd5 = id0.bytes(root, 'S', 1302)

    print("nopens=%s, ctime=%s, crc=%s, md5=%s" % (nonefmt("%d",nopens), nonefmt("%08x",ctime), nonefmt("%08x",crc), hexdump(srcmd5) if srcmd5 else "-"))

    dumpuser(id0)


def dumpnames(args, id0, nam):
    for ea in nam.allnames():
        print("%08x: %s" % (ea, id0.name(ea)))


def dumpscript(id0, node):
    """ dump all stored scripts """
    name = id0.string(node, 'S', 0)
    lang = id0.string(node, 'S', 1)
    body = id0.blob(node, 'X').rstrip(b'\x00').decode('utf-8')

    print("======= %s %s =======" % (lang, name))
    print(body)

def dumpstructmember(id0, spec):
    def i64(a,b): return a + (b<<32)
    if id0.wordsize==8:
        f = i64(spec[0], spec[1]), i64(spec[2], spec[3]), i64(spec[4], spec[5]), spec[6], spec[7]
    else:
        f = spec
    print("     %02x %02x %08x %02x: " % tuple(f[1:]), end="")

    nodeid = f[0] + id0.nodebase
    name = id0.name(nodeid)
    enumid = id0.int(nodeid, 'A', 11)
    struct = id0.int(nodeid, 'A', 3)
    #TODO 'A', 16 - stringtype
    #TODO 'S', 0 - member comment
    #TODO 'S', 1 - repeatable member comment
    ptrseg = hexdump(id0.bytes(nodeid, 'S', 9))
    eltype = hexdump(id0.bytes(nodeid, 'S', 0x3000))

    print("%-40s" % name, end="")
    if enumid:
        print(" enum %08x" % enumid, end="")
    if struct:
        print(" struct %08x" % struct, end="")
    if ptrseg:
        # packed
        # note: 64bit nrs are stored low32, high32
        #  flags1, target, base, delta, flags2 

        # flags1: 
        #   0=off8  1=off16 2=off32 3=low8  4=low16 5=high8 6=high16 9=off64
        #   0x10 = targetaddr, 0x20 = baseaddr, 0x40 = delta, 0x80 = base is plainnum
        # flags2: 
        #   1=image is off, 0x10 = subtract, 0x20 = signed operand
        print(" ptr %s" % ptrseg, end="")
    if eltype:
        print(" type %s" % eltype, end="")
    print()


def dumpstruct(id0, node):
    """ dump all info for the struct defined by `node` """
    name = id0.name(node)
    packed = id0.blob(node, 'M')
    spec = idaunpack(packed)

    entsize = 5 if id0.wordsize==4 else 8

    extra = ", 0x%x" % spec[-1] if len(spec)-entsize*spec[1]==3 else ", -"
    # note: 64bit nrs are stored low32, high32
    print("struct %s, 0x%x%s" % (name, spec[0], extra))
    #  spec[0] = flags
    #    1 = SF_VAR, 2 = SF_UNION, 4 = SF_HASHUNI, 8 = SF_NOLIST, 0x10 = SF_TYPLIB, 0x20 = SF_HIDDEN, 0x40 = SF_FRAME, 0xF80 = SF_ALIGN, 0x1000 = SF_GHOST
    #  spec[1] = # members

    #  spec[-1] = seqnr
    #
    if len(spec)-entsize*spec[1] not in (2,3):
        print("expected struct spec : %d = %d" % (spec[1], (len(spec)-2)//5))
    for i in range(spec[1]):
        dumpstructmember(id0, spec[entsize*i+2:entsize*(i+1)+2])


def dumpenummember(id0, node):
    """ print information on a single enum member """
    name = id0.name(node)
    value = id0.int(node, 'A', -3)
    # id0.int(node, 'A', -2)  -> points back to enum

    if value is None:
        value = 0
    print("    %08x %s" % (value, name))


def dumpenum(id0, node):
    """ dump all info for the enum defined by `node` """
    name = id0.name(node)
    size = id0.int(node, 'A', -1)  or 0    # empty enums do not have size
    display = id0.int(node, 'A', -3)
    flags = id0.int(node, 'A', -5)
    # flags>>3 -> width
    # flags&1 -> bitfield
    print("enum %s, 0x%x, 0x%x, 0x%x" % (name, size, display, flags))
    startkey = id0.makekey(node, 'E')
    endkey = id0.makekey(node, 'F')
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        dumpenummember(id0, id0.int(cur)-1)
        cur.next()

    # todo: handle bitfields (node, 'm', i)  -> list of masks -> list of values


def dumpimport(id0, node):
    startkey = id0.makekey(node, 'A')
    endkey = id0.makekey(node, 'B')
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        ea = id0.int(cur)
        print("%08x: %s" % (ea, id0.name(ea)))
        cur.next()


def dumplist(id0, listname, dumper):
    """
    Lists are all stored in a similar way.
    """
    sroot = id0.nodeByName(listname)
    if not sroot:
        return

    # note: (node,'A',-1) = list size
    for i in itertools.count():
        snode = id0.int(sroot, 'A', i)
        if not snode:
            break
        dumper(id0, snode-1)


# todo:
#   "$ fr[0-9a-f]+"           -- M
#   "$ fr[0-9a-f]+. r"
#   "$ fr[0-9a-f]+. s"
#   "$ fr[0-9a-f]+.<varname>" -- S
#   
#   "$ F[0-9A-F]+"  with the same format
#          ". r", ". s", ".<varname>"

# "$ pv edges", "$ pv2 blob", "$ proximity last node"
# "$ chooser\\".....

def printent(args, id0, c):
    if args.verbose:
        print("%s = %s" % (id0.prettykey(c.getkey()), id0.prettyval(c.getval())))
    else:
        print("%s = %s" % (hexdump(c.getkey()), hexdump(c.getval())))

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

    xlatop = { '=':'eq', '==':'eq', '>':'gt', '<':'lt', '>=':'ge', '<=':'le' }

    m = re.match(r'^([=<>]=?)?(.+?)(?:/(\w+)(?:/(.+))?)?$', query)
    op = m.group(1) or "=="
    base = m.group(2)
    tag = m.group(3)
    ix = m.group(4)

    op = xlatop[op]

    if base[:1] == '_':
        nodeid = int(base[1:], 16) + id0.nodebase
    elif re.match(r'^[0-9a-fA-F]+$', base):
        nodeid = int(base, 16)
    else:
        nodeid = id0.nodeByName(base)
        if args.verbose > 1:
            print("found node %x for %s" % (nodeid, base))
    if nodeid is None:
        print("Could not find '%s'" % base)
        return

    s = [ nodeid ]
    if tag is not None:
        s.append(tag)
        if ix is not None:
            try:
                ix = int(ix, 0)
            except:
                pass
            s.append(ix)

    limit = args.limit

    c = id0.btree.find(op, id0.makekey(*s))
    while c and not c.eof() and (limit is None or limit>0):
        printent(args, id0, c)
        if args.dec:
            c.prev()
        else:
            c.next()
        if limit is not None:
            limit -= 1
        elif op == 'eq':
            break



def processid0(args, id0):

    if args.pagedump:
        id0.btree.pagedump()

    if args.query:
        for query in args.query:
            id0query(args, id0, query)
    elif args.id0:
        id0.btree.dump()
    elif args.inc:
        c = id0.btree.find('ge', b'')
        while not c.eof():
            printent(args, id0, c)
            c.next()
    elif args.dec:
        c = id0.btree.find('le', b'\x80')
        while not c.eof():
            printent(args, id0, c)
            c.prev()

    if args.info:
        dumpinfo(id0)



def processid1(args, id1):
    if args.id1:
        id1.dump()


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
    processid0(args, id0)
    processid1(args, idb.getsection(idblib.ID1File))
    processid2(args, idb.getsection(idblib.ID2File))
    processnam(args, nam)
    processtil(args, idb.getsection(idblib.TILFile))
    processseg(args, idb.getsection(idblib.SEGFile))

    if args.names:
        dumpnames(args, id0, nam)

    if args.scripts:
        dumplist(id0, '$ scriptsnippets', dumpscript)
    if args.structs:
        dumplist(id0, '$ structs', dumpstruct)
    if args.enums:
        dumplist(id0, '$ enums', dumpenum)
    if args.imports:
        dumplist(id0, '$ imports', dumpimport)


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
        fh.seek(-64,1)
        if magic.startswith(b"Va") or magic.startswith(b"VA"):
            idb = DummyIDB(args)
            if filetypehint=='id1': processid1(args, idblib.ID1File(idb, fh))
            elif filetypehint=='nam': processnam(args, idblib.NAMFile(idb, fh))
            elif filetypehint=='seg': processseg(args, idblib.SEGFile(idb, fh))
            else:
                print("unknown VA type file: %s" % hexdump(magic))
        elif magic.startswith(b"IDAS"):
            processid2(args, idblib.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDATIL"):
            processtil(args, idblib.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDA"):
            processidb(args, idblib.IDBFile(fh))
        elif magic.find(b'B-tree v')>0:
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
            if fn.find("://") in (3,4,5):
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
    return fn[i+1:].lower()


def isv2name(name):
    return name.lower() in ('$segregs.ida', '$segs.ida', '0.ida', '1.ida', 'ida.idl', 'names.ida')


def isv3ext(ext):
    return ext.lower() in ('id0', 'id1', 'id2', 'nam', 'til')


def xlatv2name(name):
    name = name.lower()

    if name=='$segregs.ida': return 'reg'
    if name=='$segs.ida': return 'seg'
    if name=='0.ida': return 'id0'
    if name=='1.ida': return 'id1'
    if name=='ida.idl': return 'idl'
    if name=='names.ida': return 'nam'
    return None


def main():
    import argparse
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

  idbtool -v --query "$ user1/S/0" -- x.idb
  idbtool -v --limit 4 --query ">_000a" -- x.idb
  idbtool -v --limit 5 --query ">Root Node/S/0" -- x.idb
  idbtool -v --limit 10 --query ">Root Node/S" -- x.idb
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
    parser.add_argument('--comments', '-c', action='store_true', help='print comments')
    parser.add_argument('--enums', '-e', action='store_true', help='print enums')
    parser.add_argument('--imports', action='store_true', help='print impors')
    parser.add_argument('--info', '-i', action='store_true', help='database info')
    parser.add_argument('--inc',  action='store_true', help='dump id0 records by cursor increment')
    parser.add_argument('--dec',  action='store_true', help='dump id0 records by cursor decrement')
    parser.add_argument('--id0', "-id0", action='store_true', help='dump id0 records, by walking the page tree')
    parser.add_argument('--id1', "-id1", action='store_true', help='dump id1 records')
    parser.add_argument('--pagedump', "-d", action='store_true', help='dump all btree pages, including any that might have become inaccessible due to datacorruption.')

    parser.add_argument('--query', "-q", type=str, nargs='*', help='search the id0 file for a specific record.')
    parser.add_argument('--limit', type=int, help='Max nr of records to return for a query.')

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
                if len(dbfiles)>1:
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
