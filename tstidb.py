from __future__ import division, print_function, absolute_import, unicode_literals
import sys
#reload(sys)
#sys.setdefaultencoding('utf8')
import os
if sys.version_info[0] == 2:
    import scandir
    os.scandir = scandir.scandir

import struct
import binascii
import idbutils
import argparse
import itertools
import traceback

from datetime import datetime

######### ida value packing

def idaunpack(buf):
    buf = bytearray(buf)
    def nextval(o):
        val = buf[o] ; o += 1
        if val==0xff:
            # 32 bit value
            # todo: figure out if this works the same for .i64 files
            val = struct.unpack_from("<L", buf, o)
            o += 4
            return val, o
        if val<0x80:
            return val, o
        val <<= 8
        val |= buf[o] ; o += 1
        if val<0xc000:
            return val&0x3fff, o
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
######### license encoding

def decryptuser(data):
    data = int(binascii.b2a_hex(data[127::-1]),16)
    user = pow(data, 0x13, 0x93AF7A8E3A6EB93D1B4D1FB7EC29299D2BC8F3CE5F84BFE88E47DDBDD5550C3CE3D2B16A2E2FBD0FBD919E8038BB05752EC92DD1498CB283AA087A93184F1DD9DD5D5DF7857322DFCD70890F814B58448071BBABB0FC8A7868B62EB29CC2664C8FE61DFBC5DB0EE8BF6ECF0B65250514576C4384582211896E5478F95C42FDED)
    user = binascii.a2b_hex("%0256x" % user)
    return user[1:]

def licensestring(lic):

    if len(lic)!=127:
        print("unknown license format: %s" % binascii.b2a_hex(lic))
        return
    if struct.unpack_from("<L", lic, -20)[0]:
        print("unknown license format: %s" % binascii.b2a_hex(lic))
        return

    # note: first 2 bytes probably a checksum

    licver, = struct.unpack_from("<H", lic, 2)
    if licver==0:
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
    orignode = id0.nodeByName('$ original user')
    if orignode:
        user0 = id0.bytes(orignode, 'S', 0) 
        # user0 has 128 bytes rsa encrypted license, followed by 32 bytes zero
        print("orig: %s" % licensestring(decryptuser(user0)))
    curnode = id0.nodeByName('$ user1')
    if curnode:
        user1 = id0.bytes(curnode, 'S', 0)
        print("user: %s" % licensestring(user1))

######### idb summary
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
        magic, version, cpu, idpflags, demnames, filetype, coresize, corestart, ostype, apptype  = struct.unpack_from("<3sH8sBBH"+(id0.fmt*2)+"HH", params, 0)
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

    print("nopens=%s, ctime=%s, crc=%s, md5=%s" % (nonefmt("%d",nopens), nonefmt("%08x",ctime), nonefmt("%08x",crc), binascii.b2a_hex(srcmd5) if srcmd5 else "-"))

    dumpuser(id0)

def dumpnames(args, id0, nam):
    for ea in nam.allnames():
        print("%08x: %s" % (ea, id0.string(ea, 'N')))

def dumpscript(id0, node):
    name = id0.string(node, 'S', 0)
    lang = id0.string(node, 'S', 1)
    body = id0.blob(node, 'X').rstrip(b'\x00').decode('utf-8')

    print("======= %s %s =======" % (lang, name))
    print(body)

def dumpstructmember(id0, spec):
    print("%08x %02x %02x %08x %02x: " % tuple(spec), end="")

    nodeid = spec[0] + id0.nodebase
    name = id0.string(nodeid, 'N')
    enumid = id0.int(nodeid, 'A', 11)
    struct = id0.int(nodeid, 'A', 3)
    ptrseg = id0.int(nodeid, 'S', 9)
    eltype = id0.int(nodeid, 'S', 0x3000)

    print(" %-40s" % name, end="")
    if enumid:
        print(" enum %08x" % enumid, end="")
    if struct:
        print(" struct %08x" % struct, end="")
    if ptrseg:
        print(" ptr %08x" % ptrseg, end="")
    if eltype:
        print(" type %08x" % eltype, end="")
    print()

def dumpstruct(id0, node):
    name = id0.string(node, 'N')
    packed = id0.blob(node, 'M')
    spec = idaunpack(packed)
    print("struct %s, 0x%x, 0x%x" % (name, spec[0], spec[-1]))
    if len(spec)-5*spec[1] not in (2,3):
        print("expected struct spec : %d = %d" % (spec[1], (len(spec)-2)//5))
    for i in range(spec[1]):
        dumpstructmember(id0, spec[5*i+2:5*i+7])


def dumpenummember(id0, node):
    name = id0.string(node, 'N')
    value = id0.int(node, 'A', -3)
    # id0.int(node, 'A', -2)  -> points back to enum

    print("    %08x %s" % (value, name))

def dumpenum(id0, node):
    name = id0.string(node, 'N')
    size = id0.int(node, 'A', -1)
    display = id0.int(node, 'A', -3)
    flags = id0.int(node, 'A', -5)
    # flags>>3 -> width
    # flags&1 -> bitfield
    print("enum %s, 0x%x, 0x%x, 0x%x" % (name, size, display, flags))
    startkey = id0.makekey(node, 'E')
    endkey = id0.nextkey(startkey)
    cur = id0.btree.find('ge', startkey)
    while cur.getkey() < endkey:
        dumpenummember(id0, id0.int(cur)-1)
        cur.next()
    

def dumplist(id0, listname, dumper):
    sroot = id0.nodeByName(listname)
    if not sroot:
        return

    # note: (node,'A',-1) = list size
    for i in itertools.count():
        snode = id0.int(sroot, 'A', i)
        if not snode:
            break
        dumper(id0, snode-1)


def processid0(args, id0):

    if args.id0:
        id0.btree.dump()
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
    print("magic=%s, filever=%d" % (idb.magic, idb.fileversion))
    for i in range(6):
        comp, ofs, size = idb.getsectioninfo(i)
        if ofs:
            part = idb.getpart(i)
            print("%2d: %02x, %08x %8x:  %s" % (i, comp, ofs, size, binascii.b2a_hex(part.read(256))))
    processid0(args, idb.getsection(idbutils.ID0File))
    processid1(args, idb.getsection(idbutils.ID1File))
    processid2(args, idb.getsection(idbutils.ID2File))
    processnam(args, idb.getsection(idbutils.NAMFile))
    processtil(args, idb.getsection(idbutils.TILFile))
    processseg(args, idb.getsection(idbutils.SEGFile))

    if args.names:
        nam = idb.getsection(idbutils.NAMFile)
        id0 = idb.getsection(idbutils.ID0File)
        dumpnames(id0, nam)

    if args.scripts:
        id0 = idb.getsection(idbutils.ID0File)
        dumplist(id0, '$ scriptsnippets', dumpscript)
    if args.structs:
        id0 = idb.getsection(idbutils.ID0File)
        dumplist(id0, '$ structs', dumpstruct)
    if args.enums:
        id0 = idb.getsection(idbutils.ID0File)
        dumplist(id0, '$ enums', dumpenum)



def processfile(args, filetypehint, fh):
    class DummyIDB:
        def __init__(idb, args):
            if args.i64:
                idb.magic = 'IDA2'
            else:
                idb.magic = 'IDA1'

    try:
        magic = fh.read(64)
        fh.seek(-64,1)
        if magic.startswith(b"Va") or magic.startswith(b"VA"):
            idb = DummyIDB(args)
            if filetypehint=='id1': processid1(args, idbutils.ID1File(idb, fh))
            elif filetypehint=='nam': processnam(args, idbutils.NAMFile(idb, fh))
            elif filetypehint=='seg': processseg(args, idbutils.SEGFile(idb, fh))
            else:
                print("unknown VA type file: %s" % binascii.b2a_hex(magic))
        elif magic.startswith(b"IDAS"):
            processid2(args, idbutils.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDATIL"):
            processtil(args, idbutils.ID2File(DummyIDB(args), fh))
        elif magic.startswith(b"IDA"):
            processidb(args, idbutils.IDBFile(fh))
        elif magic.find(b'B-tree v')>0:
            processid0(args, idbutils.ID0File(DummyIDB(args), fh))

    except Exception as e:
        print("ERROR %s" % e)

def recover_database(args, basepath, dbfiles):
    processidb(args, RecoverIDBFile(args, basepath, dbfiles))

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
    parser = argparse.ArgumentParser(description='idbtool - print info from hex-rays IDA .idb files', 
            epilog="""
idbtool can process complete .idb files, but also naked .id0, .id1, .nam, .til files.
All versions since IDA v2.0 are supported.
""")
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('--filetype', '-t', type=str, help='specify filetype when loading `naked` id1,nam or seg files')
    parser.add_argument('--i64', '-i64', action='store_true', help='specify that `naked` file is from a 64 bit database')

    parser.add_argument('--names', '-n', action='store_true', help='print names')
    parser.add_argument('--scripts', '-s', action='store_true', help='print scripts')
    parser.add_argument('--structs', '-u', action='store_true', help='print structs')
    parser.add_argument('--comments', '-c', action='store_true', help='print comments')
    parser.add_argument('--enums', '-e', action='store_true', help='print enums')
    parser.add_argument('--info', '-i', action='store_true', help='database info')
    parser.add_argument('--id0', "-id0", action='store_true', help='dump id0 records')
    parser.add_argument('--id1', "-id1", action='store_true', help='dump id1 records')

    parser.add_argument('--recover', action='store_true', help='recover idb from seperate .id0 etc files')

    # todo: add option to combine .id0, .id1, .nam etc in one database
    # useful for reading v2.0 databases, and for recovering corrupted databases.

    parser.add_argument('FILES', type=str, nargs='*', help='Files')
    args = parser.parse_args()

    if args.FILES:
        dbs = dict()

        for fn in EnumeratePaths(args, args.FILES):
            basepath, filename = os.path.split(fn)
            if isv2name(filename):
                d = dbs.setdefault(basepath, set())
                d[xlatv2name(filename)] = fn
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
            
            if args.recover:
                for basepath, dbfiles in dbs.items():
                    if len(dbfiles)>1:
                        print("\n==> " + basepath + " <==\n")
                        recover_database(args, basepath, dbfiles)
    else:
        processfile(args, args.filetype, sys.stdin.buffer)

if __name__ == '__main__':
    main()
