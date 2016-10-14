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

def processfile(args, fh):
    try:
        magic = fh.read(4)
        fh.seek(-4,1)
        if magic.startswith(b"IDA"):
            idb = idbutils.IDBFile(fh)
            print("magic=%s, filever=%d" % (idb.magic, idb.fileversion))
            for i in range(6):
                comp, ofs, size = idb.getsectioninfo(i)
                if ofs:
                    part = idb.getpart(i)
                    print("%2d: %02x, %08x %8x:  %s" % (i, comp, ofs, size, binascii.b2a_hex(part.read(256))))
            id0 = idb.getsection(idbutils.ID0File)

            print("=========== dump")
            id0.btree.dump()

            print("=========== enumerate using next")

            cursor = id0.btree.find('ge', b'')
            i = 0
            while not cursor.eof() and i < 100:
                print("   %s" % (binascii.b2a_hex(cursor.getkey())))
                cursor.next()
                i += 1

            print("=========== relations")
            for k in ('4e526f6f74204e6f6465','2eff000001','4e757466385f73625f6d61','4e757466385f73625f6d6170','4e7a6f6e655f6e616d6573','4e7a6f6e655f6e616d657373','2e4124b244784124b49f','2e4124b244784124b4a0','2eff000001530000051a','2eff000001530000051a00','2eff00000153000004b900','2eff000001530000056a00'):
                key = binascii.a2b_hex(k)
                for rel in ('lt', 'le', 'eq', 'ge', 'gt'):
                    cursor = id0.btree.find(rel, key)
                    if cursor:
                        if cursor.eof():
                            print("%s:%-40s -> EOF" % (rel, k))
                        else:
                            foundkey = cursor.getkey()
                            print("%s:%-40s -> %s" % (rel, k, binascii.b2a_hex(foundkey)))
                    else:
                        print("%s:%-40s -> NOT FOUND" % (rel, k))
#                   if act == 'lt':
#                       print("check = %s" % (foundkey < key), end=" ")
#                       cursor.next()
#                       if cursor.eof():
#                           print("next = EOF")
#                       else:
#                           print("next = %s" % (cursor.getkey() > key))

#                   if act == 'gt':
#                       print("check = %s" % (foundkey > key), end=" ")
#                       cursor.prev()
#                       if cursor.eof():
#                           print("prev = EOF")
#                       else:
#                           print("prev = %s" % (cursor.getkey() < key))

        elif magic.startswith(b"Va"):
            print("todo - nam/id1/seg file")
        else:
            id0 = idbutils.ID0File(None, fh)
            id0.btree.dump()

            print("root=",id0.btree.find('eq', b"NRoot Node"))
            print("root=",id0.btree.find('eq', b".\xff\x00\x00\x01"))
    except Exception as e:
        print("ERROR %s" % e)
    

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


def main():
    import argparse
    parser = argparse.ArgumentParser(description='idbtool - print info from hex-rays IDA .idb files')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('FILES', type=str, nargs='*', help='Files')
    args = parser.parse_args()

    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):

            print("\n==> " + fn + " <==\n")

            try:
                with open(fn, "rb") as fh:
                    processfile(args, fh)
            except Exception as e:
                print("ERROR: %s" % e)
                raise
    else:
        processfile(args, sys.stdin.buffer)

if __name__ == '__main__':
    main()
