"""
`idaunpack` is a tool to aid in decoding packed data structures from an
IDA idb or i64 database.
"""
from __future__ import print_function, division
import struct
import re
import sys
from binascii import a2b_hex, b2a_hex
from idblib import IdaUnpacker

def dump_packed(data, wordsize, pattern):
    p = IdaUnpacker(wordsize, data)
    if pattern:
        for c in pattern:
            if p.eof():
                print("EOF")
                break
            if c == 'H':
                val = p.next16()
                fmt = "%04x"
            elif c == 'L':
                val = p.next32()
                fmt = "%08x"
            elif c == 'Q':
                val = p.next64()
                fmt = "%016x"
            elif c == 'W':
                val = p.nextword()
                if wordsize==4:
                    fmt = "[%08x]"
                else:
                    fmt = "[%016x]"
            else:
                raise Exception("unknown pattern: %s" % c)
            print(fmt % val, end=" ")

    while not p.eof():
        val = p.next32()
        print("%08x" % val, end=" ")

    print()

def unhex(hextxt):
    return a2b_hex(re.sub(r'\W+', '', hextxt, flags=re.DOTALL))

def main():
    import argparse
    parser = argparse.ArgumentParser(description='idaunpack')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--debug', action='store_true', help='abort on exceptions.')
    parser.add_argument('--pattern', '-p', type=str, help='unpack pattern: sequence of H, L, Q, W')
    parser.add_argument('-4', '-3', '-32', const=4, dest='wordsize', action='store_const', help='use 32 bit words')
    parser.add_argument('-8', '-6', '-64', const=8, dest='wordsize', action='store_const', help='use 64 bit words')
    parser.add_argument('--wordsize', '-w', type=int, help='specify wordsize')
    parser.add_argument('hexconsts', nargs='*', type=str)

    args = parser.parse_args()
    if args.wordsize is None:
        args.wordsize = 4

    for x in args.hexconsts:
       dump_packed(unhex(x), args.wordsize, args.pattern)

if __name__ == '__main__':
    main()
