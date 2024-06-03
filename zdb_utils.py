from lz4 import block
import math
import os
import struct
import sys

def debug_print0(message, verbose=0, fd=sys.stderr):
    if verbose >= 0:
        print("DBG0:", message, file=fd)

def debug_print1(message, verbose, fd=sys.stderr):
    if verbose >= 1:
        print("DBG1:", message, file=fd)

def debug_print2(message, verbose, fd=sys.stderr):
    if verbose >= 2:
        print("DBG2:", message, file=fd)

def debug_print3(message, verbose, fd=sys.stderr):
    if verbose >= 3:
        print("DBG3:", message, file=fd)

def debug_print4(message, verbose, fd=sys.stderr):
    if verbose >= 4:
        print("DBG4:", message, file=fd)

def roundup(x, y):
    return math.ceil(x/y) * y

def lz4_decompress(block_data, uncompressed_size=0x200000):
    buf_size = struct.unpack(">I", block_data[:4])[0]
    assert buf_size < uncompressed_size
    buf = block.decompress(block_data[4:buf_size+4], uncompressed_size=uncompressed_size)
    assert len(buf) == uncompressed_size, "lz4 decompress error"
    return buf

def bits_get(x, low, length):
    return (x >> low) & ((1 << length) - 1)
