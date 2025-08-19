from lz4 import block
import math
import os
import struct
import sys
from typing import Union, List

DEBUG_ZFS_BLK       =   ["DBG_BLK", int(os.environ.get("DEBUG_ZFS_BLK", 0))]
DEBUG_ZFS_VDEV      =   ["DBG_VDEV", int(os.environ.get("DEBUG_ZFS_VDEV", 0))]
DEBUG_ZFS_ZAP       =   ["DBG_ZAP", int(os.environ.get("DEBUG_ZFS_ZAP", 0))]
DEBUG_ZFS_OBJECT    =   ["DBG_OBJ", int(os.environ.get("DEBUG_ZFS_OBJECT", 0))]
DEBUG_SHOW_HEADER    =   int(os.environ.get("DEBUG_ZFS_SHOW_HEADER", 0))

def filter_lvl(lvl):
    def decorator(func):
        def new_func(message, debug_info, fd=sys.stderr):
            if type(debug_info) == list:
                header, q_lvl = debug_info
            else:
                q_lvl = int(debug_info)
                header = "DEBUG_ZFS_COMM"
            debug_header = ""
            if DEBUG_SHOW_HEADER > 0:
                debug_header = f"{header}{lvl}: "

            if q_lvl >= lvl:
                return func(f"{debug_header}{message}", fd)
        return new_func
    return decorator

@filter_lvl(0)
def debug_print0(message, fd=sys.stderr):
    print(message, file=fd)

@filter_lvl(1)
def debug_print1(message, fd=sys.stderr):
    print(message, file=fd)

@filter_lvl(2)
def debug_print2(message, fd=sys.stderr):
    print(message, file=fd)

@filter_lvl(3)
def debug_print3(message, fd=sys.stderr):
    print(message, file=fd)

def std_write(buf):
    if sys.stdout.isatty():
        print("Warning: not write binary to stdout, please use pipe or io redirect")
        return
    return os.write(1, buf)

@filter_lvl(4)
def debug_print4(message, fd=sys.stderr):
    print(message, file=fd)

def roundup(x, y):
    return math.ceil(x/y) * y

def lz4_decompress(block_data, uncompressed_size=0x200000):
    buf_size = struct.unpack(">I", block_data[:4])[0]
    assert buf_size < uncompressed_size, f"expect: {buf_size} < {uncompressed_size}"
    buf = block.decompress(block_data[4:buf_size+4], uncompressed_size=uncompressed_size)
    assert len(buf) == uncompressed_size, "lz4 decompress error"
    return buf

def bits_get(x, low, length):
    return (x >> low) & ((1 << length) - 1)

class hexdump:
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def __iter__(self):
        last_bs, last_line = None, None
        for i in range(0, len(self.buf), 16):
            bs = bytearray(self.buf[i : i + 16])
            line = "{:08x}  {:23}  {:23}  |{:16}|".format(
                self.off + i,
                " ".join(("{:02x}".format(x) for x in bs[:8])),
                " ".join(("{:02x}".format(x) for x in bs[8:])),
                "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
            )
            if bs == last_bs:
                line = "*"
            if bs != last_bs or line != last_line:
                yield line
            last_bs, last_line = bs, line
        yield "{:08x}".format(self.off + len(self.buf))

    def __str__(self):
        return "\n".join(self)

    def __repr__(self):
        return "\n".join(self)

def fletcher4(data: Union[bytes, List[int]]) -> str:
    """
    计算 Fletcher4 校验和（128位，16字节）

    参数:
        data: 输入数据（字节串或32位无符号整数列表）

    返回:
        16字节的校验和（字节串，大端序）
    """

    data_len = len(data)

    assert data_len <= (8 << 20), f"large lenght not supported: {data_len}"
    # 初始化累加器
    a = b = c = d = 0

    # 如果输入是字节流，转换为32位整数列表（小端序）
    if isinstance(data, bytes):
        # 填充字节到4的倍数（ZFS通常按块对齐，此处简化处理）
        if len(data) % 4 != 0:
            data += b'\x00' * (4 - len(data) % 4)
        # 解包为uint32列表（小端序）
        uint32_list = list(struct.unpack(f'<{len(data)//4}I', data))
    else:
        uint32_list = data

    # 核心计算：四级累加器
    for word in uint32_list:
        a += word
        b += a
        c += b
        d += c

    func = lambda x: (x & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder='big').hex().lstrip("0")
    return ":".join([func(x) for x in [a, b, c, d]])

