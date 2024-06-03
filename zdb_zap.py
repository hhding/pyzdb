#!/usr/bin/env python3

import struct
import os
from collections import namedtuple
from zdb_utils import *

class ZapRegistry:
    type_to_class = dict()

    @classmethod
    def register(cls, handle_class):
        cls.type_to_class[handle_class.my_type] = handle_class

    @classmethod
    def get_inst(cls, buf):
        blk_type = struct.unpack_from("Q", buf)[0]
        return cls.type_to_class[blk_type](buf)

class ZapCommon:
    def __init_subclass__(cls, **kwargs):
        ZapRegistry.register(cls)

    def __init__(self, buf):
        self.buf = buf

    def iter_ent(self, obj, verbose=0):
        return []

class MicroZap(ZapCommon):
    my_type = (1<< 63) + 3
    mzap_ent_len = 64
    mzap_name_len = 64 - 8 - 4 - 2
    # 3Q5Q, 64 bytes;
    def decode_ent(self, buf, offset):
        mze_value, mze_cd, mze_name = struct.unpack_from(f"QIxx{self.mzap_name_len}s", buf, offset)
        return mze_value, mze_cd, mze_name
    
    def iter_ent(self, obj, verbose=0):
        debug_print0("microzap:")
        buf_len = len(self.buf)
        offset = 64
        while offset < buf_len:
            value, cd, name = self.decode_ent(self.buf, offset)
            if name[0] != 0:
                yield value, cd, name.decode()
            offset += self.mzap_ent_len
        return

Zle = namedtuple("ZapLeafEntry", "le_type le_value_intlen le_next le_name_chunk le_name_minints le_value_chunk le_value_numints le_cd le_hash")
Zla = namedtuple("ZapLeafArray", "la_type la_array la_next")
LHdr = namedtuple("LHdr", "lh_block_type lh_pad1 lh_prefix lh_magic lh_nfree lh_nentries lh_prefix_len lh_freelist lh_flags")

class LeafZap(ZapCommon):
    my_type = (1<< 63) + 0
    bs = 24
    hdr_len = 48
    def __init__(self, buf):
        super().__init__(buf)
        self.hdr = LHdr(*struct.unpack_from("3QIHHHHB", buf))
        max_entries = len(buf) // 32
        entries = []
        for i in range(max_entries):
            off = self.hdr_len + 2*i
            idx = struct.unpack_from("H", buf, off)[0]
            if idx == 0xffff:
                continue
            entries.append(idx)
        self.entries = entries
        self.ent_start = max_entries * 2 + self.hdr_len

    def get_off(self, idx):
        return idx * self.bs + self.ent_start

    def unpack(self, fmt, idx):
        return struct.unpack_from(fmt, self.buf, self.get_off(idx))

    def get_zle(self, idx):
        zle = Zle(*self.unpack("2B5HIQ", idx))
        assert zle.le_type == 252 and zle.le_next == 0xffff
        return zle

    def get_zla(self, idx):
        zla = Zla(*self.unpack("B21sH", idx))
        assert zla.la_type == 251
        if zla.la_next == 0xffff:
            return zla.la_array
        return zla.la_array + self.get_zla(zla.la_next)

    def iter_ent(self, obj, verbose=0):
        pack_size = {1: "B", 2: "H", 4: "I", 8: "Q"}
        for idx in self.entries:
            zle = self.get_zle(idx)
            raw_name, raw_value = self.get_zla(zle.le_name_chunk), self.get_zla(zle.le_value_chunk)
            name = raw_name[:zle.le_name_minints].decode()
            pack_fmt = f">{zle.le_value_numints}{pack_size[zle.le_value_intlen]}"
            value_list = struct.unpack_from(pack_fmt, raw_value)
            if zle.le_value_numints == 1:
                value = value_list[0]
            else:
                value = value_list
            yield name, value


class FatZap(ZapCommon):
    my_type = (1<< 63) + 1
    magic = 0x2f52ab2ab
    names = "zap_block_type zap_magic zt_blk zt_numblks zt_shift zt_nextblk zt_blk_copied zap_freeblk zap_num_leafs zap_num_entries zap_salt zap_normflags zap_flags"
    ZapHdr = namedtuple("ZapHdr", names)

    def __init__(self, buf):
        super().__init__(buf)
        self.hdr = self.ZapHdr(*struct.unpack_from("13Q", buf))
        assert self.hdr.zt_numblks == 0, "Only embed ptr table is supported"

    def iter_ent(self, obj, verbose=0):
        debug_print0("fatzap:")
        debug_print2(self.hdr, verbose=verbose)
        buf_len = len(self.buf)
        half_len = buf_len // 2
        blkid_list = []
        for i in range(0, half_len, 8):
            off = half_len + i
            blkid = struct.unpack_from("Q", self.buf, off)[0]
            if blkid not in blkid_list:
                blkid_list.append(blkid)
                blkdata = obj.read_blk(blkid)
                leaf = LeafZap(blkdata.buf)
                for name, value in leaf.iter_ent(obj, verbose=verbose):
                    yield value, None, name
        