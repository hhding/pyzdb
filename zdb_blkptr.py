import struct
from collections import namedtuple
from zdb_vdev import vdev_read
from zdb_utils import *

class DVA:
    def __init__(self, idx, data):
        self.idx = idx
        self.dva_word = data
        self.vdev = bits_get(self.dva_word[0], 32, 24)
        self.asize = bits_get(self.dva_word[0], 0, 24) * 512
        self.offset = bits_get(self.dva_word[1], 0, 63) * 512

    def desc(self, lsize=None, psize=None):
        if self.asize == 0:
            return "DVA[unallocated]"
        if lsize and psize:
            return f"DVA[{self.idx}]=<{self.vdev}:{self.offset:4x}:{lsize:x}/{psize:x} asize={self.asize:x}>"
        return f"DVA[{self.idx}]=<{self.vdev}:{self.offset:x}:{self.asize:x}>"

    def __repr__(self):
        return self.desc()


class BlkPtr:
    bs = 128
    BlockData = namedtuple("BlockData", ["id", "vdev", "offset", "buf"])
    def __init__(self, data):
        self.data = data
        fields = struct.unpack("@7Q16x7Q", data[:self.bs])
        self.dva = []
        for idx in range(3):
            dva = DVA(idx, [fields[2*idx], fields[2*idx+1]])
            if dva.asize > 0:
                self.dva.append(dva)

        prop_int = fields[6]
        self.embd = bits_get(prop_int, 39, 1) 
        if self.embd:
            names = "pbirth_txg lbith_txg fill b d x lvl type etype e comp psize lsize"
            prop_offset_list = [(63, 1), (62, 1), (61, 1), (56, 5), (48, 8), (40, 8), (39, 1), (32, 7), (25, 7), (0, 25)]
            size_shift = 0
        else:
            names = "pbirth_txg lbith_txg fill b d x lvl type cksum e comp psize lsize"
            prop_offset_list = [(63, 1), (62, 1), (61, 1), (56, 5), (48, 8), (40, 8), (39, 1), (32, 7), (16, 16), (0, 16)]
            size_shift = 9

        prop_list = list(fields[7:10]) + [bits_get(prop_int, o, l) for o, l in prop_offset_list]
        self.prop = namedtuple("BlkPtrProp", names)(*prop_list)
        self.fields = fields
        self.lvl = self.prop.lvl

        self.lsize = (self.prop.lsize + 1) << size_shift
        self.psize = (self.prop.psize + 1) << size_shift
        self.iblk_cnt = self.lsize // self.bs
        self.iblk_cache = dict()

    def get_embddata(self):
        buf = self.data
        return buf[:6*8] + buf[7*8:0xa*8] + buf[0xb*8:128]

    def get_blkdata(self, blkid, nlevels=1):
        if self.prop.x != 0:
            raise NotImplementedError("BlkPTR encrypted data")
        if self.embd:
            raw_buf = self.get_embddata()
            buf = lz4_decompress(raw_buf, self.lsize)
            return self.BlockData(blkid, -1, -1, buf)
        
        if self.prop.fill == 0:
            debug_print1(f"BlkPTR: skip empty block: L{self.lvl} {blkid}", DEBUG_ZFS_BLK)
            return self.BlockData(blkid, -1, -1, None)

        dva = self.dva[0]
        debug_print2(f"{'  '*(nlevels - self.lvl -1)}BlkPtr: L{self.lvl} {dva}", DEBUG_ZFS_BLK)
        buf = vdev_read(dva.vdev, dva.offset, self.psize, self.lsize)
        if self.lvl == 0:
            debug_print1(f"ZFS_BLK: L{self.lvl} {dva}", DEBUG_ZFS_BLK)
            return self.BlockData(blkid, dva.vdev, dva.offset, buf)
        # recursive to next level data block
        iblk_offset = (blkid // (self.iblk_cnt**(self.lvl-1))) * self.bs
        blkptr = BlkPtr(buf[iblk_offset:iblk_offset+self.bs])
        return blkptr.get_blkdata(blkid, nlevels)

    def desc(self):
        assert self.prop.type != 0, "BLKPTR Type is 0"

        if self.embd == 1:
            return f"[L{self.lvl} {self.prop.type} EMBD {self.lsize:x}L/{self.psize}P]"

        dva = self.dva[0].desc(self.lsize, self.psize)
        return f"[L{self.lvl} {self.prop.type} {dva}]"

    def get_checksum(self):
        return ":".join([f"{int(x):x}" for x in self.fields[-4:]])

    def show(self):
        print(self.desc())

    def __repr__(self):
        return self.desc()
