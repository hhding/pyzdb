#!/usr/bin/env python3

import struct
from collections import namedtuple
import argparse
from zdb_blkptr import BlkPtr
from zdb_utils import *
from zdb_zap import *
from datetime import datetime

def print_zip(alist, blist, indent="\t"):
    for a, b in zip(alist, blist):
        print(f"{indent}{a} = {b}")

dmu_ot_info = [
    ["dump_none",	"unallocated"],
    ["dump_zap",	"object directory"],
    ["dump_uint64",	"object array"],
    ["dump_none",	"packed nvlist"],
    ["dump_none",	"packed nvlist size"],
    ["dump_none",	"bpobj"],
    ["dump_bpobj",	"bpobj header"],
    ["dump_none",	"SPA space map header"],
    ["dump_none",	"SPA space map"],
    ["dump_none",	"ZIL intent log"],
    ["dump_dnode",	"DMU dnode"],
    ["dump_dmu_objset",	"DMU objset"],
    ["dump_dsl_dir",	"DSL directory"],
    ["dump_zap",	"DSL directory child map"],
    ["dump_zap",	"DSL dataset snap map"],
    ["dump_zap",	"DSL props"],
    ["dump_dsl_dataset",	"DSL dataset"],
    ["dump_none",	"ZFS znode"],
    ["dump_none",	"ZFS V0 ACL"],
    ["dump_uint8",	"ZFS plain file"],
    ["dump_zpldir",	"ZFS directory"],
    ["dump_zap",	"ZFS master node"],
    ["dump_zap",	"ZFS delete queue"],
    ["dump_none",	"zvol object"],
    ["dump_zap",	"zvol prop"],
    ["dump_none",	"other uint8[]"],
    ["dump_uint64",	"other uint64[]"],
    ["dump_zap",	"other ZAP"],
    ["dump_zap",	"persistent error log"],
    ["dump_none",	"SPA history"],
    ["dump_none",	"SPA history offsets"],
    ["dump_zap",	"Pool properties"],
    ["dump_zap",	"DSL permissions"],
    ["dump_none",	"ZFS ACL"],
    ["dump_none",	"ZFS SYSACL"],
    ["dump_none",	"FUID table"],
    ["dump_none",	"FUID table size"],
    ["dump_zap",	"DSL dataset next clones"],
    ["dump_zap",	"scan work queue"],
    ["dump_zap",	"ZFS user/group/project used" ],
    ["dump_zap",	"ZFS user/group/project quota"],
    ["dump_zap",	"snapshot refcount tags"],
    ["dump_none",	"DDT ZAP algorithm"],
    ["dump_zap",	"DDT statistics"],
    ["dump_znode",	"System attributes"],
    ["dump_zap",	"SA master node"],
    ["dump_sa_attrs",	"SA attr registration"],
    ["dump_sa_layouts",	"SA attr layouts"],
    ["dump_zap",	"scan translations"],
    ["dump_none",	"deduplicated block"],
    ["dump_zap",	"DSL deadlist map"],
    ["dump_none",	"DSL deadlist map hdr"],
    ["dump_zap",	"DSL dir clones"],
    ["dump_none",	"bpobj subobj"],
]

def get_q_id(type_id):
    if type_id > 54:
        remap_id = type_id & 0x1f 
        if remap_id == 4:
            return 27
        elif remap_id == 3:
            return 26
    return type_id

def dmutype2name(type_id):
    return dmu_ot_info[get_q_id(type_id)][1]

def get_dump_func(type_id):
    return dmu_ot_info[get_q_id(type_id)][0]

def get_dn_type(buf):
    return buf[0]

'''same as struct dnode phys'''
class DMUObjectCommon:
    def __init__(self, data):
        self.data = data
        assert len(data) >= 0x200, "buf too small, at least 0x200"
        names = "dn_type indblkshift nlevels nblkptr bonustype checksum compress flags datablkszsec bonuslen extra_slots maxblkid used"
        prop = namedtuple("DnodePhys", names)(*struct.unpack("@8BHHB3xQQ32x", data[:64]))
        self.prop = prop
        self.iblk = 1 << prop.indblkshift
        self.dblk = prop.datablkszsec << 9 # 16KB
        self.bps = self.get_bps(prop.nblkptr)
        self.block_cache = dict()
    
    def iter_my_zap(self):
        buf = self.read_blk(0).buf
        zap = ZapRegistry.get_inst(buf)
        for name, value in zap.iter_ent(self):
            yield name, value

    def get_zap(self, qname):
        for name, value in self.iter_my_zap():
            if name == qname:
                return value

    def dump_raw(self):
        if sys.stdout.isatty():
            print(f"dump_raw: length: {len(self.data):x}, redirect or pipe to output data")
        else:
            return std_write(self.data)

    def get_bonus_data(self):
        start = 64 + 128
        buf = self.data[start:start + self.prop.bonuslen]
        debug_print4("========== bonus data ===================", DEBUG_ZFS_OBJECT)
        debug_print4(hexdump(buf), DEBUG_ZFS_OBJECT)
        return buf

    def get_bps(self, nblkptr):
        bps = []
        for i in range(nblkptr):
            start = 64 + i*128
            bp = BlkPtr(self.data[start:start+128])
            if bp.prop.type != 0:
                bps.append(bp)
        return bps

    def read_blk(self, blkid):
        if blkid in self.block_cache:
            return self.block_cache[blkid]

        if self.prop.nlevels == 0:
            return [-1, -1, None]
        if self.prop.nlevels == 1:
            blk_data = self.bps[blkid].get_blkdata(0)
        else:
            blk_data = self.bps[0].get_blkdata(blkid, nlevels=self.prop.nlevels)
        self.block_cache[blkid] = blk_data

        return self.block_cache[blkid]

    def iter_blks(self):
        for blkid in range(self.prop.maxblkid + 1):
            blockdata = self.read_blk(blkid)
            if blockdata.buf:
                yield blockdata

    def __repr__(self):
        return f"{dmutype2name(self.prop.dn_type)}"

    def desc(self):
        if self.prop.dn_type == 0:
            return "DMU unallocated"

        name = f"{dmutype2name(self.prop.dn_type)}"
        info = f"{name}"
        if self.prop.bonuslen > 0:
            info = f"{name} BONUS<{self.prop.bonuslen}>"

        return info

class DMUObject(DMUObjectCommon):
    def __init__(self, objset, data):
        super().__init__(data)
        self.os = objset

    def dump_none(self, buf=None):
        pass

    def dump_zap(self, buf=None):
        for name, value in self.iter_my_zap():
            print(f"\t{name} = {value}")

    dump_sa_layouts = dump_zap
    dump_dnode = dump_none
    dump_dmu_objset = dump_none

    def dump_zpldir(self, buf=None):
        for name, value in self.iter_my_zap():
            obj_id = value & ((1<<48) - 1)
            file_type = value >> 60
            print(f"\t{name} = {obj_id} (type: {file_type})")

    def dump_znode(self, buf=None):
        self.os.get_znode_attr(buf)

    def iter_sa_attr(self):
        for name, value in self.iter_my_zap():
            attr_num = bits_get(value, 0, 16)
            attr_bswap = bits_get(value, 16, 8)
            attr_length = bits_get(value, 24, 16)
            yield name, value, attr_num, attr_bswap, attr_length

    def dump_sa_attrs(self, buf=None):
        for name, value, attr_num, attr_bswap, attr_length in self.iter_sa_attr():
            print(f"\t{name} = {hex(value)} : [{attr_length}:{attr_bswap}:{attr_num}]")

    def dump_dsl_dir(self, buf=None):
        if buf:
            names = "creation_time head_dataset_obj parent_dir_obj origin_obj child_dir_zapobj used_bytes compressed_bytes uncompressed_bytes quota reserved props_zapobj deleg_zapobj flags used_breakdown[HEAD] used_breakdown[SNAP] used_breakdown[CHILD] used_breakdown[CHILD_RSRV] used_breakdown[REFRSRV] clones".split()
            values = struct.unpack_from("20Q", buf)
            print_zip(names, values)

    def dump_bpobj(self, buf=None):
        names = "num_blkptrs bytes comp uncomp subobjs numsubobjs".split()
        values = list(struct.unpack_from("6Q", buf))
        print_zip(names, values)
        
    def dump_uint8(self, buf=None):
        debug_print1("=========== raw_data start ============", DEBUG_ZFS_OBJECT)
        for blk in self.iter_blks():
            debug_print4(f"Dump_uint8: Fetching {blk.vdev}:{blk.offset:x}:{len(blk.buf):x}", DEBUG_ZFS_OBJECT)
            std_write(blk.buf)
        debug_print1("=========== raw_data end ============", DEBUG_ZFS_OBJECT)

    def dump_dsl_dataset(self, buf=None):
        names = "dir_obj prev_snap_obj prev_snap_txg next_snap_obj snapnames_zapobj num_children userrefs_obj creation_time creation_txg deadlist_obj used_bytes compressed_bytes uncompressed_bytes unique fsid_guid guid flags next_clones_obj props_obj".split()
        values = struct.unpack_from("16Q128x3Q", buf)
        print_zip(names, values)
        print(f"\tbp = {BlkPtr(buf[128:128+128]).desc()}")
        self.dump_zap()

    def get_dump_func(self, dn_type):
        func_name = get_dump_func(dn_type)
        if hasattr(self, func_name):
            return getattr(self, func_name)
        return getattr(self, "dump_none")

    def dump(self, raw=False):
        debug_print3(f"dnode struct: {self.prop}", DEBUG_ZFS_OBJECT)
        debug_print4(hexdump(self.data), DEBUG_ZFS_OBJECT)
        debug_print1(f'dumpling dnode "{self.desc()}"', DEBUG_ZFS_OBJECT)
        if raw:
            return self.dump_raw()
        if self.prop.bonuslen > 0 and self.prop.bonustype > 0:
            dump_func = self.get_dump_func(self.prop.bonustype)
            dump_func(self.get_bonus_data())
        dump_func = self.get_dump_func(self.prop.dn_type)
        dump_func()

def get_mode(mode):
    off = 0
    mask = 7
    modes = []
    while mode > 0:
        modes.insert(0, f"{mode & mask}")
        mode = mode >> 3
    return "".join(modes)

class DMUObjset(DMUObjectCommon):
    dn_type = 10
    type2name = {
        0: "DMU_OST_NONE",
        1: "DMU_OST_META",
        2: "DMU_OST_ZFS",
        3: "DMU_OST_ZVOL",
    }

    SA_STD = [
        ["ZPL_UID", "uid", int],
        ["ZPL_GID", "gid", int],
        ["ZPL_ATIME", "atime", lambda x: datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")],
        ["ZPL_MTIME", "mtime", lambda x: datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")],
        ["ZPL_CTIME", "ctime", lambda x: datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")],
        ["ZPL_CRTIME", "crtime", lambda x: datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")],
        ["ZPL_GEN", "gen", int],
        ["ZPL_MODE", "mode", get_mode],
        ["ZPL_SIZE",  "size", int],
        ["ZPL_PARENT", "parent", int],
        ["ZPL_LINKS", "links", int],
    ]

    def __init__(self, data):
        super().__init__(data)

    def get_znode_attr(self, znode_buf):
        sa_obj_id = self.get_object(1).get_zap("SA_ATTRS")
        sa_master = self.get_object(sa_obj_id)
        registry_id = sa_master.get_zap("REGISTRY")
        layouts_id = sa_master.get_zap("LAYOUTS")
        self.sa_name_dict = dict()
        self.sa_attr_dict = dict()
        self.layouts = dict()
        for name, value, attr_num, attr_bswap, attr_length in self.get_object(registry_id).iter_sa_attr():
            self.sa_name_dict[name] = [attr_bswap, attr_length, value]
            self.sa_attr_dict[attr_num] = [name, attr_bswap, attr_length, value]

        for name, layouts in self.get_object(layouts_id).iter_my_zap():
            self.layouts[name] = layouts
        magic, layout, size = struct.unpack_from("IHH", znode_buf)
        assert magic == 0x2f505a
        hdrsz = (layout >> 10)*8
        layout_id = f"{layout & ((1<<10) - 1)}"
        off = 8
        attrs = dict()
        for attr_num in self.layouts[layout_id]:
            attr_length = self.sa_attr_dict[attr_num][-2]
            attr_name = self.sa_attr_dict[attr_num][0]
            value = struct.unpack_from("Q", znode_buf, off)[0]
            attrs[attr_name] = value
            off = off + attr_length
        for name, desc, func in self.SA_STD:
            print(f"\t{desc}\t{func(attrs[name])}")


    def dump_object(self, object_id, raw=False):
        obj = self.get_object(object_id)
        debug_print1(f'dumping id #{object_id} "{obj}" from object set', DEBUG_ZFS_OBJECT)
        obj.dump(raw)

    def dump(self, object_id=0, raw=False):
        obj_type = self.get_objset_type()
        debug_print3(f"dnode struct: {self.prop}", DEBUG_ZFS_OBJECT)
        debug_print4(hexdump(self.data), DEBUG_ZFS_OBJECT)
        debug_print0(f"OBJSET: {self.type2name.get(obj_type)}, BP = {self.bps}", DEBUG_ZFS_OBJECT)
        if object_id == 0:
            for obj_id, obj in self.iter_objects():
                debug_print0(f"{obj_id:>4d} {obj}", DEBUG_ZFS_OBJECT, fd=sys.stdout)
            return 
        return self.dump_object(object_id, raw)

    def get_objset_type(self):
        assert len(self.data) >= 1024 and self.prop.dn_type == self.dn_type
        objset_type = struct.unpack_from("@Q", self.data[512+192:])[0]
        return objset_type

    def get_object(self, obj_id):
        obj_per_blk = 32
        blkid = obj_id // obj_per_blk
        obj_offset = (obj_id % obj_per_blk) * 512
        blockdata = self.read_blk(blkid).buf
        buf = blockdata[obj_offset:obj_offset + 512]
        return DMUObject(self, buf)

    def iter_objects(self):
        obj_per_blk = 32
        for blockdata in self.iter_blks():
            obj_id = blockdata.id * obj_per_blk
            for i in range(obj_per_blk):
                obj = DMUObject(self, blockdata.buf[i*512:i*512+512])
                if obj.prop.dn_type != 0:
                    yield obj_id + i, obj

# This script always starts from objset,
# as dump other objects also depends on objset itself.
#
# 从对象 objset 开始，可以找到所有对象，步骤如下：
# 逐级读取 objset->bps 数据块(L2->L1->L0 这样)
# 每个数据块大小 16K：32 个对象（512 字节）
# 参考上面的 iter_objects

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", metavar="mos", help="path to objset data, default is stdin")
    parser.add_argument("--obj_id", metavar="0", help="object id, default 0 is objset itself", type=int, default=0)
    parser.add_argument("--raw", help="dump as raw data", action='store_true')
    args = parser.parse_args()
    return args


def main():
    args = parse_arg()
    if args.file:
        debug_print0(f"Reading object from: {args.file}", DEBUG_ZFS_OBJECT)
        buf = open(args.file, "rb").read()
    else:
        debug_print0(f"Reading object from stdin", DEBUG_ZFS_OBJECT)
        buf = sys.stdin.buffer.read()

    return DMUObjset(buf).dump(args.obj_id, args.raw)

if __name__ == '__main__':
    main()
