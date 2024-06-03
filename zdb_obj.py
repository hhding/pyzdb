import struct
from collections import namedtuple
import argparse
from zdb_blkptr import BlkPtr
from zdb_utils import *
from zdb_zap import *

def print_zip(alist, blist, indent="\t"):
    for a, b in zip(alist, blist):
        print(f"{indent}{a} = {b}")

def dump_none(obj, buf=None, verbose=0):
    debug_print2("call dump_none", verbose=verbose)

def fmt_base(base="d"):
    def func(value):
        if type(value) == int:
            return f"{value:{base}}"
        return "".join(f"{v:02x}" for v in value)
    return func

def dump_zap(obj, buf=None, verbose=0, fmt_func=fmt_base('d')):
    debug_print0("call dump_zap", verbose=verbose)
    debug_print0("Dumping zap object data:", verbose=verbose)
    for value, cd, name in ZapRegistry.get_inst(obj.read_blk(0).buf).iter_ent(obj, verbose=verbose):
        print(f"\t{name} = {fmt_func(value)}")

def dump_uint64(obj, buf=None, verbose=0):
    debug_print0("call dump_uint64", verbose=verbose)

def dump_zpldir(obj, buf=None, verbose=0):
    debug_print0("call dump_zpldir", verbose=verbose)
    for value, cd, name in ZapRegistry.get_inst(obj.read_blk(0).buf).iter_ent(obj, verbose=verbose):
        obj_id = value & ((1<<48) - 1)
        file_type = value >> 60
        print(f"\t{name} = {obj_id} (type: {file_type})")

def dump_dnode(obj, buf=None, verbose=0):
    debug_print0("call dump_dnode", verbose=verbose)

def dump_dmu_objset(obj, buf=None, verbose=0):
    debug_print0("call dump_objset", verbose=verbose)

def dump_znode(obj, buf=None, verbose=0):
    debug_print0("call dump_znode", verbose=verbose)

def dump_dsl_dir(obj, buf=None, verbose=0):
    debug_print0("call dump_dsl_dir", verbose=verbose)
    names = "creation_time head_dataset_obj parent_dir_obj origin_obj child_dir_zapobj used_bytes compressed_bytes uncompressed_bytes quota reserved props_zapobj deleg_zapobj flags used_breakdown[HEAD] used_breakdown[SNAP] used_breakdown[CHILD] used_breakdown[CHILD_RSRV] used_breakdown[REFRSRV] clones".split()
    values = struct.unpack_from("20Q", buf)
    print_zip(names, values)

def dump_bpobj(obj, buf=None, verbose=0):
    debug_print0("call dump_bpobj", verbose=verbose)
    names = "num_blkptrs bytes comp uncomp subobjs numsubobjs".split()
    values = list(struct.unpack_from("6Q", buf))
    print_zip(names, values)
    
def dump_uint8(obj, buf=None, verbose=0):
    debug_print0("call dump_uint8", verbose=verbose)
    debug_print0("=========== raw_data start ============", verbose=verbose)
    for blk in obj.iter_blks():
        os.write(1, blk.buf)
    debug_print0("=========== raw_data end ============", verbose=verbose)

def dump_dsl_dataset(obj, buf=None, verbose=0):
    debug_print0("call dump_dsl_dataset", verbose=verbose)
    names = "dir_obj prev_snap_obj prev_snap_txg next_snap_obj snapnames_zapobj num_children userrefs_obj creation_time creation_txg deadlist_obj used_bytes compressed_bytes uncompressed_bytes unique fsid_guid guid flags next_clones_obj props_obj".split()
    values = struct.unpack_from("16Q128x3Q", buf)
    print_zip(names, values)
    print(f"\tbp = {BlkPtr(buf[128:128+128]).desc(verbose)}")
    dump_zap(obj)

dmu_ot_info = [
    [dump_none,	"unallocated"],
    [dump_zap,	"object directory"],
    [dump_uint64,	"object array"],
    [dump_none,	"packed nvlist"],
    [dump_none,	"packed nvlist size"],
    [dump_none,	"bpobj"],
    [dump_bpobj,	"bpobj header"],
    [dump_none,	"SPA space map header"],
    [dump_none,	"SPA space map"],
    [dump_none,	"ZIL intent log"],
    [dump_dnode,	"DMU dnode"],
    [dump_dmu_objset,	"DMU objset"],
    [dump_dsl_dir,	"DSL directory"],
    [dump_zap,	"DSL directory child map"],
    [dump_zap,	"DSL dataset snap map"],
    [dump_zap,	"DSL props"],
    [dump_dsl_dataset,	"DSL dataset"],
    [dump_none,	"ZFS znode"],
    [dump_none,	"ZFS V0 ACL"],
    [dump_uint8,	"ZFS plain file"],
    [dump_zpldir,	"ZFS directory"],
    [dump_zap,	"ZFS master node"],
    [dump_zap,	"ZFS delete queue"],
    [dump_none,	"zvol object"],
    [dump_zap,	"zvol prop"],
    [dump_none,	"other uint8[]"],
    [dump_uint64,	"other uint64[]"],
    [dump_zap,	"other ZAP"],
    [dump_zap,	"persistent error log"],
    [dump_none,	"SPA history"],
    [dump_none,	"SPA history offsets"],
    [dump_zap,	"Pool properties"],
    [dump_zap,	"DSL permissions"],
    [dump_none,	"ZFS ACL"],
    [dump_none,	"ZFS SYSACL"],
    [dump_none,	"FUID table"],
    [dump_none,	"FUID table size"],
    [dump_zap,	"DSL dataset next clones"],
    [dump_zap,	"scan work queue"],
    [dump_zap,	"ZFS user/group/project used" ],
    [dump_zap,	"ZFS user/group/project quota"],
    [dump_zap,	"snapshot refcount tags"],
    [dump_none,	"DDT ZAP algorithm"],
    [dump_zap,	"DDT statistics"],
    [dump_znode,	"System attributes"],
    [dump_zap,	"SA master node"],
    [dump_none,	"SA attr registration"],
    [dump_none,	"SA attr layouts"],
    [dump_zap,	"scan translations"],
    [dump_none,	"deduplicated block"],
    [dump_zap,	"DSL deadlist map"],
    [dump_none,	"DSL deadlist map hdr"],
    [dump_zap,	"DSL dir clones"],
    [dump_none,	"bpobj subobj"],
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
    try:
        dump_func, name = dmu_ot_info[get_q_id(type_id)]
    except IndexError:
        return f"DMU {type_id}"
    return name

def get_dump_func(type_id):
    try:
        dump_func, name = dmu_ot_info[get_q_id(type_id)]
    except IndexError:
        return dump_none
    return dump_func

def get_dn_type(buf):
    return buf[0]

class DMUObjectRegistry:
    dn_type_cls = dict()

    @classmethod
    def register(cls, handle_cls):
        cls.dn_type_cls[handle_cls.dn_type] = handle_cls
    
    @classmethod
    def get_registry(cls, dn_type, default=None):
        return cls.dn_type_cls.get(dn_type, default)
    
'''same as struct dnode phys'''
class DMUObject:
    def __init_subclass__(cls, *args, **kwargs):
        DMUObjectRegistry.register(cls)

    def __init__(self, data):
        self.data = data
        assert len(data) >= 0x200, "buf too small, at least 0x200"
        names = "dn_type indblkshift nlevels nblkptr bonustype checksum compress flags datablkszsec bonuslen extra_slots maxblkid used"
        prop = namedtuple("DnodePhys", names)(*struct.unpack("@8BHHB3xQQ32x", data[:64]))
        self.prop = prop
        self.iblk = 1 << prop.indblkshift
        self.dblk = prop.datablkszsec << 9 # 16KB
        self.bps = self.get_bps(prop.nblkptr)
    
    def dump(self, verbose=0):
        debug_print0(f'dumpling dnode "{self.desc(verbose)}"', verbose)
        if self.prop.bonuslen > 0 and self.prop.bonustype > 0:
            dump_func = get_dump_func(self.prop.bonustype)
            dump_func(self, self.get_bonus_data(), verbose=verbose)
        dump_func = get_dump_func(self.prop.dn_type)
        dump_func(self, verbose=verbose)

    def dump_raw(self, verbose):
        if verbose >= 3:
            return os.write(1, self.data)
        else:
            print(f"dump_raw: length: {len(self.data):x}, verbose >= 3 to show data")
            return

    def get_bonus_data(self):
        start = 64 + 128
        return self.data[start:start + self.prop.bonuslen]

    def get_bps(self, nblkptr):
        bps = []
        for i in range(nblkptr):
            start = 64 + i*128
            bp = BlkPtr(self.data[start:start+128])
            if bp.prop.type != 0:
                bps.append(bp)
        return bps

    def read_blk(self, blkid):
        if self.prop.nlevels == 0:
            return [-1, -1, None]
        if self.prop.nlevels == 1:
            return self.bps[blkid].get_blkdata(0)
        return self.bps[0].get_blkdata(blkid)

    def iter_blks(self):
        for blkid in range(self.prop.maxblkid + 1):
            blockdata = self.read_blk(blkid)
            if blockdata.buf:
                yield blockdata

    def __repr__(self):
        return f"{dmutype2name(self.prop.dn_type)}"

    def desc(self, verbose=0):
        if self.prop.dn_type == 0:
            return "DMU unallocated"

        bp_info = "NO BLKPTR"
        if self.prop.nblkptr:
            bp_info = "BP=" + " ".join([bp.desc() for bp in self.bps])

        name = f"{dmutype2name(self.prop.dn_type)}"
        info = f"{name}"
        if self.prop.bonuslen > 0:
            info = f"{name} BONUS<{self.prop.bonuslen}>"

        if verbose >= 1:
            info = f"{info} {self.prop}"
        if verbose >= 2:
            info = f"{info} {bp_info}"
        return info

class DMUObjset(DMUObject):
    dn_type = 10
    type2name = {
        0: "DMU_OST_NONE",
        1: "DMU_OST_META",
        2: "DMU_OST_ZFS",
        3: "DMU_OST_ZVOL",
    }

    def dump_id(self, object_id, verbose=0):
        obj = self.get_object(object_id)
        debug_print1(fr'dumping id #{object_id} "{obj}" from objectset', verbose)
        obj.dump_raw(verbose)

    def dump(self, verbose=0):
        obj_type = self.get_objset_type()
        debug_print2(f"OBJSET {self.type2name.get(obj_type)}", verbose)
        for obj_id, obj in self.iter_objects(verbose=verbose):
            debug_print0(f"{obj_id:>4d} {obj}", verbose=verbose, fd=sys.stdout)

    def get_objset_type(self):
        assert len(self.data) >= 1024 and self.prop.dn_type == self.dn_type
        objset_type = struct.unpack_from("@Q", self.data[512+192:])[0]
        return objset_type

    def get_object(self, obj_id):
        obj_per_blk = 32
        blkid = obj_id // obj_per_blk
        obj_offset = (obj_id % obj_per_blk) * 512
        blockdata = self.read_blk(blkid)
        buf = blockdata.buf[obj_offset:obj_offset + 512]
        handle_cls = DMUObjectRegistry.get_registry(get_dn_type(self.data), DMUObject)

        return handle_cls(buf)

    def iter_objects(self, verbose):
        obj_per_blk = 32
        for blockdata in self.iter_blks():
            debug_print2(f"Dumpling block #{blockdata.id} @ {blockdata.vdev}:{blockdata.offset:x}", verbose)
            obj_id = blockdata.id * obj_per_blk
            for i in range(obj_per_blk):
                obj = DMUObject(blockdata.buf[i*512:i*512+512])
                if obj.prop.dn_type != 0:
                    yield obj_id + i, obj

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file")
    parser.add_argument("--obj_id", type=int, default=-1)
    parser.add_argument("--verbose", type=int, default=0)
    args = parser.parse_args()
    return args


def main():
    args = parse_arg()
    if args.file:
        debug_print1(f"Reading object from: {args.file}", args.verbose)
        buf = open(args.file, "rb").read()
    else:
        debug_print1(f"Reading object from stdin", args.verbose)
        buf = sys.stdin.buffer.read()

    if args.obj_id != -1:
        obj = DMUObjset(buf)
        return obj.dump_id(args.obj_id, args.verbose)
    else:
        obj_class = DMUObjectRegistry.get_registry(get_dn_type(buf), DMUObject)
        return obj_class(buf).dump(args.verbose)

if __name__ == '__main__':
    main()
