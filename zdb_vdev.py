#!/usr/bin/env python3

import argparse
import os
import json
from zdb_utils import *

class VDEVLeaf:
    def __init__(self, **kwargs):
        self.id = kwargs['id']
        self.type = kwargs["type"]
        self.path =  kwargs['path']
        assert self.type in ["file", "disk"]

    def read(self, offset, size):
        debug_print1(f"VDEVLeaf read at #{self.id} path: {self.path} offset: 0x{offset:x}+0x400000 size={size:x}", DEBUG_ZFS_VDEV)
        with open(self.path, "rb") as f:
            f.seek(offset + 0x400000)
            data = f.read(size)
            return data

    def __repr__(self):
        return f"<Vdev:{self.id}:{self.path}>"

class VDEVRaidZ:
    def __init__(self, **kwargs):
        self.id = kwargs["id"]
        self.guid = kwargs['guid']
        self.ashift = kwargs["ashift"]
        self.nparity = kwargs["nparity"]
        self.child_config = kwargs["children"]
        self.children = dict()
        self.dcols = len(self.child_config)
        for child in self.child_config:
            self.add_child(VDEVLeaf(**child))
        self.min_block_size = 1 << self.ashift

    def add_child(self, child):
        self.children[child.id] = child

    def __repr__(self):
        return f"<Raidz{self.nparity}:{self.children}>"

    @staticmethod
    def vdev_raiz_map_alloc(io_offset, io_size, ashift, dcols, nparity):
        # 在 vdev 里面第几个扇区
        b = io_offset >> ashift
        # 需要几个 io 请求
        s = io_size >> ashift
        # 条带 (stripe) 第一个 column 编号
        f = b % dcols
        # 每个子设备的偏移
        o = (b // dcols) << ashift
        # 先大致分配，每个dev 分到 q 个 io
        q = s // (dcols - nparity)

        # 还剩下几个
        r = s - q * (dcols - nparity)
        if r == 0:
            bc = 0
        else:
            bc = r + nparity

        # acols：访问到的 column 数量
        # scols：访问到的 column 数量，还包括填充的 column 数量
        if q == 0:
            # 数据都不能用完所有的条带的情况，这种情况其实就是 r == s, bc = r + nparity
            acols = bc
            scols = min(dcols, roundup(bc, nparity + 1))
        else:
            acols = dcols
            scols = dcols

        rr = dict()
        rr['rr_cols'] = acols
        rr['rr_scols'] = scols
        rr['rr_bigcols'] = bc
        rr['rr_firstdatacol'] = nparity

        rr_col = []
        asize = 0
        for c in range(scols):
            col = f + c
            coff = o
            if col >= dcols:
                col -= dcols
                coff += 1 << ashift
            rc = dict()
            rc['rc_devidx'] = col
            rc['rc_offset'] = coff
            if c >= acols:  # 超过了 r + npairty 的情况，应该返回空数据
                rc['rc_size'] = 0
            elif c < bc:    # 前面几列，会比别人多一行
                rc['rc_size'] = (q+1) << ashift
            else:
                rc['rc_size'] = q << ashift
            asize += rc['rc_size']
            rr_col.append(rc)

        rr['rr_col'] = rr_col
        return rr

    def read_chunks(self, rr):
        for rc in rr['rr_col'][rr['rr_firstdatacol']:]:
            rc_size = rc['rc_size']
            if rc_size > 0:
                devidx = rc['rc_devidx']
                dev = self.children[devidx]
                yield dev.read(rc['rc_offset'], rc_size)

    def read(self, io_offset, io_size):
        debug_print1(f"Raidz{self.nparity} read vdev: {self.id}, disk: {self.dcols}, ashift: {self.ashift} ({1<<self.ashift})", DEBUG_ZFS_VDEV)
        rr = self.vdev_raiz_map_alloc(io_offset, io_size, self.ashift, self.dcols, self.nparity)
        debug_print2(json.dumps(rr, indent=4), DEBUG_ZFS_VDEV)
        data = b''
        for chunk in self.read_chunks(rr):
            data += chunk
        return data

class VDEVHandler:
    def __init__(self, nv_config_list):
        self.vdev_dict = dict()
        self.vdev_guid_dict = dict()
        for nv_config in nv_config_list:
            vdev_conf = nv_config["vdev_tree"]
            vdev_id = vdev_conf["id"]
            vdev_guid = vdev_conf["guid"]
            if vdev_id in self.vdev_dict:
                assert self.vdev_guid_dict[vdev_id] == vdev_guid
                continue
            assert vdev_conf['type'] in ['raidz', 'file', 'disk'], "Only raidz and file vdev are supported"
            if vdev_conf['type'] == 'raidz':
                vdev = VDEVRaidZ(**vdev_conf)
            elif vdev_conf['type'] in ['file', 'disk']:
                vdev = VDEVLeaf(**vdev_conf)
            self.vdev_dict[vdev_id] = vdev
            self.vdev_guid_dict[vdev_id] = vdev_guid

    def read_vdev(self, vdev_id, io_offset, io_size):
        vdev = self.vdev_dict[vdev_id]
        vdev_size = roundup(io_size, vdev.min_block_size)
        data = vdev.read(io_offset, vdev_size)[:io_size]
        assert io_size == len(data)
        return data

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", metavar="nvlist.json", default="nvlist.json")
    parser.add_argument("--ptr", metavar="<vdev>:<offset>:<size>[:<flags>]", help="/path/to/file:0:200:r local file is also supported")
    args = parser.parse_args()
    return args


def vdev_read(vdev_id, offset, io_size, vdev_conf="nvlist.json"):
    with open(vdev_conf) as f:
        return VDEVHandler(json.load(f)).read_vdev(vdev_id, offset, io_size)

def main():
    args = parse_arg()
    if args.ptr:
        from zdb_blkptr import BlkPtr
        return BlkPtr.read_ptr(args.ptr)

if __name__ == '__main__':
    main()