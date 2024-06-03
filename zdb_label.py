import struct
from collections import OrderedDict
import math
import argparse
import json

from zdb_blkptr import BlkPtr

class NVPair:
    def __init__(self, data):
        self.data = data
        value_offset, self.name = self.get_str(struct.calcsize(">2I"))
        self.value = self.decode_value(value_offset)

    def decode_value(self, value_offset):
        self.datatype, self.datacnt = struct.unpack_from(">2I", self.data, value_offset)
        offset = value_offset + struct.calcsize(">2I")
        if self.datatype == 0x8:
            return struct.unpack_from(">Q", self.data[offset:])[0]
        elif self.datatype == 0x9:
            return self.get_str(offset)[1]
        elif self.datatype == 19:
            return NVList(self.name, self.data[offset:]).table
        elif self.datatype == 20:
            return NVListArray(self.name, self.data[offset:], self.datacnt).values
        elif self.datatype == 0x1:
            return "TRUE"
        else:
            print(f"unknown {self.name} {self.datatype} {self.data[offset:]}")

    def get_str(self, offset):
        n = struct.unpack_from(">I", self.data, offset)[0]
        aligned = math.ceil(n/4)*4
        return offset + aligned + 4, self.data[offset+4: offset+n+4].decode()

    def __repr__(self):
        return f"<NVPair:{self.name}: {self.value}>"

# XDR encoding functions
#
# An xdr packed nvlist is encoded as:
#
#  - encoding method and host endian (4 bytes)
#  - nvl_version (4 bytes)
#  - nvl_nvflag (4 bytes)
#
#  - encoded nvpairs, the format of one xdr encoded nvpair is:
#      - encoded size of the nvpair (4 bytes)
#      - decoded size of the nvpair (4 bytes)
#      - name string, (4 + sizeof(NV_ALIGN4(string))
#        a string is coded as size (4 bytes) and data
#      - data type (4 bytes)
#      - number of elements in the nvpair (4 bytes)
#      - data
#
#  - 2 zero's for end of the entire list (8 bytes)

class NVList:
    def __init__(self, name, data):
        self.name = name
        self.table = OrderedDict()
        # Length of NVList is variable
        self.version, self.flag = struct.unpack_from(">2I", data)
        # skip nvl_version and nvl_nvflag
        offset = struct.calcsize(">2I")

        while True:
            enc_size, dec_size = struct.unpack_from(">2I", data, offset)
            # NVList ends with 00000000
            if enc_size == 0 and dec_size == 0:
                self.len = offset + 8
                break
            nvp = NVPair(data[offset: offset + enc_size])
            self.table[nvp.name] = nvp.value
            offset = offset + enc_size

    def get_value_by_name(self, name):
        return self.table[name]

    def get_obj_by_name(self, name):
        return self.table[name]

class NVListArray:
    def __init__(self, name, data, cnt, level=0):
        self.name = name
        self.data = data
        self.cnt = cnt
        self.values = []
        offset = 0
        for i in range(cnt):
            nvl = NVList(f"{self.name}[{i}]", data[offset:])
            offset = offset + nvl.len
            self.values.append(nvl.table)

class Uberblock:
    def __init__(self, data):
        self.magic, self.version, self.txg, self.guid_sum, self.ts = struct.unpack_from("5Q", data)
        self.blkptr = BlkPtr(data[5*8:])

    def dump(self, idx=0):
        if self.magic == 0xbab10c:
            print(f"Uberblock[{idx}]\n\tmagic = {hex(self.magic)}\n\tversion = {self.version}\n\ttxg = {self.txg}\n\ttimestamp = {self.ts}\n\trootbp = {self.blkptr}")

class UberblockList:
    UB_LEN = 1024
    def __init__(self, data):
        self.data = data
        self.ublist = []
        data_len = len(self.data)
        offset = 0
        while offset < data_len:
            ubdata = data[offset : offset + self.UB_LEN]
            self.ublist.append(Uberblock(ubdata))
            offset += self.UB_LEN
        self.ublist.sort(key=lambda x:x.txg)

    def dump(self):
        for idx, ub in enumerate(self.ublist):
            ub.dump(idx)


class Label:
    def __init__(self, dev, label_id=0):
        self.label_id = label_id
        assert label_id <=1, "Label 0 and Label 1 only"
        with open(dev, "rb") as f:
            f.seek(label_id*512)
            data = f.read(512*1024)
        # 0-8KB black space; 8-16KB booth header;
        # 16-128KB NVPairs; 128-256KB Uberblock list
        self.nvdata = data[16*1024: 128*1024]
        self.ublist = UberblockList(data[128*1024:266*1024])
        self.encoding_method = self.nvdata[0]
        self.encoding_endian = self.nvdata[1]
        self.nvlist = NVList("root", self.nvdata[4:])
        self.top_guid = self.nvlist.table['top_guid']

    def get_nvlist(self, remove_guid=False):
        if remove_guid:
            del self.nvlist.table["guid"]
        return self.nvlist.table

    def dump_nvlist(self):
        print(json.dumps(self.nvlist.table, indent=4))

    def dump_uberblock(self):
        self.ublist.dump()

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", nargs="*", default=["/dev/vdb1"])
    parser.add_argument("--dump", choices=["nvlist", 'uberblock'])
    args = parser.parse_args()
    return args


def main():
    args = parse_arg()
    if args.dump == "nvlist":
        nvdata = [Label(dev).get_nvlist() for dev in args.dev]
        print(json.dumps(nvdata, indent=4))
        return

    if args.dump == "uberblock":
        label = Label(args.dev[0])
        label.dump_uberblock()
        return

if __name__ == '__main__':
    main()