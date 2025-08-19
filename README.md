# pyzdb
Home made tools to play with the ondisk data of zfs.

zdb is a great tool.
As Linux does not have a tool like mdb, so I write these small scripts to help play with zfs data.

# How to use the scripts
```
# generate config from dev labels
# same as zdb -C
./zdb_label.py --dev ~/workspace/zfs_test/blk* --dump nvlist > nvlist.json
# same as zdb -l -uuuu zpool, you can get the rootbp
# output like this:
# Uberblock[137]
#	magic = 0xbab10c
#	version = 5000
#	txg = 23148999
#	timestamp = 1755587607
#	rootbp = [L0 11 DVA[0]=<0:1102b4e13400:1000/200 asize=600>]
./zdb_label.py --dev ~/workspace/zfs_test/blk* --dump uberblock | tail -n 6
# Read the MOS: type is objset and object id is 0
# zdb_vdev.py: usage is almost same as zdb -R, "d" is decompress(only lz4 is supported), 'r' is raw output
# zdb_object.py: similar with zdb -ddd, dump the object or objset
./zdb_vdev.py --ptr 0:1102b4e13400:1000/200:dr | ./zdb_obj.py
./zdb_vdev.py --ptr 0:1102b4e13400:1000/200:dr | ./zdb_obj.py --obj_id 1

# some zdb trick
# dump uberlock and rootbp
# $ zdb -l -uuuu zpool
# read bp
# $ zdb -R poolname vdev:offset:[<lsize>/]<psize>[:flags]
#     if psize < lsize, "d" in flags, note flag "c" is conflict with "d"
#     if ptr is not L0, you can play with flags "di"; because meta is always compressed
#        it will dump next level block pointer (bp)

```
