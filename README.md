# pyzdb
Home made tools to play with the ondisk data of zfs.

zdb is a great tool.
As Linux does not have a tool like mdb, so I write these small scripts to help play with zfs data.

# How to use the scripts
```
./zdb_label.py --dev ~/workspace/zfs_test/blk* --dump nvlist > nvlist.json
./zdb_label.py --dev ~/workspace/zfs_test/blk* --dump uberblock | tail -n 6
./zdb_vdev.py --ptr 0:1d24000:1000/1000 | ./zdb_obj.py
./zdb_vdev.py --ptr 0:1d24000:1000/1000 | ./zdb_obj.py --obj_id 1
```
