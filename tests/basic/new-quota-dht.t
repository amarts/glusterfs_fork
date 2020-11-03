#!/bin/bash

. $(dirname $0)/../include.rc
. $(dirname $0)/../volume.rc

cleanup;

TEST glusterd
TEST pidof glusterd
TEST $CLI volume info;

TEST $CLI volume create $V0 $H0:$B0/${V0}{1,2,3};
TEST $CLI volume set $V0 feature.simple-quota-pass-through false;
TEST $CLI volume start $V0;

## Mount FUSE
TEST $GFS -s $H0 --volfile-id $V0 $M1;

mkdir $M1/test2;

TEST setfattr -n trusted.glusterfs.namespace -v true $M1/test2;
TEST setfattr -n trusted.gfs.squota.limit -v 10000 $M1/test2;

echo -n helloworld > $M1/test2/file1;
echo -n helloworld > $M1/test2/file2;
TEST dd if=/dev/urandom of=$M1/test2/dd-file count=1 bs=8k

df  $M1/test2;
used_size=$(df --block-size=1 --output=used $M1/test2 | tail -n1);
TEST setfattr -n glusterfs.quota.total-usage -v $used_size $M1/test2;

mkdir $M1/test2/dir2.1;
mkdir $M1/test2/dir2.2;
echo -n helloworld > $M1/test2/dir2.1/file1;
echo -n helloworld > $M1/test2/dir2.2/file1;

TEST mkdir -p $M1/a/b/c/d/e/f;

echo hello world > $M1/a/b/c/d/e/f/g;

TEST ! dd if=/dev/urandom of=$M1/test2/dd-file1 count=1 bs=8k

sleep 5;

TEST cat $M1/a/b/c/d/e/f/g;

df $M1/test2;

TEST $CLI volume stop $V0;
TEST $CLI volume start $V0;

sleep 3;

umount $M1;

TEST $GFS --xlator-option *dht.lookup-optimize=false -s $H0 --volfile-id $V0 $M1;

#used_size=$(df --block-size=1 --output=used $M1/test2 | tail -n1);
#TEST setfattr -n glusterfs.quota.total-usage -v $used_size $M1/test2;

echo -n helloworld >> $M1/test2/dir2.1/file1;
echo -n helloworld >> $M1/test2/dir2.2/file1;
echo -n helloworld >> $M1/test2/file1;
echo -n helloworld >> $M1/a/b/c/d/e/f/g;

TEST ! dd if=/dev/urandom of=$M1/test2/dd-file2 count=3 bs=4k

df $M1/test2;

sleep 4;

TEST echo "DONE"

#cleanup;
