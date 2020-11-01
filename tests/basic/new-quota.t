#!/bin/bash

. $(dirname $0)/../include.rc
. $(dirname $0)/../volume.rc

cleanup;

TEST glusterd
TEST pidof glusterd
TEST $CLI volume info;

TEST $CLI volume create $V0 replica 3 $H0:$B0/${V0}{1,2,3};
#TEST $CLI volume set $V0 quota-deem-statfs enable;
TEST $CLI volume start $V0;

## Mount FUSE
TEST $GFS -s $H0 --volfile-id $V0 $M1;

mkdir $M1/test;
echo -n helloworld > $M1/file1;
echo -n helloworld > $M1/file2;

mkdir $M1/test2;

TEST setfattr -n trusted.glusterfs.namespace -v true $M1/test2;
TEST setfattr -n trusted.glusterfs.quota.limit-set -v 10000 $M1/test2;

echo -n helloworld > $M1/test2/file1;
echo -n helloworld > $M1/test2/file2;
echo -n helloworld > $M1/test/file1;
echo -n helloworld > $M1/test/file2;

dd if=/dev/urandom of=$M1/test2/dd-file count=1 bs=8k

df $M1/test2;

mkdir $M1/test2/dir2.1;
mkdir $M1/test2/dir2.2;
echo -n helloworld > $M1/test2/dir2.1/file1;
echo -n helloworld > $M1/test2/dir2.2/file1;
echo -n helloworld > $M1/file3;

TEST mkdir -p $M1/a/b/c/d/e/f;

echo hello world > $M1/a/b/c/d/e/f/g;

sleep 5;
TEST kill_brick $V0 $H0 $B0/${V0}3;

sleep 3;
TEST $CLI volume start $V0 force;

sleep 1;

TEST cat $M1/a/b/c/d/e/f/g;

df $M1/test2;

TEST $CLI volume stop $V0;
TEST $CLI volume start $V0;
sleep 3;

ls $M1;

echo -n helloworld >> $M1/test/file1;
echo -n helloworld >> $M1/test/file2;
echo -n helloworld >> $M1/file1;
echo -n helloworld >> $M1/file2;
echo -n helloworld >> $M1/test2/dir2.1/file1;
echo -n helloworld >> $M1/test2/dir2.2/file1;
echo -n helloworld >> $M1/test2/file1;
echo -n helloworld >> $M1/a/b/c/d/e/f/g;

df $M1/test2;

sleep 4;

TEST echo "DONE"

#cleanup;
