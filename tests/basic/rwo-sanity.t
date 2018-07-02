#!/bin/bash

. $(dirname $0)/../include.rc
. $(dirname $0)/../volume.rc

cleanup;

TEST glusterd
TEST pidof glusterd

TEST $CLI volume create $V0 $H0:$B0/${V0}1;
TEST $CLI volume set $V0 features.read-write-once enable;
TEST $CLI volume set $V0 performance.open-behind off;
TEST $CLI volume set $V0 performance.quick-read off;
TEST $CLI volume set $V0 performance.write-behind off;
TEST $CLI volume set $V0 performance.read-ahead off;
TEST $CLI volume set $V0 performance.stat-prefetch off;
TEST $CLI volume start $V0;

## Mount FUSE
TEST $GFS -s $H0 --volfile-id $V0 $M1;

# This test covers lookup, mkdir, mknod, symlink, link, rename,
# create operations
TEST $(dirname $0)/rpc-coverage.sh $M1

# TEST truncate -s 200M $M0/loop-file

# mkfs.xfs

# add more tests

# cleanup;
