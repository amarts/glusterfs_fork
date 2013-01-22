#!/bin/bash

#AFR TEST-IDENTIFIER SPLIT-BRAIN
. $(dirname $0)/../include.rc
. $(dirname $0)/../volume.rc

cleanup;

TEST glusterd
TEST pidof glusterd
TEST $CLI volume info;

B0_hiphenated=`echo $B0 | tr '/' '-'`
TEST $CLI volume create $V0 replica 2 $H0:$B0/${V0}{1,2}

#Make sure self-heal is not triggered when the bricks are re-started
TEST $CLI volume set $V0 cluster.self-heal-daemon off
TEST $CLI volume set $V0 performance.stat-prefetch off
TEST $CLI volume start $V0
TEST glusterfs --entry-timeout=0 --attribute-timeout=0 -s $H0 --volfile-id=$V0 $M0 --direct-io-mode=enable
TEST touch $M0/a
TEST touch $M0/b
TEST touch $M0/c
TEST touch $M0/d
echo "1" > $M0/b
echo "1" > $M0/d
TEST kill_brick $V0 $H0 $B0/${V0}2
echo "1" > $M0/a
echo "1" > $M0/c
TEST setfattr -n trusted.mdata -v abc $M0/b
TEST setfattr -n trusted.mdata -v abc $M0/d
TEST $CLI volume start $V0 force
EXPECT_WITHIN 20 "1" afr_child_up_status $V0 1
TEST kill_brick $V0 $H0 $B0/${V0}1
echo "2" > $M0/a
echo "2" > $M0/c
TEST setfattr -n trusted.mdata -v def $M0/b
TEST setfattr -n trusted.mdata -v def $M0/d
TEST $CLI volume start $V0 force
EXPECT_WITHIN 20 "1" afr_child_up_status $V0 0
EXPECT_WITHIN 20 "1" afr_child_up_status $V0 1

TEST glusterfs --entry-timeout=0 --attribute-timeout=0 -s $H0 --volfile-id=$V0 $M1 --direct-io-mode=enable
#Files are in split-brain, so open should fail
TEST ! cat $M0/a;
TEST ! cat $M1/a;
TEST ! cat $M0/b;
TEST ! cat $M1/b;

#Reset split-brain status
TEST setfattr -n trusted.afr.$V0-client-1 -v 0x000000000000000000000000 $B0/${V0}1/a;
TEST setfattr -n trusted.afr.$V0-client-1 -v 0x000000000000000000000000 $B0/${V0}1/b;

#The operations should do self-heal and give correct output
EXPECT "2" cat $M0/a;
EXPECT "2" cat $M1/a;
EXPECT "def" getfattr -n trusted.mdata --only-values $M0/b 2>/dev/null
EXPECT "def" getfattr -n trusted.mdata --only-values $M1/b 2>/dev/null

TEST umount $M0
TEST umount $M1

TEST $CLI volume set $V0 cluster.data-self-heal off
TEST $CLI volume set $V0 cluster.metadata-self-heal off

TEST glusterfs --entry-timeout=0 --attribute-timeout=0 -s $H0 --volfile-id=$V0 $M0 --direct-io-mode=enable
TEST glusterfs --entry-timeout=0 --attribute-timeout=0 -s $H0 --volfile-id=$V0 $M1 --direct-io-mode=enable

#Files are in split-brain, so open should fail
TEST ! cat $M0/c
TEST ! cat $M1/c
TEST ! cat $M0/d
TEST ! cat $M1/d

TEST setfattr -n trusted.afr.$V0-client-1 -v 0x000000000000000000000000 $B0/${V0}1/c
TEST setfattr -n trusted.afr.$V0-client-1 -v 0x000000000000000000000000 $B0/${V0}1/d

#The operations should NOT do self-heal but give correct output
EXPECT "2" cat $M0/c
EXPECT "2" cat $M1/c
EXPECT "1" cat $M0/d
EXPECT "1" cat $M1/d

#Check that the self-heal is not triggered.
EXPECT "1" cat $B0/${V0}1/c
EXPECT "abc" getfattr -n trusted.mdata --only-values $B0/${V0}1/d 2>/dev/null
cleanup;
