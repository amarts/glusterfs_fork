if BUILD_CLOUDSYNC
  CLOUDSYNC_DIR = cloudsync
endif

if BUILD_METADISP
  METADISP_DIR = metadisp
endif

SUBDIRS = locks quota read-only quiesce index barrier arbiter upcall marker quota \
	compress changelog gfid-access snapview-client snapview-server trash \
	shard bit-rot leases selinux sdfs namespace $(CLOUDSYNC_DIR) thin-arbiter \
	utime $(METADISP_DIR) simple-quota

CLEANFILES =
