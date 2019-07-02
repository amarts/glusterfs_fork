if BUILD_GNFS
  GNFS_DIR = nfs
endif

if BUILD_GLUSTERD
  MGMT_GLUSTERD = mgmt
endif

DIST_SUBDIRS = cluster storage protocol performance debug features \
          mount nfs mgmt system playground meta

SUBDIRS = cluster storage protocol performance debug features \
          mount ${GNFS_DIR} ${MGMT_GLUSTERD} system playground meta

EXTRA_DIST = xlator.sym

CLEANFILES =
