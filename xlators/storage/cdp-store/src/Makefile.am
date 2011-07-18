
xlator_LTLIBRARIES = cdp-store.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/storage

cdp_store_la_LDFLAGS = -module -avoidversion

cdp_store_la_SOURCES = cdp.c cdp-helpers.c cdp-snapshot.c
cdp_store_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = cdp.h cdp-mem-types.h

AM_CFLAGS = -fPIC -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
            -D$(GF_HOST_OS) -Wall -I$(top_srcdir)/libglusterfs/src -shared \
            -nostartfiles -I$(top_srcdir)/contrib/md5 -I$(top_srcdir)/rpc/xdr/src \
            -I$(top_srcdir)/rpc/rpc-lib/src $(GF_CFLAGS)

CLEANFILES =

