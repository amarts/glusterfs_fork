sbin_PROGRAMS = volfile-server

volfile_server_SOURCES = volfile-server.c
volfile_server_LDADD = $(top_builddir)/libglusterfs/src/libglusterfs.la \
	$(top_builddir)/rpc/rpc-lib/src/libgfrpc.la \
	$(top_builddir)/rpc/xdr/src/libgfxdr.la $(GF_LDADD) $(LIB_DL)
volfile_server_LDFLAGS = $(GF_LDFLAGS)

noinst_HEADERS = volfile-server.h

AM_CPPFLAGS = $(GF_CPPFLAGS) \
	-I$(top_srcdir)/libglusterfs/src $(GF_GLUSTERFS_CFLAGS) \
        -DDATADIR=\"$(localstatedir)\"  \
	-I$(top_srcdir)/rpc/rpc-lib/src \
	-I$(top_srcdir)/rpc/xdr/src \
	-I$(top_builddir)/rpc/xdr/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =

$(top_builddir)/libglusterfs/src/libglusterfs.la:
	$(MAKE) -C $(top_builddir)/libglusterfs/src/ all
