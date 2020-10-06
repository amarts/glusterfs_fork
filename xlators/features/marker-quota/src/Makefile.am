xlator_LTLIBRARIES = marker-quota.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

marker_quota_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)

marker_quota_la_SOURCES = marker-quota.c
marker_quota_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la 

noinst_HEADERS = marker-quota.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES = 

uninstall-local:
	rm -f $(DESTDIR)$(xlatordir)/marker.so

install-data-hook:
	ln -sf marker-quota.so $(DESTDIR)$(xlatordir)/marker.so
