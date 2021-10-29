## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2021

###############################################################################
# File lists                                                                  #
###############################################################################

cpro_sources = msspi/src/msspi.cpp
cpro_headers = msspi/src/msspi.h

common_headers = common.h prototypes.h version.h $(cpro_headers)
common_sources = tls.c str.c file.c client.c log.c options.c protocol.c
common_sources += network.c resolver.c sthreads.c
common_sources += fd.c stunnel.c $(cpro_sources)
unix_sources = pty.c libwrap.c ui_unix.c
shared_sources = env.c
win32_gui_sources = ui_win_gui.c resources.h resources.rc
win32_gui_sources += stunnel.ico active.ico error.ico idle.ico
win32_cli_sources = ui_win_cli.c

###############################################################################
# Unix executables and shared library                                         #
###############################################################################

if IOS
frameworkdir=@prefix@/framework
framework_LTLIBRARIES = libstunnel_msspi.la
else #IOS
sbin_PROGRAMS = stunnel_msspi
endif #IOS

stunnel_msspi_SOURCES = $(common_headers) $(common_sources) $(unix_sources)
sbin_SCRIPTS = stunnel3

EXTRA_DIST = stunnel3.in
CLEANFILES = stunnel3

# Red Hat "by design" bug #82369
stunnel_msspi_CPPFLAGS = -I$(SYSROOT)/usr/kerberos/include

# Set ssl paths
if SOLARIS
if CSP_64
I_SSLDIR=-I$(SSLDIR)/include
L_SSLDIR=-L$(SSLDIR)/lib/amd64 -L$(SSLDIR)/lib/sparcv9
else # CSP_64
I_SSLDIR=-I$(SSLDIR)/include
L_SSLDIR=-L$(SSLDIR)/lib64 -L$(SSLDIR)/lib
endif # CSP_64
else # SOLARIS
# -----------------------------

if SSLDIR_SET
I_SSLDIR=-I$(SSLDIR)/include
L_SSLDIR=-L$(SSLDIR)/lib64 -L$(SSLDIR)/lib
else # SSLDIR_SET
I_SSLDIR=-I@abs_top_builddir@/../cp-openssl-1.1.0/include
L_SSLDIR=-L@abs_top_builddir@/../cp-openssl-1.1.0
endif # SSLDIR_SET
endif # SOLARIS

if E2K
stunnel_msspi_CPPFLAGS += -DSECURITY_DLL_NAME='"@libdir@/libssp.so"'
endif # E2K

# Additional preprocesor definitions
stunnel_msspi_CPPFLAGS += $(I_SSLDIR)
stunnel_msspi_CPPFLAGS += -DLIBDIR='"$(pkglibdir)"'
stunnel_msspi_CPPFLAGS += -DCONFDIR='"$(sysconfdir)/stunnel"'

# TLS library
stunnel_msspi_LDFLAGS = $(L_SSLDIR)

# stunnel3 script
edit = sed \
	-e 's|@bindir[@]|$(bindir)|g'
stunnel3: Makefile
	$(edit) '$(srcdir)/$@.in' >$@
stunnel3: $(srcdir)/stunnel3.in

if MSSPI
stunnel_msspi_LDADD = \
    @abs_top_builddir@/../../../reader/source/support/librdrsup.la \
    @abs_top_builddir@/../../../CSP/capilite/libcapi10.la \
    @abs_top_builddir@/../../../CSP/capilite/libcapi20.la

stunnel_msspi_CPPFLAGS += \
    -I@abs_top_srcdir@/../../../CSP/src/include

if USE_BOOST
stunnel_msspi_CPPFLAGS += \
    -I@abs_top_srcdir@/../../../shared/include
endif # USE_BOOST
endif # MSSPI

AM_LDFLAGS=
if SOLARIS
AM_LDFLAGS+=@LIBM@ -XCClinker -xnolib  -lc -lCstd -lCrun
endif # !SOLARIS

if DARWIN
AM_LDFLAGS+= -framework CoreFoundation
endif #DARWIN

# Unix shared library
if IOS
# pkglib_LTLIBRARIES = libstunnel-msspi.la
libstunnel_msspi_la_SOURCES = $(shared_sources)
libstunnel_msspi_la_LDFLAGS = -avoid-version
endif #IOS

###############################################################################
# Win32 executables                                                           #
###############################################################################

mingw:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_arch=win32 win32_targetcpu=i686 win32_mingw=mingw

mingw64:
	$(MAKE) -f $(srcdir)/mingw.mk srcdir=$(srcdir) win32_arch=win64 win32_targetcpu=x86_64 win32_mingw=mingw64

.PHONY: mingw mingw64

clean-local:
	rm -rf ../obj ../bin

# Remaining files to be included
EXTRA_DIST += $(win32_gui_sources) $(win32_cli_sources)
EXTRA_DIST += make.bat makece.bat makew32.bat
EXTRA_DIST += mingw.mk mingw.mak evc.mak vc.mak os2.mak
