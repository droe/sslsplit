### Variable overrides

# You can change many aspects of the build behaviour without modifying this
# make file simply by setting environment variables.
#
# Dependencies and features are auto-detected, but can be overridden:
#
# OPENSSL_BASE	Prefix of OpenSSL library and headers to build against
# LIBEVENT_BASE	Prefix of libevent library and headers to build against
# LIBPCAP_BASE	Prefix of libpcap library and headers to build against
# LIBNET_BASE	Prefix of libnet library and headers to build against
# CHECK_BASE	Prefix of check library and headers to build against (optional)
# PKGCONFIG	Name/path of pkg-config program to use for auto-detection
# PCFLAGS	Additional pkg-config flags
# XNU_VERSION	Version of included XNU headers to build against (OS X only)
# FEATURES	Enable optional or force-enable undetected features (see below)
#
# Where and how to install to:
#
# PREFIX	Prefix to install under (default /usr/local)
# DESTDIR	Destination root under which prefix is located (default /)
# MANDIR	Subdir of PREFIX that contains man section dirs
# INSTALLUID	UID to use for installed files if installing as root
# INSTALLGID	GID to use for installed files if installing as root
#
# Standard compiler variables are respected, e.g.:
#
# CC		Compiler, e.g. for cross-compiling, ccache or ccc-analyzer
# CFLAGS	Additional compiler flags, e.g. optimization flags
# CPPFLAGS	Additional pre-processor flags
# LDFLAGS	Additional linker flags
# LIBS		Additional libraries to link against
# SOURCE_DATE_EPOCH	Set to epoch time to make the build reproducible
#
# On macOS, the following build environment variables are respected:
#
# DEVELOPER_DIR		Override Xcode Command Line Developer Tools directory
# MACOSX_VERSION_MIN	Minimal version of macOS to target, e.g. 10.11
# SDK			SDK name to build against, e.g. macosx, macosx10.11
#
# Examples:
#
# Build against custom installed libraries under /opt:
# % OPENSSL_BASE=/opt/openssl LIBEVENT_BASE=/opt/libevent make
#
# Create a statically linked binary:
# % PCFLAGS='--static' CFLAGS='-static' LDFLAGS='-static' make
#
# Build a macOS binary for El Capitan using the default SDK from Xcode 7.3.1:
# % MACOSX_VERSION_MIN=10.11 DEVELOPER_DIR=/Applications/Xcode-7.3.1.app/Contents/Developer make



### OpenSSL tweaking

# Define to enable support for SSLv2.
# Default since 0.4.9 is to disable SSLv2 entirely even if OpenSSL supports it,
# since there are servers that are not compatible with SSLv2 Client Hello
# messages.  If you build in SSLv2 support, you can disable it at runtime using
# -R ssl2 to get the same result as not building in SSLv2 support at all.
#FEATURES+=	-DWITH_SSLV2


### Debugging

# These flags are added to CFLAGS iff building from a git repo.
DEBUG_CFLAGS?=	-g
#DEBUG_CFLAGS+=	-Werror

# Define to remove false positives when debugging memory allocation.
# Note that you probably want to build OpenSSL with -DPURIFY too.
#FEATURES+=	-DPURIFY

# Define to add proxy state machine debugging; dump state in debug mode.
#FEATURES+=	-DDEBUG_PROXY

# Define to add certificate debugging; dump all certificates in debug mode.
#FEATURES+=	-DDEBUG_CERTIFICATE

# Define to add SSL session cache debugging; dump all sessions in debug mode.
#FEATURES+=	-DDEBUG_SESSION_CACHE

# Define to add debugging of sslsplit's own ClientHello message parser.
#FEATURES+=	-DDEBUG_CLIENTHELLO_PARSER

# Define to add thread debugging; dump thread state when choosing a thread.
#FEATURES+=	-DDEBUG_THREAD

# Define to add privilege separation server event loop debugging.
#FEATURES+=	-DDEBUG_PRIVSEP_SERVER

# When debugging OpenSSL related issues, make sure you use a debug build of
# OpenSSL and consider enabling its debugging options -DREF_PRINT -DREF_CHECK
# for debugging reference counting of OpenSSL objects and/or
# -DPURIFY for using valgrind and similar tools.


### Mac OS X header selection

# First, try to use the exact XNU version reported by the kernel.  If they
# are not available, try to look up a suitable XNU version that we have
# headers for based on the OS X release reported by sw_vers.  Then as a last
# resort, fall back to the latest version of XNU that we have headers for,
# which may or may not work, depending on if there were API or ABI changes
# in the DIOCNATLOOK ioctl interface to the NAT state table in the kernel.
#
# Note that you can override the XNU headers used by defining XNU_VERSION.

ifeq ($(shell uname),Darwin)
include Mk/xcode.mk
ifneq ($(wildcard /usr/include/libproc.h),)
FEATURES+=	-DHAVE_DARWIN_LIBPROC
endif
OSX_VERSION=	$(shell sw_vers -productVersion)
ifneq ($(XNU_VERSION),)
XNU_METHOD=	override
XNU_HAVE=	$(shell uname -a|sed 's/^.*root:xnu-//g'|sed 's/~.*$$//')
else
XNU_METHOD=	uname
XNU_VERSION=	$(shell uname -a|sed 's/^.*root:xnu-//g'|sed 's/~.*$$//')
XNU_HAVE:=	$(XNU_VERSION)
endif
ifeq ($(wildcard xnu/xnu-$(XNU_VERSION)),)
XNU_METHOD=	sw_vers
XNU_VERSION=	$(shell awk '/^XNU_RELS.*\# $(OSX_VERSION)$$/ {print $$2}' xnu/GNUmakefile)
endif
ifeq ($(wildcard xnu/xnu-$(XNU_VERSION)),)
XNU_METHOD=	fallback
XNU_VERSION=	$(shell awk '/^XNU_RELS/ {print $$2}' xnu/GNUmakefile|tail -1)
endif
ifneq ($(wildcard xnu/xnu-$(XNU_VERSION)),)
FEATURES+=	-DHAVE_PF
PKG_CPPFLAGS+=	-I./xnu/xnu-$(XNU_VERSION)
BUILD_INFO+=	OSX:$(OSX_VERSION) XNU:$(XNU_VERSION):$(XNU_METHOD):$(XNU_HAVE)
endif
endif


### Autodetected features

# Autodetect pf
ifneq ($(wildcard /usr/include/net/pfvar.h),)
FEATURES+=	-DHAVE_PF
# OpenBSD 4.7+ and FreeBSD 9.0+ also include ipfw-style divert-to in pf
FEATURES+=	-DHAVE_IPFW
endif

# Autodetect ipfw
ifneq ($(wildcard /sbin/ipfw),)
FEATURES+=	-DHAVE_IPFW
endif

# Autodetect ipfilter
ifneq ($(wildcard /usr/include/netinet/ip_fil.h),)
FEATURES+=	-DHAVE_IPFILTER
endif

# Autodetect netfilter
ifneq ($(wildcard /usr/include/linux/netfilter.h),)
FEATURES+=	-DHAVE_NETFILTER
endif


### Variables you might need to override

PREFIX?=	/usr/local
MANDIR?=	share/man

INSTALLUID?=	0
INSTALLGID?=	0
BINUID?=	$(INSTALLUID)
BINGID?=	$(INSTALLGID)
BINMODE?=	0755
MANUID?=	$(INSTALLUID)
MANGID?=	$(INSTALLGID)
MANMODE?=	0644
ifeq ($(shell id -u),0)
BINOWNERFLAGS?=	-o $(BINUID) -g $(BINGID)
MANOWNERFLAGS?=	-o $(MANUID) -g $(MANGID)
else
BINOWNERFLAGS?=	
MANOWNERFLAGS?=	
endif

OPENSSL?=	openssl
PKGCONFIG?=	$(shell command -v pkg-config||echo false)
ifeq ($(PKGCONFIG),false)
$(warning pkg-config not found - guessing paths/flags for dependencies)
endif

BASENAME?=	basename
CAT?=		cat
CHECKNR?=	checknr
CUT?=		cut
GREP?=		grep
INSTALL?=	install
MKDIR?=		mkdir
SED?=		sed
SORT?=		sort


### Variables only used for developer targets

KHASH_URL?=	https://github.com/attractivechaos/klib/raw/master/khash.h
GPGSIGNKEY?=	0xB5D3397E

CPPCHECK?=	cppcheck
GPG?=		gpg
GIT?=		git
WGET?=		wget
DOCKER?=	docker

BZIP2?=		bzip2
COL?=		col
LN?=		ln
MAN?=		man
TAR?=		tar


### You should not need to touch anything below this line

PKGLABEL:=	SSLsplit
PKGNAME:=	sslsplit
TARGET:=	$(PKGNAME)
SRCS:=		$(filter-out $(wildcard *.t.c),$(wildcard *.c))
HDRS:=		$(wildcard *.h)
OBJS:=		$(SRCS:.c=.o)
FEATURES:=	$(sort $(FEATURES))

TSRCS:=		$(wildcard *.t.c)
TOBJS:=		$(TSRCS:.t.c=.t.o)
TOBJS+=		$(filter-out main.o,$(OBJS))

include Mk/buildinfo.mk
VERSION:=	$(BUILD_VERSION)
ifdef GITDIR
CFLAGS+=	$(DEBUG_CFLAGS)
endif

# Autodetect dependencies known to pkg-config
PKGS:=		
ifndef OPENSSL_BASE
PKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists openssl \
		&& echo openssl)
endif
ifndef LIBEVENT_BASE
PKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists libevent \
		&& echo libevent)
PKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists libevent_openssl \
		&& echo libevent_openssl)
PKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists libevent_pthreads \
		&& echo libevent_pthreads)
endif
ifndef LIBPCAP_BASE
PKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists libpcap \
		&& echo libpcap)
endif
TPKGS:=		
ifndef CHECK_BASE
TPKGS+=		$(shell $(PKGCONFIG) $(PCFLAGS) --exists check \
		&& echo check)
endif

# Function: Generate list of base paths to search when locating packages
# $1 packagename
bases=		/usr/local/opt/$(1) \
		/opt/local \
		/usr/local \
		/usr

# Function: Locate base path for a package we depend on
# $1 packagename, $2 pattern suffix, $3 override path(s)
locate=		$(subst /$(2),,$(word 1,$(wildcard \
		$(addsuffix /$(2),$(if $(3),$(3),$(call bases,$(1)))))))

# Autodetect dependencies not known to pkg-config
ifeq (,$(filter openssl,$(PKGS)))
OPENSSL_FOUND:=	$(call locate,openssl,include/openssl/ssl.h,$(OPENSSL_BASE))
OPENSSL:=	$(OPENSSL_FOUND)/bin/openssl
ifndef OPENSSL_FOUND
$(error dependency 'OpenSSL' not found; \
	install it or point OPENSSL_BASE to base path)
endif
endif
ifeq (,$(filter libevent,$(PKGS)))
LIBEVENT_FOUND:=$(call locate,libevent,include/event2/event.h,$(LIBEVENT_BASE))
ifndef LIBEVENT_FOUND
$(error dependency 'libevent 2.x' not found; \
	install it or point LIBEVENT_BASE to base path)
endif
endif
ifeq (,$(filter libpcap,$(PKGS)))
LIBPCAP_FOUND:=	$(call locate,libpcap,include/pcap.h,$(LIBPCAP_BASE))
ifndef LIBPCAP_FOUND
$(error dependency 'libpcap' not found; \
	install it or point LIBPCAP_BASE to base path)
endif
endif
ifeq (,$(filter check,$(TPKGS)))
CHECK_FOUND:=	$(call locate,check,include/check.h,$(CHECK_BASE))
ifndef CHECK_FOUND
CHECK_MISSING:=	1
endif
endif

# Always search filesystem for libnet because libnet-config is unreliable
LIBNET_FOUND:=	$(call locate,libnet,include/libnet-1.1/libnet.h,$(LIBNET_BASE))
ifdef LIBNET_FOUND
LIBNET_FOUND_INC:=	$(LIBNET_FOUND)/include/libnet-1.1
else
LIBNET_FOUND:=	$(call locate,libnet,include/libnet.h,$(LIBNET_BASE))
LIBNET_FOUND_INC:=	$(LIBNET_FOUND)/include
endif
ifndef LIBNET_FOUND
$(error dependency 'libnet' not found; \
	install it or point LIBNET_BASE to base path)
endif

ifdef OPENSSL_FOUND
PKG_CPPFLAGS+=	-I$(OPENSSL_FOUND)/include
PKG_LDFLAGS+=	-L$(OPENSSL_FOUND)/lib
PKG_LIBS+=	-lssl -lcrypto -lz
endif
ifdef LIBEVENT_FOUND
PKG_CPPFLAGS+=	-I$(LIBEVENT_FOUND)/include
PKG_LDFLAGS+=	-L$(LIBEVENT_FOUND)/lib
PKG_LIBS+=	-levent
endif
ifeq (,$(filter libevent_openssl,$(PKGS)))
PKG_LIBS+=	-levent_openssl
endif
ifeq (,$(filter libevent_pthreads,$(PKGS)))
PKG_LIBS+=	-levent_pthreads
endif
ifdef LIBNET_FOUND
PKG_CPPFLAGS+=	-I$(LIBNET_FOUND_INC)
PKG_LDFLAGS+=	-L$(LIBNET_FOUND)/lib
PKG_LIBS+=	-lnet
endif
ifdef LIBPCAP_FOUND
PKG_CPPFLAGS+=	-I$(LIBPCAP_FOUND)/include
PKG_LDFLAGS+=	-L$(LIBPCAP_FOUND)/lib
PKG_LIBS+=	-lpcap
endif
ifdef CHECK_FOUND
TPKG_CPPFLAGS+=	-I$(CHECK_FOUND)/include
TPKG_LDFLAGS+=	-L$(CHECK_FOUND)/lib
TPKG_LIBS+=	-lcheck
endif

ifneq (,$(strip $(PKGS)))
PKG_CFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --cflags-only-other $(PKGS))
PKG_CPPFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --cflags-only-I $(PKGS))
PKG_LDFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --libs-only-L \
		--libs-only-other $(PKGS))
PKG_LIBS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --libs-only-l $(PKGS))
endif
ifneq (,$(strip $(TPKGS)))
TPKG_CFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --cflags-only-other $(TPKGS))
TPKG_CPPFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --cflags-only-I $(TPKGS))
TPKG_LDFLAGS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --libs-only-L \
		--libs-only-other $(TPKGS))
TPKG_LIBS+=	$(shell $(PKGCONFIG) $(PCFLAGS) --libs-only-l $(TPKGS))
endif

CPPDEFS+=	-D_GNU_SOURCE \
		-D"PKGLABEL=\"$(PKGLABEL)\""
CPPCHECKFLAGS+=	$(CPPDEFS)

ifneq (ccc-analyzer,$(notdir $(CC)))
PKG_CPPFLAGS:=	$(subst -I,-isystem,$(PKG_CPPFLAGS))
TPKG_CPPFLAGS:=	$(subst -I,-isystem,$(TPKG_CPPFLAGS))
endif

CFLAGS+=	$(PKG_CFLAGS) \
		-std=c99 -Wall -Wextra -pedantic \
		-D_FORTIFY_SOURCE=2 -fstack-protector-all
CPPFLAGS+=	$(PKG_CPPFLAGS) $(CPPDEFS) $(FEATURES)
TCPPFLAGS+=	$(TPKG_CPPFLAGS)
LDFLAGS+=	$(PKG_LDFLAGS)
LIBS+=		$(PKG_LIBS)

ifneq ($(shell uname),Darwin)
CFLAGS+=	-pthread
LDFLAGS+=	-pthread
endif

# _FORTIFY_SOURCE requires -O on Linux
ifeq ($(shell uname),Linux)
ifeq (,$(findstring -O,$(CFLAGS)))
CFLAGS+=	-O
endif
endif

export VERSION
export OPENSSL
export OPENSSL_BASE
export OPENSSL_FOUND
export MKDIR
export WGET

ifndef MAKE_RESTARTS
$(info ------------------------------------------------------------------------------)
$(info $(PKGLABEL) $(VERSION))
$(info ------------------------------------------------------------------------------)
$(info Report bugs at https://github.com/droe/sslsplit/issues/new)
$(info Please supply this header for diagnostics when reporting build issues)
$(info Before reporting bugs, make sure to try the latest develop branch first:)
$(info % git clone -b develop https://github.com/droe/sslsplit.git)
$(info ------------------------------------------------------------------------------)
$(info Via pkg-config: $(strip $(PKGS) $(TPKGS)))
ifdef OPENSSL_FOUND
$(info OPENSSL_BASE:   $(strip $(OPENSSL_FOUND)))
endif
ifdef LIBEVENT_FOUND
$(info LIBEVENT_BASE:  $(strip $(LIBEVENT_FOUND)))
endif
ifdef LIBPCAP_FOUND
$(info LIBPCAP_BASE:   $(strip $(LIBPCAP_FOUND)))
endif
ifdef LIBNET_FOUND
$(info LIBNET_BASE:    $(strip $(LIBNET_FOUND)))
endif
ifdef CHECK_FOUND
$(info CHECK_BASE:     $(strip $(CHECK_FOUND)))
endif
$(info Build options:  $(FEATURES))
$(info Build info:     $(BUILD_INFO))
ifeq ($(shell uname),Darwin)
$(info OSX_VERSION:    $(OSX_VERSION))
$(info XNU_VERSION:    $(XNU_VERSION) ($(XNU_METHOD), have $(XNU_HAVE)))
endif
$(info uname -a:       $(shell uname -a))
$(info ------------------------------------------------------------------------------)
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

build.o: CPPFLAGS+=$(BUILD_CPPFLAGS)
build.o: build.c FORCE

%.t.o: %.t.c $(HDRS) GNUmakefile
ifdef CHECK_MISSING
	$(error unit test dependency 'check' not found; \
	install it or point CHECK_BASE to base path)
endif
	$(CC) -c $(CPPFLAGS) $(TCPPFLAGS) $(CFLAGS) $(TPKG_CFLAGS) -o $@ \
		-x c $<

%.o: %.c $(HDRS) GNUmakefile
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

travis: TCPPFLAGS+=-DTRAVIS
travis: test

test: TCPPFLAGS+=-D"TEST_ZEROUSR=\"$(shell id -u -n root||echo 0)\""
test: TCPPFLAGS+=-D"TEST_ZEROGRP=\"$(shell id -g -n root||echo 0)\""
test: $(TARGET).test
	$(MAKE) -C extra/engine
	$(MAKE) -C extra/pki testreqs
	./$(TARGET).test

sudotest: test
	sudo ./$(TARGET).test

$(TARGET).test: $(TOBJS)
	$(CC) $(LDFLAGS) $(TPKG_LDFLAGS) -o $@ $^ $(LIBS) $(TPKG_LIBS)

clean:
	$(MAKE) -C extra/engine clean
	$(RM) -f $(TARGET) $(TARGET).test *.o .*.o *.core *~
	$(RM) -rf *.dSYM

install: $(TARGET)
	test -d $(DESTDIR)$(PREFIX)/bin || $(MKDIR) -p $(DESTDIR)$(PREFIX)/bin
	test -d $(DESTDIR)$(PREFIX)/$(MANDIR)/man1 || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	test -d $(DESTDIR)$(PREFIX)/$(MANDIR)/man5 || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man5
	$(INSTALL) $(BINOWNERFLAGS) -m $(BINMODE) \
		$(TARGET) $(DESTDIR)$(PREFIX)/bin/
	$(INSTALL) $(MANOWNERFLAGS) -m $(MANMODE) \
		$(TARGET).1 $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/
	$(INSTALL) $(MANOWNERFLAGS) -m $(MANMODE) \
		$(TARGET).conf.5 $(DESTDIR)$(PREFIX)/$(MANDIR)/man5/

deinstall:
	$(RM) -f $(DESTDIR)$(PREFIX)/bin/$(TARGET) $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/$(TARGET).1 \
		$(DESTDIR)$(PREFIX)/$(MANDIR)/man5/$(TARGET).conf.5

ifdef GITDIR
lint:
	$(CPPCHECK) $(CPPCHECKFLAGS) --force --enable=all --error-exitcode=1 .

manlint: $(TARGET).1
	$(CHECKNR) $(TARGET).1

mantest: $(TARGET).1
	$(RM) -f man1
	$(LN) -sf . man1
	$(MAN) -M . 1 $(TARGET)
	$(RM) man1

copyright: *.c *.h *.1 *.5 extra/*/*.c
	Mk/bin/copyright.py $^

$(PKGNAME)-$(VERSION).1.txt: $(TARGET).1
	$(RM) -f man1
	$(LN) -sf . man1
	$(MAN) -M . 1 $(TARGET) | $(COL) -b >$@
	$(RM) man1

man: $(PKGNAME)-$(VERSION).1.txt

manclean:
	$(RM) -f $(PKGNAME)-*.1.txt

fetchdeps:
	$(WGET) -O- $(KHASH_URL) >khash.h
	#$(RM) -rf xnu/xnu-*
	$(MAKE) -C xnu fetch

dist: $(PKGNAME)-$(VERSION).tar.bz2 $(PKGNAME)-$(VERSION).tar.bz2.asc

%.asc: %
	$(GPG) -u $(GPGSIGNKEY) --armor --output $@ --detach-sig $<

$(PKGNAME)-$(VERSION).tar.bz2:
	$(MKDIR) -p $(PKGNAME)-$(VERSION)
	echo $(VERSION) >$(PKGNAME)-$(VERSION)/VERSION
	$(OPENSSL) dgst -sha1 -r *.[hc] | $(SORT) -k 2 \
		>$(PKGNAME)-$(VERSION)/HASHES
	$(GIT) archive --prefix=$(PKGNAME)-$(VERSION)/ HEAD \
		>$(PKGNAME)-$(VERSION).tar
	$(TAR) -f $(PKGNAME)-$(VERSION).tar -r $(PKGNAME)-$(VERSION)/VERSION
	$(TAR) -f $(PKGNAME)-$(VERSION).tar -r $(PKGNAME)-$(VERSION)/HASHES
	$(BZIP2) <$(PKGNAME)-$(VERSION).tar >$(PKGNAME)-$(VERSION).tar.bz2
	$(RM) $(PKGNAME)-$(VERSION).tar
	$(RM) -r $(PKGNAME)-$(VERSION)

disttest: $(PKGNAME)-$(VERSION).tar.bz2 $(PKGNAME)-$(VERSION).tar.bz2.asc
	$(GPG) --verify $<.asc $<
	$(BZIP2) -d < $< | $(TAR) -x -f -
	cd $(PKGNAME)-$(VERSION) && $(MAKE) && $(MAKE) test && ./$(TARGET) -V
	$(RM) -r $(PKGNAME)-$(VERSION)

distclean:
	$(RM) -f $(PKGNAME)-*.tar.bz2*

realclean: distclean manclean clean
	$(MAKE) -C extra/pki clean
endif

docker:
	$(DOCKER) build -f docker/sslsplit/Dockerfile --target builder -t sslsplit-builder:$(VERSION) .
	$(DOCKER) build -f docker/sslsplit/Dockerfile --target production -t sslsplit:$(VERSION) .
	$(DOCKER) run sslsplit:$(VERSION)

FORCE:

.PHONY: all config clean test travis lint install deinstall copyright manlint \
        mantest man manclean fetchdeps dist disttest distclean realclean \
        docker

