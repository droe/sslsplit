### OpenSSL tweaking

# Define to enable support for SSLv2.
# Default since 0.4.9 is to disable SSLv2 entirely, since there are servers
# that are not compatible with SSLv2 Client Hello messages.  If you build in
# SSLv2 support, you can disable it at runtime using -R ssl2 to get the same
# result as not building in SSLv2 support at all.
#FEATURES+=	-DWITH_SSLV2

# Define to make SSLsplit set a session id context in server mode.
#FEATURES+=	-DUSE_SSL_SESSION_ID_CONTEXT


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

# Define to add debugging of parsing the SNI from the SSL ClientHello.
#FEATURES+=	-DDEBUG_SNI_PARSER

# Define to add thread debugging; dump thread state when choosing a thread.
#FEATURES+=	-DDEBUG_THREAD

# When debugging OpenSSL related issues, make sure you use a debug build of
# OpenSSL and consider enabling its debugging options -DREF_PRINT -DREF_CHECK
# for debugging reference counting of OpenSSL objects and/or
# -DPURIFY for using valgrind and similar tools.


### Mac OS X header selection

# First, try to use the exact XNU version reported by the kernel.  If they
# are not available, try to look up a suitable XNU version that we have
# headers for based on the OS X release reported by sw_vers.  Then as a last
# resort, fall back to the latest version of XNU that we have headers for,
# which may or may not work, depending on if there were significant changes
# in the DIOCNATLOOK ioctl interface to the NAT state table in the kernel.

ifeq ($(shell uname),Darwin)
ifneq ($(wildcard /usr/include/libproc.h),)
FEATURES+=	-DHAVE_DARWIN_LIBPROC
endif
XNU_VERSION?=	$(shell uname -a|sed 's/^.*root:xnu-//g'|sed 's/~.*$$//')
OSX_VERSION?=	$(shell sw_vers -productVersion)
XNU_METHOD=	uname
XNU_HAVE:=	$(XNU_VERSION)
ifeq ($(wildcard xnu/xnu-$(XNU_VERSION)),)
XNU_VERSION=	$(shell awk '/\# $(OSX_VERSION)$$/ {print $$2}' xnu/GNUmakefile)
XNU_METHOD=	sw_vers
endif
ifeq ($(wildcard xnu/xnu-$(XNU_VERSION)),)
XNU_VERSION=	$(shell awk '/^XNU_RELS/ {print $$2}' xnu/GNUmakefile|tail -1)
XNU_METHOD=	fallback
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

OPENSSL?=	openssl
PKGCONFIG?=	pkg-config

BASENAME?=	basename
CAT?=		cat
GREP?=		grep
INSTALL?=	install
MKDIR?=		mkdir
SED?=		sed


### Variables only used for developer targets

KHASH_URL?=	https://github.com/attractivechaos/klib/raw/master/khash.h
GPGSIGNKEY?=	0xB5D3397E

CPPCHECK?=	cppcheck
GPG?=		gpg
GIT?=		git
WGET?=		wget

BZIP2?=		bzip2
COL?=		col
LN?=		ln
MAN?=		man
TAR?=		tar


### You should not need to touch anything below this line

TARGET:=	sslsplit
PNAME:=		SSLsplit
SRCS:=		$(filter-out $(wildcard *.t.c),$(wildcard *.c))
HDRS:=		$(wildcard *.h)
OBJS:=		$(SRCS:.c=.o)

TSRCS:=		$(wildcard *.t.c)
TOBJS:=		$(TSRCS:.t.c=.t.o)
TOBJS+=		$(filter-out main.o,$(OBJS))

VFILE:=		$(wildcard VERSION)
GITDIR:=	$(wildcard .git)
ifdef VFILE
VERSION:=	$(shell $(CAT) VERSION)
BUILD_INFO+=	V:FILE
else
ifndef GITDIR
VERSION:=	$(shell $(BASENAME) $(PWD)|\
			$(GREP) $(TARGET)-|\
			$(SED) 's/.*$(TARGET)-\(.*\)/\1/g')
BUILD_INFO+=	V:DIR
else
VERSION:=	$(shell $(GIT) describe --tags --dirty --always)
BUILD_INFO+=	V:GIT
endif
CFLAGS+=	$(DEBUG_CFLAGS)
endif
BUILD_DATE:=	$(shell date +%Y-%m-%d)

# Autodetect dependencies known to pkg-config
PKGS:=		
ifndef OPENSSL_BASE
PKGS+=		$(shell $(PKGCONFIG) --exists openssl && echo openssl)
endif
ifndef LIBEVENT_BASE
PKGS+=		$(shell $(PKGCONFIG) --exists libevent && echo libevent)
PKGS+=		$(shell $(PKGCONFIG) --exists libevent_openssl \
		&& echo libevent_openssl)
PKGS+=		$(shell $(PKGCONFIG) --exists libevent_pthreads \
		&& echo libevent_pthreads)
endif
TPKGS:=		
ifndef CHECK_BASE
TPKGS+=		$(shell $(PKGCONFIG) --exists check && echo check)
endif

# Autodetect dependencies not known to pkg-config
ifeq (,$(filter openssl,$(PKGS)))
OPENSSL_PAT:=	include/openssl/ssl.h
ifdef OPENSSL_BASE
OPENSSL_FIND:=	$(wildcard $(OPENSSL_BASE)/$(OPENSSL_PAT))
else
OPENSSL_FIND:=	$(wildcard \
		/opt/local/$(OPENSSL_PAT) \
		/usr/local/$(OPENSSL_PAT) \
		/usr/$(OPENSSL_PAT))
endif
OPENSSL_FOUND:=	$(OPENSSL_FIND:/$(OPENSSL_PAT)=)
ifndef OPENSSL_FOUND
$(error dependency 'OpenSSL' not found; \
	install it or point OPENSSL_BASE to base path)
endif
endif
ifeq (,$(filter libevent,$(PKGS)))
LIBEVENT_PAT:=	include/event2/event.h
ifdef LIBEVENT_BASE
LIBEVENT_FIND:=	$(wildcard $(LIBEVENT_BASE)/$(LIBEVENT_PAT))
else
LIBEVENT_FIND:=	$(wildcard \
		/opt/local/$(LIBEVENT_PAT) \
		/usr/local/$(LIBEVENT_PAT) \
		/usr/$(LIBEVENT_PAT))
endif
LIBEVENT_FOUND:=$(LIBEVENT_FIND:/$(LIBEVENT_PAT)=)
ifndef LIBEVENT_FOUND
$(error dependency 'libevent 2.x' not found; \
	install it or point LIBEVENT_BASE to base path)
endif
endif
ifeq (,$(filter check,$(TPKGS)))
CHECK_PAT:=	include/check.h
ifdef CHECK_BASE
CHECK_FIND:=	$(wildcard $(CHECK_BASE)/$(CHECK_PAT))
else
CHECK_FIND:=	$(wildcard \
		/opt/local/$(CHECK_PAT) \
		/usr/local/$(CHECK_PAT) \
		/usr/$(CHECK_PAT))
endif
CHECK_FOUND:=	$(CHECK_FIND:/$(CHECK_PAT)=)
ifndef CHECK_FOUND
CHECK_MISSING:=	1
endif
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
ifdef CHECK_FOUND
TPKG_CPPFLAGS+=	-I$(CHECK_FOUND)/include
TPKG_LDFLAGS+=	-L$(CHECK_FOUND)/lib
TPKG_LIBS+=	-lcheck
endif

ifneq (,$(strip $(PKGS)))
PKG_CFLAGS+=	$(shell $(PKGCONFIG) --cflags-only-other $(PKGS))
PKG_CPPFLAGS+=	$(shell $(PKGCONFIG) --cflags-only-I $(PKGS))
PKG_LDFLAGS+=	$(shell $(PKGCONFIG) --libs-only-L --libs-only-other $(PKGS))
PKG_LIBS+=	$(shell $(PKGCONFIG) --libs-only-l $(PKGS))
endif
ifneq (,$(strip $(TPKGS)))
TPKG_CFLAGS+=	$(shell $(PKGCONFIG) --cflags-only-other $(TPKGS))
TPKG_CPPFLAGS+=	$(shell $(PKGCONFIG) --cflags-only-I $(TPKGS))
TPKG_LDFLAGS+=	$(shell $(PKGCONFIG) --libs-only-L --libs-only-other $(TPKGS))
TPKG_LIBS+=	$(shell $(PKGCONFIG) --libs-only-l $(TPKGS))
endif

CPPDEFS+=	-D_GNU_SOURCE \
		-D"BNAME=\"$(TARGET)\"" -D"PNAME=\"$(PNAME)\"" \
		-D"VERSION=\"$(VERSION)\"" -D"BUILD_DATE=\"$(BUILD_DATE)\"" \
		-D"FEATURES=\"$(FEATURES)\"" -D"BUILD_INFO=\"$(BUILD_INFO)\""
CPPCHECKFLAGS+=	$(CPPDEFS)
FEATURES:=	$(sort $(FEATURES))

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

export VERSION
export OPENSSL
export MKDIR
export WGET

all: version config $(TARGET)

version:
	@echo "$(PNAME) $(VERSION)"

config:
	@echo "via pkg-config: $(strip $(PKGS) $(TPKGS))"
ifdef OPENSSL_FOUND
	@echo "OPENSSL_BASE:   $(strip $(OPENSSL_FOUND))"
endif
ifdef LIBEVENT_FOUND
	@echo "LIBEVENT_BASE:  $(strip $(LIBEVENT_FOUND))"
endif
ifdef CHECK_FOUND
	@echo "CHECK_BASE:     $(strip $(CHECK_FOUND))"
endif
	@echo "Build options:  $(FEATURES)"
ifeq ($(shell uname),Darwin)
	@echo "OSX_VERSION:    $(OSX_VERSION)"
	@echo "XNU_VERSION:    $(XNU_VERSION) ($(XNU_METHOD), have $(XNU_HAVE))"
endif

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

version.o: version.c version.h GNUmakefile $(VFILE) FORCE

%.t.o: %.t.c $(HDRS) GNUmakefile
ifdef CHECK_MISSING
	$(error unit test dependency 'check' not found; \
	install it or point CHECK_BASE to base path)
endif
	$(CC) -c $(CPPFLAGS) $(TCPPFLAGS) $(CFLAGS) $(TPKG_CFLAGS) -o $@ \
		-x c $<

%.o: %.c $(HDRS) GNUmakefile
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

test: TCPPFLAGS+=-D"TEST_ZEROUSR=\"$(shell id -u -n root||echo 0)\""
test: TCPPFLAGS+=-D"TEST_ZEROGRP=\"$(shell id -g -n root||echo 0)\""
test: $(TARGET).test
	$(RM) extra/pki/session.pem
	$(MAKE) -C extra/pki testreqs session
	./$(TARGET).test

$(TARGET).test: $(TOBJS)
	$(CC) $(LDFLAGS) $(TPKG_LDFLAGS) -o $@ $^ $(LIBS) $(TPKG_LIBS)

clean:
	$(RM) -f $(TARGET) $(TARGET).test *.o .*.o *.core *~
	$(RM) -rf *.dSYM

install: $(TARGET)
	test -d $(DESTDIR)$(PREFIX)/bin || $(MKDIR) -p $(DESTDIR)$(PREFIX)/bin
	test -d $(DESTDIR)$(PREFIX)/$(MANDIR)/man1 || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	$(INSTALL) -o 0 -g 0 -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	$(INSTALL) -o 0 -g 0 -m 0644 $(TARGET).1 $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/

deinstall:
	$(RM) -f $(DESTDIR)$(PREFIX)/bin/$(TARGET) $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/$(TARGET).1

ifdef GITDIR
lint:
	$(CPPCHECK) $(CPPCHECKFLAGS) --force --enable=all --error-exitcode=1 .

mantest:
	$(RM) -f man1
	$(LN) -sf . man1
	$(MAN) -M . 1 $(TARGET)
	$(RM) man1

$(TARGET)-$(VERSION).1.txt: $(TARGET).1
	$(RM) -f man1
	$(LN) -sf . man1
	$(MAN) -M . 1 $(TARGET) | $(COL) -b >$@
	$(RM) man1

man: $(TARGET)-$(VERSION).1.txt

manclean:
	$(RM) -f $(TARGET)-*.1.txt

fetchdeps:
	$(WGET) -O- $(KHASH_URL) >khash.h
	#$(RM) -rf xnu/xnu-*
	$(MAKE) -C xnu fetch

dist: $(TARGET)-$(VERSION).tar.bz2 $(TARGET)-$(VERSION).tar.bz2.asc

%.asc: %
	$(GPG) -u $(GPGSIGNKEY) --armor --output $@ --detach-sig $<

$(TARGET)-$(VERSION).tar.bz2:
	$(MKDIR) -p $(TARGET)-$(VERSION)
	echo $(VERSION) >$(TARGET)-$(VERSION)/VERSION
	$(GIT) archive --prefix=$(TARGET)-$(VERSION)/ HEAD \
		>$(TARGET)-$(VERSION).tar
	$(TAR) -f $(TARGET)-$(VERSION).tar -r $(TARGET)-$(VERSION)/VERSION
	$(BZIP2) <$(TARGET)-$(VERSION).tar >$(TARGET)-$(VERSION).tar.bz2
	$(RM) $(TARGET)-$(VERSION).tar
	$(RM) -r $(TARGET)-$(VERSION)

disttest: $(TARGET)-$(VERSION).tar.bz2 $(TARGET)-$(VERSION).tar.bz2.asc
	$(GPG) --verify $<.asc $<
	$(BZIP2) -d < $< | $(TAR) -x -f -
	cd $(TARGET)-$(VERSION) && $(MAKE) && $(MAKE) test && ./$(TARGET) -V
	$(RM) -r $(TARGET)-$(VERSION)

distclean:
	$(RM) -f $(TARGET)-*.tar.bz2*

realclean: distclean manclean clean
	$(MAKE) -C extra/pki clean
endif

FORCE:

.PHONY: all config clean test lint install deinstall \
        mantest man manclean fetchdeps dist disttest distclean realclean

