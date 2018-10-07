# in: PKGNAME
# in: FEATURES (optional)
# in: BUILD_INFO (optional)
# in: OPENSSL (optional)
# in: OPENSSL_FOUND (optional)
# in: SOURCE_DATE_EPOCH (optional)

ifndef PKGNAME
$(error PKGNAME not defined)
endif

ifndef OPENSSL
ifdef OPENSSL_FOUND
OPENSSL=	$(OPENSSL_FOUND)/bin/openssl
else
OPENSSL=	openssl
endif
endif

BASENAME?=	basename
CUT?=		cut
DATE?=		date
DIFF?=		diff
GIT?=		git
GREP?=		grep
RM?=		rm
SED?=		sed
SORT?=		sort
TR?=		tr
WC?=		wc

GITDIR:=	$(wildcard .git)
VERSION_FILE:=	$(wildcard VERSION)
HASHES_FILE:=	$(wildcard HASHES)
NEWS_FILE:=	$(firstword $(wildcard NEWS*))

ifdef GITDIR
BUILD_VERSION:=	$(shell $(GIT) describe --tags --dirty --always)
BUILD_INFO+=	V:GIT
else
ifdef VERSION_FILE
BUILD_VERSION:=	$(shell $(CAT) VERSION)
BUILD_INFO+=	V:FILE
else
BUILD_VERSION:=	$(shell $(BASENAME) $(PWD)|\
			$(GREP) $(PKGNAME)-|\
			$(SED) 's/.*$(PKGNAME)-\(.*\)/\1/g')
BUILD_INFO+=	V:DIR
endif
ifdef HASHES_FILE
BUILD_INFO+=	HDIFF:$(shell $(OPENSSL) dgst -sha1 -r *.[hc]|\
		$(SORT) -k 2 >HASHES~;\
		$(DIFF) -u HASHES HASHES~|\
		$(GREP) '^-[^-]'|$(WC) -l|$(TR) -d ' ';\
		$(RM) HASHES~)
endif
ifdef NEWS_FILE
NEWS_SHA:=	$(shell $(OPENSSL) dgst -sha1 -r $(NEWS_FILE) |\
			$(CUT) -c -7)
BUILD_INFO+=	N:$(NEWS_SHA)
endif
endif # GITDIR

ifdef SOURCE_DATE_EPOCH
BUILD_DATE:=	$(shell \
		$(DATE) -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null||\
		$(DATE) -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null||\
		$(DATE) -u "+%Y-%m-%d")
else
BUILD_DATE:=	$(shell date +%Y-%m-%d)
endif
BUILD_CPPFLAGS+=-D"BUILD_PKGNAME=\"$(PKGNAME)\"" \
		-D"BUILD_VERSION=\"$(BUILD_VERSION)\"" \
		-D"BUILD_DATE=\"$(BUILD_DATE)\"" \
		-D"BUILD_INFO=\"$(BUILD_INFO)\"" \
		-D"BUILD_FEATURES=\"$(FEATURES)\""

# out: NEWS_FILE
# out: NEWS_SHA
# out: VERSION_FILE
# out: GITDIR
# out: BUILD_VERSION
# out: BUILD_DATE
# out: BUILD_INFO
# out: BUILD_CPPFLAGS
