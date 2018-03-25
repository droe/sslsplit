# in: PKGNAME
# in: FEATURES (optional)
# in: BUILD_INFO (optional)

ifndef PKGNAME
$(error PKGNAME not defined)
endif

BASENAME?=	basename
CUT?=		cut
GIT?=		git
GREP?=		grep
OPENSSL?=	openssl
SED?=		sed

GITDIR:=	$(wildcard .git)
VERSION_FILE:=	$(wildcard VERSION)
NEWS_FILE:=	$(firstword $(wildcard NEWS*))

ifdef GITDIR
BUILD_VERSION:=	$(shell $(GIT) describe --tags --dirty --always)
BUILD_INFO+=	V:GIT
GITDIR:=
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
ifdef NEWS_FILE
NEWS_SHA:=	$(shell $(OPENSSL) dgst -sha1 -r $(NEWS_FILE) |\
			$(CUT) -c -7)
BUILD_INFO+=	N:$(NEWS_SHA)
endif
endif # GITDIR

BUILD_DATE:=	$(shell date +%Y-%m-%d)
BUILD_CPPFLAGS+=-D"BUILD_PKGNAME=\"$(PKGNAME)\"" \
		-D"BUILD_VERSION=\"$(BUILD_VERSION)\"" \
		-D"BUILD_DATE=\"$(BUILD_DATE)\"" \
		-D"BUILD_INFO=\"$(BUILD_INFO)\"" \
		-D"BUILD_FEATURES=\"$(FEATURES)\""

# out: NEWS_FILE
# out: NEWS_SHA
# out: VERSION_FILE
# out: BUILD_VERSION
# out: BUILD_DATE
# out: BUILD_INFO
# out: BUILD_CPPFLAGS
