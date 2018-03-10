# in: PKGNAME
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
NEWSSHA:=	$(shell $(OPENSSL) dgst -sha1 -r $(NEWS_FILE) |\
			$(CUT) -c -7)
BUILD_INFO+=	N:$(NEWSSHA)
NEWSSHA:=
endif
endif # GITDIR

BUILD_DATE:=	$(shell date +%Y-%m-%d)

# out: NEWS_FILE
# out: VERSION_FILE
# out: BUILD_DATE
# out: BUILD_VERSION
# out: BUILD_INFO
