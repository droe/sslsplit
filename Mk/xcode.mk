# macOS Xcode and SDK selection makefile
# Authored 2018, Daniel Roethlisberger
# Provided under the Unlicense
# https://github.com/droe/example.kext

# DEVELOPER_DIR   override Xcode Command Line Developer Tools directory
# MACOSX_VERSION_MIN  minimal version of macOS to target, e.g. 10.11
# SDK             SDK name to build against (e.g. macosx, macosx10.11, ...);
#                 for kernel extensions, use macosx$(MACOSX_VERSION_MIN)

# target specific macOS min version
ifdef MACOSX_VERSION_MIN
CFLAGS+=	-mmacosx-version-min=$(MACOSX_VERSION_MIN)
LDFLAGS+=	-mmacosx-version-min=$(MACOSX_VERSION_MIN)
endif

# select specific Xcode
ifdef DEVELOPER_DIR
ifndef SDK
SDK:=		macosx
endif
else
DEVELOPER_DIR:=	$(shell xcode-select -p)
endif

# activate the selected Xcode and SDK
ifdef SDK
SDKPATH:=	$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) --show-sdk-path||echo none)
ifeq "$(SDKPATH)" "none"
$(error SDK not found)
endif
CPPFLAGS+=	-isysroot $(SDKPATH)
LDFLAGS+=	-isysroot $(SDKPATH)
CC:=		$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) cc||echo false)
CXX:=		$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) c++||echo false)
CODESIGN:=	$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) codesign||echo false)
else
CC?=		cc
CXX?=		c++
CODESIGN?=	codesign
endif

