UNAME_S:=	$(shell uname -s)

ifdef OPENSSL_FOUND
OPENSSL_BASE=	$(OPENSSL_FOUND)
else
ifndef OPENSSL_BASE
OPENSSL_BASE=	$(shell pkg-config --variable=prefix openssl)
endif
endif

ifeq ($(UNAME_S),Darwin)
SUFFIX:=	dylib
#CFLAGS+=	-arch i386
CFLAGS+=	-arch x86_64
else
SUFFIX:=	so
endif

CFLAGS+=	-fPIC -I$(OPENSSL_BASE)/include
LDFLAGS+=	-L$(OPENSSL_BASE)/lib
LIBS+=		-lcrypto

TARGET=		dummy-engine

all: $(TARGET).$(SUFFIX)

$(TARGET).$(SUFFIX): $(TARGET).c GNUmakefile
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET).$(SUFFIX)

.PHONY: all clean
