# inherited
VERSION?=	unknown
MKDIR?=		mkdir
WGET?=		wget

# xnu
XNURL?=		https://opensource.apple.com/source/xnu/
XNU_IDIRS?=	libkern net
XNU_FILES?=	APPLE_LICENSE \
		libkern/libkern/tree.h bsd/net/radix.h bsd/net/pfvar.h

# All the xnu releases which contain bsd/net/pfvar.h
XNU_RELS+=	1456.1.26	# 10.6
XNU_RELS+=	1456.1.26	# 10.6.1
XNU_RELS+=	1486.2.11	# 10.6.2
XNU_RELS+=	1504.3.12	# 10.6.3
XNU_RELS+=	1504.7.4	# 10.6.4
XNU_RELS+=	1504.9.17	# 10.6.5
XNU_RELS+=	1504.9.26	# 10.6.6
XNU_RELS+=	1504.9.37	# 10.6.7
XNU_RELS+=	1504.15.3	# 10.6.8
XNU_RELS+=	1699.22.73	# 10.7
XNU_RELS+=	1699.22.81	# 10.7.1
XNU_RELS+=	1699.24.8	# 10.7.2
XNU_RELS+=	1699.24.23	# 10.7.3
XNU_RELS+=	1699.26.8	# 10.7.4
XNU_RELS+=	1699.32.7	# 10.7.5
XNU_RELS+=	2050.7.9	# 10.8
XNU_RELS+=	2050.9.2	# 10.8.1
XNU_RELS+=	2050.18.24	# 10.8.2
XNU_RELS+=	2050.22.13	# 10.8.3
XNU_RELS+=	2050.24.15	# 10.8.4
XNU_RELS+=	2050.48.11	# 10.8.5
XNU_RELS+=	2422.1.72	# 10.9
XNU_RELS+=	2422.1.72	# 10.9.1
XNU_RELS+=	2422.90.20	# 10.9.2
XNU_RELS+=	2422.100.13	# 10.9.3
XNU_RELS+=	2422.110.17	# 10.9.4
XNU_RELS+=	2422.115.4	# 10.9.5
XNU_RELS+=	2782.1.97	# 10.10
XNU_RELS+=	2782.1.97	# 10.10.1

all: fetch

fetch: $(foreach ver,$(sort $(XNU_RELS)),xnu-$(ver))

xnu-%:
	$(MKDIR) -p $@ $(foreach dir,$(XNU_IDIRS),$@/$(dir))
	for f in $(XNU_FILES); do \
		ff=`echo "$$f"|sed 's/^[^/]*\///'`; \
		$(WGET) -O- $(XNURL)$@/$$f?txt >$@/$$ff; \
		done

