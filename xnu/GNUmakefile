# inherited
VERSION?=	unknown
MKDIR?=		mkdir
WGET?=		wget

# All the xnu releases which contain bsd/net/pfvar.h
# Commented out are releases where the xnu version is known but the
# corresponding source code has not been published by Apple yet.
# If there were no API or ABI changes to the pf ioctl interface,
# falling back to the latest published version should work fine.

# Mac OS X Snow Leopard
XNU_RELS+=	1456.1.26	# 10.6
XNU_RELS+=	1456.1.26	# 10.6.1
XNU_RELS+=	1486.2.11	# 10.6.2
XNU_RELS+=	1504.3.12	# 10.6.3
XNU_RELS+=	1504.7.4	# 10.6.4
XNU_RELS+=	1504.9.17	# 10.6.5
XNU_RELS+=	1504.9.26	# 10.6.6
XNU_RELS+=	1504.9.37	# 10.6.7
XNU_RELS+=	1504.15.3	# 10.6.8

# Mac OS X Lion
XNU_RELS+=	1699.22.73	# 10.7
XNU_RELS+=	1699.22.81	# 10.7.1
XNU_RELS+=	1699.24.8	# 10.7.2
XNU_RELS+=	1699.24.23	# 10.7.3
XNU_RELS+=	1699.26.8	# 10.7.4
XNU_RELS+=	1699.32.7	# 10.7.5

# OS X Mountain Lion
XNU_RELS+=	2050.7.9	# 10.8
XNU_RELS+=	2050.9.2	# 10.8.1
XNU_RELS+=	2050.18.24	# 10.8.2
XNU_RELS+=	2050.22.13	# 10.8.3
XNU_RELS+=	2050.24.15	# 10.8.4
XNU_RELS+=	2050.48.11	# 10.8.5

# OS X Mavericks
XNU_RELS+=	2422.1.72	# 10.9
XNU_RELS+=	2422.1.72	# 10.9.1
XNU_RELS+=	2422.90.20	# 10.9.2
XNU_RELS+=	2422.100.13	# 10.9.3
XNU_RELS+=	2422.110.17	# 10.9.4
XNU_RELS+=	2422.115.4	# 10.9.5

# OS X Yosemite
XNU_RELS+=	2782.1.97	# 10.10
XNU_RELS+=	2782.1.97	# 10.10.1
XNU_RELS+=	2782.10.72	# 10.10.2
XNU_RELS+=	2782.20.48	# 10.10.3
XNU_RELS+=	2782.30.5	# 10.10.4
XNU_RELS+=	2782.40.9	# 10.10.5

# OS X El Capitan
XNU_RELS+=	3247.1.106	# 10.11
XNU_RELS+=	3247.10.11	# 10.11.1
XNU_RELS+=	3248.20.55	# 10.11.2
XNU_RELS+=	3248.30.4	# 10.11.3
XNU_RELS+=	3248.40.184	# 10.11.4
XNU_RELS+=	3248.50.21	# 10.11.5
XNU_RELS+=	3248.60.10	# 10.11.6

# macOS Sierra
XNU_RELS+=	3789.1.32	# 10.12
XNU_RELS+=	3789.21.4	# 10.12.1
XNU_RELS+=	3789.31.2	# 10.12.2
XNU_RELS+=	3789.41.3	# 10.12.3
XNU_RELS+=	3789.51.2	# 10.12.4
XNU_RELS+=	3789.60.24	# 10.12.5
XNU_RELS+=	3789.70.16	# 10.12.6

# macOS High Sierra
XNU_RELS+=	4570.1.46	# 10.13
XNU_RELS+=	4570.20.62	# 10.13.1
XNU_RELS+=	4570.31.3	# 10.13.2
XNU_RELS+=	4570.41.2	# 10.13.3
XNU_RELS+=	4570.51.1	# 10.13.4
XNU_RELS+=	4570.61.1	# 10.13.5
XNU_RELS+=	4570.71.2	# 10.13.6

# macOS Mojave
#XNU_RELS+=	4903.201.2	# 10.14         # "coming soon!"
XNU_RELS+=	4903.221.2	# 10.14.1
XNU_RELS+=	4903.231.4	# 10.14.2
XNU_RELS+=	4903.241.1	# 10.14.3
#XNU_RELS+=	4903.251.3	# 10.14.4       # "coming soon!"
#XNU_RELS+=	4903.261.4	# 10.14.5       # "coming soon!"

# macOS Catalina

# defaults
XNURL?=		https://opensource.apple.com/source/xnu/
XNU_IDIRS?=	libkern net
XNU_FILES?=	APPLE_LICENSE \
		libkern/libkern/tree.h bsd/net/radix.h bsd/net/pfvar.h

all: fetch

fetch: $(foreach ver,$(sort $(XNU_RELS)),xnu-$(ver))

xnu-%:
	$(MKDIR) -p $@ $(foreach dir,$(XNU_IDIRS),$@/$(dir))
	for f in $(XNU_FILES); do \
		ff=`echo "$$f"|sed 's/^[^/]*\///'`; \
		$(WGET) -O- $(XNURL)$@/$$f?txt >$@/$$ff; \
		done

xnu-1456.%: XNU_IDIRS=sys net
xnu-1456.%: XNU_FILES=APPLE_LICENSE bsd/sys/tree.h bsd/net/radix.h bsd/net/pfvar.h

xnu-1486.%: XNU_IDIRS=sys net
xnu-1486.%: XNU_FILES=APPLE_LICENSE bsd/sys/tree.h bsd/net/radix.h bsd/net/pfvar.h

xnu-1504.%: XNU_IDIRS=sys net
xnu-1504.%: XNU_FILES=APPLE_LICENSE bsd/sys/tree.h bsd/net/radix.h bsd/net/pfvar.h

