/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "nat.h"

#include "log.h"
#include "attrib.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_PF
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef __APPLE__
#define PRIVATE
#endif /* __APPLE__ */
#include <net/pfvar.h>
#ifdef __APPLE__
#undef PRIVATE
#endif /* __APPLE__ */
#include <unistd.h>
#endif /* HAVE_PF */

#ifdef HAVE_IPFILTER
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netinet/ipl.h>
#include <netinet/ip_compat.h>
#include <netinet/ip_fil.h>
#include <netinet/ip_nat.h>
#endif /* HAVE_IPFILTER */

#ifdef HAVE_NETFILTER
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#endif /* HAVE_NETFILTER */


/*
 * Access NAT state tables in a NAT engine independant way.
 * Adding support for additional NAT engines should require only
 * changes in this file.
 */


/*
 * pf
 */

#ifdef HAVE_PF
static int nat_pf_fd = -1;

static int
nat_pf_preinit(void)
{
	nat_pf_fd = open("/dev/pf", O_RDONLY);
	if (nat_pf_fd < 0) {
		log_err_printf("Error opening '/dev/pf': %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}

static int
nat_pf_init(void)
{
	int rv;

	rv = fcntl(nat_pf_fd, F_SETFD, fcntl(nat_pf_fd, F_GETFD) | FD_CLOEXEC);
	if (rv == -1) {
		log_err_printf("Error setting FD_CLOEXEC on '/dev/pf': %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}

static void
nat_pf_fini(void)
{
	close(nat_pf_fd);
}

static int
nat_pf_lookup_cb(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                 evutil_socket_t s,
                 struct sockaddr *src_addr, UNUSED socklen_t src_addrlen)
{
#ifdef __APPLE__
#define sport sxport.port
#define dport dxport.port
#define rdport rdxport.port
#endif /* __APPLE__ */
	struct sockaddr_storage our_addr;
	socklen_t our_addrlen;
	struct pfioc_natlook nl;

	our_addrlen = sizeof(struct sockaddr_storage);
	if (getsockname(s, (struct sockaddr *)&our_addr, &our_addrlen) == -1) {
		log_err_printf("Error from getsockname(): %s\n",
		               strerror(errno));
		return -1;
	}

	memset(&nl, 0, sizeof(struct pfioc_natlook));
	nl.af = src_addr->sa_family;
	if (nl.af == AF_INET) {
		struct sockaddr_in *src_sai = (struct sockaddr_in *)src_addr;
		struct sockaddr_in *our_sai = (struct sockaddr_in *)&our_addr;
		nl.saddr.v4.s_addr = src_sai->sin_addr.s_addr;
		nl.sport = src_sai->sin_port;
		nl.daddr.v4.s_addr = our_sai->sin_addr.s_addr;
		nl.dport = our_sai->sin_port;
	}
	if (nl.af == AF_INET6) {
		struct sockaddr_in6 *src_sai = (struct sockaddr_in6 *)src_addr;
		struct sockaddr_in6 *our_sai = (struct sockaddr_in6 *)&our_addr;
		memcpy(&nl.saddr.v6.s6_addr, &src_sai->sin6_addr.s6_addr, 16);
		nl.sport = src_sai->sin6_port;
		memcpy(&nl.daddr.v6.s6_addr, &our_sai->sin6_addr.s6_addr, 16);
		nl.dport = our_sai->sin6_port;
	}
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;

	if (ioctl(nat_pf_fd, DIOCNATLOOK, &nl)) {
		if (errno != ENOENT) {
			log_err_printf("Error from ioctl(DIOCNATLOOK): %s\n",
			               strerror(errno));
		}
		return -1;
	}

	if ((nl.dport == nl.rdport) &&
	    ((nl.af == AF_INET && nl.daddr.v4.s_addr == nl.rdaddr.v4.s_addr) ||
	     (nl.af == AF_INET6 &&
	      !memcmp(nl.daddr.v6.s6_addr, nl.rdaddr.v6.s6_addr, 16)))) {
		/* no destination address/port translation in place */
		return -1;
	}

	/* copy original destination address */
	if (nl.af == AF_INET) {
		struct sockaddr_in *dst_sai = (struct sockaddr_in *)dst_addr;
		memset(dst_sai, 0, sizeof(struct sockaddr_in));
		dst_sai->sin_addr.s_addr = nl.rdaddr.v4.s_addr;
		dst_sai->sin_port = nl.rdport;
		dst_sai->sin_family = nl.af;
		*dst_addrlen = sizeof(struct sockaddr_in);
	}
	if (nl.af == AF_INET6) {
		struct sockaddr_in6 *dst_sai = (struct sockaddr_in6 *)dst_addr;
		memset(dst_sai, 0, sizeof(struct sockaddr_in6));
		memcpy(dst_sai->sin6_addr.s6_addr, nl.rdaddr.v6.s6_addr, 16);
		dst_sai->sin6_port = nl.rdport;
		dst_sai->sin6_family = nl.af;
		*dst_addrlen = sizeof(struct sockaddr_in6);
	}

	return 0;
#ifdef __APPLE__
#undef sport
#undef dport
#undef rdport
#endif /* __APPLE__ */
}
#endif /* HAVE_PF */


/*
 * ipfilter
 */

#ifdef HAVE_IPFILTER
static int nat_ipfilter_fd = -1;

static int
nat_ipfilter_preinit(void)
{
	nat_ipfilter_fd = open(IPNAT_NAME, O_RDONLY);
	if (nat_ipfilter_fd < 0) {
		log_err_printf("Error opening '%s': %s\n",
		               IPNAT_NAME, strerror(errno));
		return -1;
	}
	return 0;
}

static int
nat_ipfilter_init(void)
{
	int rv;

	rv = fcntl(nat_ipfilter_fd, F_SETFD,
	           fcntl(nat_ipfilter_fd, F_GETFD) | FD_CLOEXEC);
	if (rv == -1) {
		log_err_printf("Error setting FD_CLOEXEC on '%s': %s\n",
		               IPNAT_NAME, strerror(errno));
		return -1;
	}
	return 0;
}

static void
nat_ipfilter_fini(void)
{
	close(nat_ipfilter_fd);
}

static int
nat_ipfilter_lookup_cb(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                       evutil_socket_t s,
                       struct sockaddr *src_addr, UNUSED socklen_t src_addrlen)
{
	struct sockaddr_storage our_addr;
	socklen_t our_addrlen;
	struct natlookup nl;
	struct ipfobj ipfo;

	our_addrlen = sizeof(struct sockaddr_storage);
	if (getsockname(s, (struct sockaddr *)&our_addr, &our_addrlen) == -1) {
		log_err_printf("Error from getsockname(): %s\n",
		               strerror(errno));
		return -1;
	}

	memset(&nl, 0, sizeof(struct natlookup));
	if (src_addr->sa_family == AF_INET) {
		struct sockaddr_in *src_sai = (struct sockaddr_in *)src_addr;
		struct sockaddr_in *our_sai = (struct sockaddr_in *)&our_addr;
		nl.nl_outip.s_addr = src_sai->sin_addr.s_addr;
		nl.nl_outport = src_sai->sin_port;
		nl.nl_inip.s_addr = our_sai->sin_addr.s_addr;
		nl.nl_inport = our_sai->sin_port;
	} else {
		log_err_printf("The ipfilter NAT engine does not "
		               "support IPv6 state lookups\n");
		return -1;
	}
	nl.nl_flags = IPN_TCP;

	/* assuming IPv4 from here */

	memset(&ipfo, 0, sizeof(struct ipfobj));
	ipfo.ipfo_rev = IPFILTER_VERSION;
	ipfo.ipfo_size = sizeof(struct natlookup);
	ipfo.ipfo_ptr = &nl;
	ipfo.ipfo_type = IPFOBJ_NATLOOKUP;

	if (ioctl(nat_ipfilter_fd, SIOCGNATL, &ipfo) == -1) {
		if (errno != ESRCH) {
			log_err_printf("Error from ioctl(SIOCGNATL): %s\n",
			               strerror(errno));
		}
		return -1;
	}

	if ((nl.nl_inport == nl.nl_realport) &&
	    (nl.nl_inip.s_addr == nl.nl_realip.s_addr)) {
		/* no destination address/port translation in place */
		return -1;
	}

	/* copy original destination address */
	struct sockaddr_in *dst_sai = (struct sockaddr_in *)dst_addr;
	memset(dst_sai, 0, sizeof(struct sockaddr_in));
	dst_sai->sin_addr.s_addr = nl.nl_realip.s_addr;
	dst_sai->sin_port = nl.nl_realport;
	dst_sai->sin_family = AF_INET;
	*dst_addrlen = sizeof(struct sockaddr_in);
	return 0;
}
#endif /* HAVE_IPFILTER */


/*
 * netfilter, tproxy
 */

#ifdef HAVE_NETFILTER
/*
 * It seems that SO_ORIGINAL_DST only works for IPv4 and that there
 * is no IPv6 equivalent yet.  Someone please port pf to Linux...
 *
 * http://lists.netfilter.org/pipermail/netfilter/2007-July/069259.html
 *
 * It looks like TPROXY is the only way to go on Linux with IPv6.
 */
static int
nat_netfilter_lookup_cb(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                        evutil_socket_t s,
                        struct sockaddr *src_addr, UNUSED socklen_t src_addrlen)
{
	int rv;

	if (src_addr->sa_family != AF_INET) {
		log_err_printf("The netfilter NAT engine only "
		               "supports IPv4 state lookups\n");
		return -1;
	}

	rv = getsockopt(s, SOL_IP, SO_ORIGINAL_DST, dst_addr, dst_addrlen);
	if (rv == -1) {
		log_err_printf("Error from getsockopt(SO_ORIGINAL_DST): %s\n",
		               strerror(errno));
	}
	return rv;
}

#ifdef IP_TRANSPARENT
/*
 * Set the listening socket IP_TRANSPARENT.  This makes the Linux IP routing
 * stack omit the source address checks on output, which is needed for
 * Linux TPROXY transparent proxying support.
 */
static int
nat_iptransparent_socket_cb(evutil_socket_t s)
{
	int on = 1;
	int rv;

	rv = setsockopt(s, SOL_IP, IP_TRANSPARENT, (void*)&on, sizeof(on));
	if (rv == -1) {
		log_err_printf("Error from setsockopt(IP_TRANSPARENT): %s\n",
		               strerror(errno));
	}
	return rv;
}
#endif /* IP_TRANSPARENT */
#endif /* HAVE_NETFILTER */


/*
 * generic
 */

#if defined(HAVE_IPFW) || (defined(HAVE_NETFILTER) && defined(IP_TRANSPARENT))
/*
 * Generic getsockname based implementation.  This assumes that getsockname,
 * by kernel magic, gives us the original destination.
 */
static int
nat_getsockname_lookup_cb(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                          evutil_socket_t s,
                          UNUSED struct sockaddr *src_addr,
                          UNUSED socklen_t src_addrlen)
{
	if (getsockname(s, dst_addr, dst_addrlen) == -1) {
		log_err_printf("Error from getsockname(): %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}
#endif


/*
 * NAT engine glue code and API.
 */

typedef int (*nat_init_cb_t)(void);
typedef void (*nat_fini_cb_t)(void);

struct engine {
	const char *name;
	unsigned int ipv6 : 1;
	unsigned int used : 1;
	nat_init_cb_t preinitcb;
	nat_init_cb_t initcb;
	nat_fini_cb_t finicb;
	nat_lookup_cb_t lookupcb;
	nat_socket_cb_t socketcb;
};

struct engine engines[] = {
#ifdef HAVE_PF
	{
		"pf", 1, 0,
		nat_pf_preinit, nat_pf_init, nat_pf_fini,
		nat_pf_lookup_cb, NULL
	},
#endif /* HAVE_PF */
#ifdef HAVE_IPFW
	{
		"ipfw", 1, 0,
		NULL, NULL, NULL,
		nat_getsockname_lookup_cb, NULL
	},
#endif /* HAVE_IPFW */
#ifdef HAVE_IPFILTER
	{
		"ipfilter", 0, 0,
		nat_ipfilter_preinit, nat_ipfilter_init, nat_ipfilter_fini,
		nat_ipfilter_lookup_cb, NULL
	},
#endif /* HAVE_IPFILTER */
#ifdef HAVE_NETFILTER
	{
		"netfilter", 0, 0,
		NULL, NULL, NULL,
		nat_netfilter_lookup_cb, NULL
	},
#ifdef IP_TRANSPARENT
	{
		"tproxy", 1, 0,
		NULL, NULL, NULL,
		nat_getsockname_lookup_cb, nat_iptransparent_socket_cb
	},
#endif /* IP_TRANSPARENT */
#endif /* HAVE_NETFILTER */
	{
		NULL, 0, 0,
		NULL, NULL, NULL,
		NULL, NULL
	}
};


/*
 * Return the name of the default NAT engine.
 */
const char *
nat_getdefaultname(void)
{
	return engines[0].name;
}

/*
 * Look for a NAT engine in the table and return the index if found.
 * If there is no NAT engine with the given name, then the index of the
 * sentinel table entry is returned.
 */
static int
nat_index(const char *name)
{
	if (name)
		for (int i = 0; engines[i].name; i++)
			if (!strcmp(name, engines[i].name))
				return i;
	return ((sizeof(engines) / sizeof(struct engine)) - 1);
}

/*
 * Returns !=0 if the named NAT engine exists, 0 if it does not exist.
 * NULL refers to the default NAT engine.
 */
int
nat_exist(const char *name)
{
	if (!name)
		name = engines[0].name;
	return !!engines[nat_index(name)].name;
}

/*
 * Returns !=0 if the named NAT engine has been marked as used, 0 if not.
 * NULL refers to the default NAT engine.
 */
int
nat_used(const char *name)
{
	if (!name)
		name = engines[0].name;
	return !!engines[nat_index(name)].used;
}

/*
 * Returns the lookup callback of the named NAT engine and marks the NAT
 * engine as used.
 * NULL refers to the default NAT engine.
 */
nat_lookup_cb_t
nat_getlookupcb(const char *name)
{
	int i;

	if (!name)
		name = engines[0].name;
	i = nat_index(name);
	engines[i].used = 1;
	return engines[i].lookupcb;
}

/*
 * Returns the socket callback of the named NAT engine.
 * NULL refers to the default NAT engine.
 */
nat_socket_cb_t
nat_getsocketcb(const char *name)
{
	if (!name)
		name = engines[0].name;
	return engines[nat_index(name)].socketcb;
}

/*
 * Returns 1 if name is a NAT engine which supports IPv6.
 * NULL refers to the default NAT engine.
 */
int
nat_ipv6ready(const char *name)
{
	if (!name)
		name = engines[0].name;
	return engines[nat_index(name)].ipv6;
}

/*
 * List all available NAT engines to standard output and flush.
 */
void
nat_list_engines(void)
{
	for (int i = 0; engines[i].name; i++) {
		fprintf(stdout, "%s%s\n", engines[i].name,
		                          i ? "" : " (default)");
	}
	fflush(stdout);
}

/*
 * Pre-initialize all NAT engines which were marked as used by previous calls
 * to nat_getlookupcb().
 *
 * Privileged initialization under root privs, before dropping privs,
 * before calling daemon().  Here should be initialization which needs
 * to provide the user feedback on errors.  This includes opening
 * special device files, for which the user may not have sufficient privs.
 *
 * Returns -1 on failure, 0 on success.
 */
int
nat_preinit(void)
{
	for (int i = 0; engines[i].preinitcb && engines[i].used; i++) {
		log_dbg_printf("NAT engine preinit '%s'\n", engines[i].name);
		if (engines[i].preinitcb() == -1)
			return -1;
	}
	return 0;
}

/*
 * Initialize all NAT engines which were marked as used by previous calls to
 * nat_getlookupcb().
 *
 * Unprivileged initialization, possibly root, possibly nobody or service user.
 *
 * Returns -1 on failure, 0 on success.
 */
int
nat_init(void)
{
	for (int i = 0; engines[i].initcb && engines[i].used; i++) {
		log_dbg_printf("NAT engine init '%s'\n", engines[i].name);
		if (engines[i].initcb() == -1)
			return -1;
	}
	return 0;
}

/*
 * Cleanup all NAT engines which were marked as used by previous calls to
 * nat_getlookupcb().
 */
void
nat_fini(void)
{
	for (int i = 0; engines[i].finicb && engines[i].used; i++) {
		log_dbg_printf("NAT engine fini '%s'\n", engines[i].name);
		engines[i].finicb();
	}
}

/*
 * Print version and option availability to standard error.
 */
void
nat_version(void)
{
	fprintf(stderr, "NAT engines:");
	for (int i = 0; engines[i].name; i++) {
		fprintf(stderr, " %s%s", engines[i].name,
		                         i ? "" : "*");
	}
	if (!engines[0].name)
		fprintf(stderr, " -");
	fprintf(stderr, "\n");
#ifdef HAVE_IPFILTER
	fprintf(stderr, "ipfilter: version %d\n", IPFILTER_VERSION);
#endif /* HAVE_IPFILTER */
#ifdef HAVE_NETFILTER
	fprintf(stderr, "netfilter:");
#ifdef IP_TRANSPARENT
	fprintf(stderr, " IP_TRANSPARENT");
#else /* !IP_TRANSPARENT */
	fprintf(stderr, " !IP_TRANSPARENT");
#endif /* !IP_TRANSPARENT */
#ifdef SOL_IPV6
	fprintf(stderr, " SOL_IPV6");
#else /* !SOL_IPV6 */
	fprintf(stderr, " !SOL_IPV6");
#endif /* !SOL_IPV6 */
#ifdef IPV6_ORIGINAL_DST
	fprintf(stderr, " IPV6_ORIGINAL_DST");
#else /* !IPV6_ORIGINAL_DST */
	fprintf(stderr, " !IPV6_ORIGINAL_DST");
#endif /* !IPV6_ORIGINAL_DST */
	fprintf(stderr, "\n");
#endif /* HAVE_NETFILTER */
}

/* vim: set noet ft=c: */
