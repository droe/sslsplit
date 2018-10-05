/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "logpkt.h"

#include "sys.h"
#include "log.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <errno.h>

#if defined(__OpenBSD__) && !defined(ETHERTYPE_IPV6)
#include <net/ethertypes.h>
#endif /* __OpenBSD__ && !ETHERTYPE_IPV6 */

#define MSS_VAL 1420

typedef struct __attribute__((packed)) {
	uint32_t magic_number;  /* magic number */
	uint16_t version_major; /* major version number */
	uint16_t version_minor; /* minor version number */
	uint32_t thiszone;      /* GMT to local correction */
	uint32_t sigfigs;       /* accuracy of timestamps */
	uint32_t snaplen;       /* max length of captured packets, in octets */
	uint32_t network;       /* data link type */
} pcap_file_hdr_t;

typedef struct __attribute__((packed)) {
	uint32_t ts_sec;        /* timestamp seconds */
	uint32_t ts_usec;       /* timestamp microseconds */
	uint32_t incl_len;      /* number of octets of packet saved in file */
	uint32_t orig_len;      /* actual length of packet */
} pcap_rec_hdr_t;

#define PCAP_MAGIC 0xa1b2c3d4

static int
logpkt_write_global_pcap_hdr(int fd)
{
	pcap_file_hdr_t hdr;

	memset(&hdr, 0x0, sizeof(hdr));
	hdr.magic_number = PCAP_MAGIC;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.snaplen = 1500;
	hdr.network = 1;
	return write(fd, &hdr, sizeof(hdr)) != sizeof(hdr) ? -1 : 0;
}

/*
 * Called on a file descriptor open for reading and writing.
 * If the fd points to an empty file, a pcap header is added and 0 is returned.
 * If the fd points to a file with PCAP magic bytes, the file position is moved
 * to the end of the file and 0 is returned.
 * If the fd points to a file without PCAP magic bytes, the file is truncated
 * to zero bytes and a new PCAP header is written.
 * On a return value of 0, the caller can continue to write PCAP records to the
 * file descriptor.  On error, -1 is returned and the file descriptor is in an
 * undefined but still open state.
 */
int
logpkt_pcap_open_fd(int fd) {
	pcap_file_hdr_t hdr;
	off_t sz;
	ssize_t n;

	sz = lseek(fd, 0, SEEK_END);
	if (sz == -1)
		return -1;

	if (sz > 0) {
		if (lseek(fd, 0, SEEK_SET) == -1)
			return -1;
		n = read(fd, &hdr, sizeof(pcap_file_hdr_t));
		if (n != sizeof(pcap_file_hdr_t))
			return -1;
		if (hdr.magic_number == PCAP_MAGIC)
			return lseek(fd, 0, SEEK_END) == -1 ? -1 : 0;
		if (lseek(fd, 0, SEEK_SET) == -1)
			return -1;
		if (ftruncate(fd, 0) == -1)
			return -1;
	}

	return logpkt_write_global_pcap_hdr(fd);
}

/*
 * Returns 1 if addr is equal to ip6 error addr, 0 otherwise.
 */
static int
logpkt_ip6addr_is_error(struct libnet_in6_addr *addr)
{
	if (memcmp(&addr->__u6_addr, &in6addr_error.__u6_addr, 16) == 0)
		return 1;
	return 0;
}

static int
logpkt_str2ip46addr(libnet_t *libnet, const char *addr, int af,
                    logpkt_ip46addr_t *ip46)
{
	if (af == AF_INET) {
		ip46->ip4 = inet_addr(addr);
		if (ip46->ip4 == 0) {
			log_err_printf("Error converting IPv4 address: %s\n",
			               addr);
			goto out;
		}
	} else {
		ip46->ip6 = libnet_name2addr6(libnet, (char *)addr,
		                              LIBNET_DONT_RESOLVE);
		if (logpkt_ip6addr_is_error(&ip46->ip6)) {
			log_err_printf("Error converting IPv6 address: %s\n",
			               addr);
			goto out;
		}
	}
	return 0;
out:
	return -1;
}

int
logpkt_ctx_init(logpkt_ctx_t *ctx, libnet_t *libnet,
                const uint8_t *src_ether, const uint8_t *dst_ether,
                const char *src_addr, const char *src_port,
                const char *dst_addr, const char *dst_port)
{
	ctx->libnet = libnet;

	memcpy(ctx->src_ether, src_ether, ETHER_ADDR_LEN);
	memcpy(ctx->dst_ether, dst_ether, ETHER_ADDR_LEN);

	ctx->af = sys_get_af(src_addr);
	if (ctx->af == AF_UNSPEC) {
		log_err_printf("Unspec address family: %s\n", src_addr);
		goto out;
	}
	if (sys_get_af(dst_addr) != ctx->af) {
		log_err_printf("Src and dst address families do not match"
		               ": %s, %s\n", src_addr, dst_addr);
		goto out;
	}

	if (logpkt_str2ip46addr(libnet, src_addr, ctx->af,
	                        &ctx->src_ip) == -1)
		goto out;
	ctx->src_port = atoi(src_port);

	if (logpkt_str2ip46addr(libnet, dst_addr, ctx->af,
	                        &ctx->dst_ip) == -1)
		goto out;
	ctx->dst_port = atoi(dst_port);

	ctx->src_seq = 0;
	ctx->src_ack = 0;
	ctx->dst_seq = 0;
	ctx->dst_ack = 0;
	return 0;
out:
	return -1;
}

static int
logpkt_write_pcap_record(libnet_t *libnet, int fd)
{
	uint32_t len;
	uint8_t *packet = NULL;
	pcap_rec_hdr_t packet_record_hdr;
	struct timeval tv;
	int rv = -1;

	if (libnet_pblock_coalesce(libnet, &packet, &len) == -1) {
		log_err_printf("Error in libnet_pblock_coalesce(): %s",
		               libnet_geterror(libnet));
		goto out;
	}

	gettimeofday(&tv, NULL);
	packet_record_hdr.ts_sec = tv.tv_sec;
	packet_record_hdr.ts_usec = tv.tv_usec;
	packet_record_hdr.orig_len = packet_record_hdr.incl_len = len;

	if (write(fd, &packet_record_hdr, sizeof(packet_record_hdr))
	    == sizeof(packet_record_hdr)) {
		if (write(fd, packet, len) != (int)len) {
			log_err_printf("Error writing pcap record packet"
			               ": %s\n", strerror(errno));
			goto out2;
		}
	} else {
		log_err_printf("Error writing pcap record hdr: %s\n",
		               strerror(errno));
		goto out2;
	}

	rv = 0;
out2:
	/* this depends on libnet_pblock_coalesce() internals */
	if (libnet->aligner > 0) {
		packet = packet - libnet->aligner;
	}
	free(packet);
out:
	return rv;
}

static int
logpkt_build_packet(libnet_t *libnet,
                    uint8_t *src_ether, uint8_t *dst_ether, int af,
                    logpkt_ip46addr_t *src_ip, logpkt_ip46addr_t *dst_ip,
                    uint16_t src_port, uint16_t dst_port,
                    char flags, uint32_t seq, uint32_t ack,
                    const uint8_t *payload, size_t payloadlen)
{
	libnet_ptag_t ptag;

	ptag = libnet_build_tcp(src_port,
	                        dst_port,
	                        seq,
	                        ack,
	                        flags,
	                        32767,          /* window size */
	                        0,              /* checksum */
	                        0,              /* urgent pointer */
	                        LIBNET_TCP_H + payloadlen,
	                        (uint8_t *)payload, payloadlen,
	                        libnet, 0);
	if (ptag == -1) {
		log_err_printf("Error building tcp header: %s",
		               libnet_geterror(libnet));
		return -1;
	}

	if (af == AF_INET) {
		ptag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H +
		                         payloadlen,
		                         0,             /* TOS */
		                         (uint16_t)
		                         libnet_get_prand(LIBNET_PRu16), /*id*/
		                         0x4000,        /* frag */
		                         64,            /* TTL */
		                         IPPROTO_TCP,   /* protocol */
		                         0,             /* checksum */
		                         src_ip->ip4,
		                         dst_ip->ip4,
		                         NULL, 0,
		                         libnet, 0);
	} else {
		ptag = libnet_build_ipv6(0,             /* traffic class */
		                         0,             /* flow label */
		                         LIBNET_IPV6_H + LIBNET_TCP_H +
		                         payloadlen,
		                         IPPROTO_TCP,
		                         255,           /* hop limit */
		                         src_ip->ip6,
		                         dst_ip->ip6,
		                         NULL, 0,
		                         libnet, 0);
	}
	if (ptag == -1) {
		log_err_printf("Error building ip header: %s",
		               libnet_geterror(libnet));
		return -1;
	}

	ptag = libnet_build_ethernet(dst_ether,
	                             src_ether,
	                             af == AF_INET ? ETHERTYPE_IP
	                                           : ETHERTYPE_IPV6,
	                             NULL, 0,
	                             libnet, 0);
	if (ptag == -1) {
		log_err_printf("Error building ethernet header: %s",
		               libnet_geterror(libnet));
		return -1;
	}
	return 0;
}

static int
logpkt_write_packet(logpkt_ctx_t *ctx, int fd, int direction, char flags,
                    const uint8_t *payload, size_t payloadlen)
{
	int rv;

	if (direction == LOGPKT_REQUEST) {
		if (flags & TH_SYN) {
			ctx->src_seq = libnet_get_prand(LIBNET_PRu32);
		}
		rv = logpkt_build_packet(ctx->libnet,
		                         ctx->src_ether, ctx->dst_ether,
		                         ctx->af, &ctx->src_ip, &ctx->dst_ip,
		                         ctx->src_port, ctx->dst_port,
		                         flags, ctx->src_seq, ctx->src_ack,
		                         payload, payloadlen);
		ctx->src_seq += payloadlen;
		ctx->dst_ack += payloadlen;
	} else {
		if (flags & TH_SYN) {
			ctx->dst_seq = libnet_get_prand(LIBNET_PRu32);
		}
		rv = logpkt_build_packet(ctx->libnet,
		                         ctx->dst_ether, ctx->src_ether,
		                         ctx->af, &ctx->dst_ip, &ctx->src_ip,
		                         ctx->dst_port, ctx->src_port,
		                         flags, ctx->dst_seq, ctx->dst_ack,
		                         payload, payloadlen);
		ctx->dst_seq += payloadlen;
		ctx->src_ack += payloadlen;
	}
	if (rv == -1) {
		log_err_printf("Error building packet\n");
		return -1;
	}

	if (fd != -1) {
		rv = logpkt_write_pcap_record(ctx->libnet, fd);
	} else {
		rv = libnet_write(ctx->libnet);
	}
	if (rv == -1) {
		log_err_printf("Error writing packet: %s",
		               libnet_geterror(ctx->libnet));
	}

	libnet_clear_packet(ctx->libnet);
	return rv;
}

int
logpkt_write_payload(logpkt_ctx_t *ctx, int fd, int direction,
                     const uint8_t *payload, size_t payloadlen)
{
	int other_direction = (direction == LOGPKT_REQUEST) ? LOGPKT_RESPONSE
	                                                    : LOGPKT_REQUEST;

	if (ctx->src_seq == 0) {
		if (logpkt_write_packet(ctx, fd, LOGPKT_REQUEST,
		                        TH_SYN, NULL, 0) == -1)
			return -1;
		ctx->dst_ack = ctx->src_seq + 1;
		if (logpkt_write_packet(ctx, fd, LOGPKT_RESPONSE,
		                        TH_SYN|TH_ACK, NULL, 0) == -1)
			return -1;
		ctx->src_ack = ctx->dst_seq + 1;
		ctx->src_seq += 1;
		if (logpkt_write_packet(ctx, fd, LOGPKT_REQUEST,
		                        TH_ACK, NULL, 0) == -1)
			return -1;
		ctx->dst_seq += 1;
	}

	while (payloadlen > 0) {
		size_t n = payloadlen > MSS_VAL ? MSS_VAL : payloadlen;
		if (logpkt_write_packet(ctx, fd, direction,
		                        TH_PUSH|TH_ACK, payload, n) == -1) {
			log_err_printf("Warning: Failed to write to pcap log"
			               ": %s\n", strerror(errno));
			return -1;
		}
		payload += n;
		payloadlen -= n;
	}

	if (logpkt_write_packet(ctx, fd, other_direction,
	                        TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write to pcap log: %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}

int
logpkt_write_close(logpkt_ctx_t *ctx, int fd, int direction) {
	int other_direction = (direction == LOGPKT_REQUEST) ? LOGPKT_RESPONSE
	                                                    : LOGPKT_REQUEST;

	if (ctx->src_seq == 0)
		return 0;

	if (logpkt_write_packet(ctx, fd, direction,
	                        TH_FIN|TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}
	if (direction == LOGPKT_REQUEST) {
		ctx->dst_ack += 1;
	} else {
		ctx->src_ack += 1;
	}

	if (logpkt_write_packet(ctx, fd, other_direction,
	                        TH_FIN|TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}
	if (direction == LOGPKT_REQUEST) {
		ctx->src_seq += 1;
		ctx->src_ack += 1;
	} else {
		ctx->src_seq += 1;
		ctx->src_ack += 1;
	}

	if (logpkt_write_packet(ctx, fd, direction,
	                        TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}

	return 0;
}

typedef struct {
	uint32_t ip;
	int result;
	uint8_t ether[ETHER_ADDR_LEN];
} logpkt_recv_arp_reply_ctx_t;

static void
logpkt_recv_arp_reply(uint8_t *user,
                      UNUSED const struct pcap_pkthdr *h,
                      const uint8_t *packet)
{
	logpkt_recv_arp_reply_ctx_t *ctx = (logpkt_recv_arp_reply_ctx_t*)user;
	struct libnet_802_3_hdr *heth = (void*)packet;
	struct libnet_arp_hdr *harp = (void*)((char*)heth + LIBNET_ETH_H);

	/* skip if wrong protocol */
	if (htons(harp->ar_op) != ARPOP_REPLY)
		return;
	if (htons(harp->ar_pro) != ETHERTYPE_IP)
		return;
	if (htons(harp->ar_hrd) != ARPHRD_ETHER)
		return;

	/* skip if wrong target IP address */
	if (!!memcmp(&ctx->ip, (char*)harp + harp->ar_hln + LIBNET_ARP_H, 4))
		return;

	/* skip if source ether mismatch */
	if (!!memcmp((u_char*)harp + sizeof(struct libnet_arp_hdr),
	             heth->_802_3_shost, ETHER_ADDR_LEN))
		return;

	memcpy(ctx->ether,
	       (u_char*)harp + sizeof(struct libnet_arp_hdr),
	       ETHER_ADDR_LEN);
	ctx->result = 0;
}

/*
 * Look up the appropriate source and destination ethernet addresses for
 * mirroring packets to dst_ip_s on interface dst_if_s.
 * Only IPv4 mirror targets are supported.
 */
int
logpkt_ether_lookup(libnet_t *libnet,
                    uint8_t *src_ether, uint8_t *dst_ether,
                    const char *dst_ip_s, const char *dst_if_s)
{
	char errbuf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ?
	            LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE];
	uint8_t broadcast_ether[ETHER_ADDR_LEN] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t zero_ether[ETHER_ADDR_LEN] = {
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	struct libnet_ether_addr *src_ether_addr;
	uint32_t src_ip;
	struct bpf_program bp;
	int count = 50;
	logpkt_recv_arp_reply_ctx_t ctx;

	if (sys_get_af(dst_ip_s) != AF_INET) {
		log_err_printf("Mirroring target must be an IPv4 address.\n");
		return -1;
	}

	ctx.result = -1;
	ctx.ip = libnet_name2addr4(libnet, (char *)dst_ip_s,
	                           LIBNET_DONT_RESOLVE);
	if (ctx.ip == (uint32_t)-1) {
		log_err_printf("Error converting dst IP address: %s\n",
		               libnet_geterror(libnet));
		goto out;
	}
	src_ip = libnet_get_ipaddr4(libnet);
	if (src_ip == (uint32_t)-1) {
		log_err_printf("Error getting src IP address: %s\n",
		               libnet_geterror(libnet));
		goto out;
	}
	src_ether_addr = libnet_get_hwaddr(libnet);
	if (src_ether_addr == NULL) {
		log_err_printf("Error getting src ethernet address: %s\n",
		               libnet_geterror(libnet));
		goto out;
	}
	memcpy(src_ether, src_ether_addr->ether_addr_octet, ETHER_ADDR_LEN);

	if (libnet_autobuild_arp(ARPOP_REQUEST,
	                         src_ether,
	                         (uint8_t*)&src_ip,
	                         zero_ether,
	                         (uint8_t*)&ctx.ip,
	                         libnet) == -1) {
		log_err_printf("Error building arp header: %s\n",
		               libnet_geterror(libnet));
		goto out;
	}

	if (libnet_autobuild_ethernet(broadcast_ether,
	                              ETHERTYPE_ARP,
	                              libnet) == -1) {
		log_err_printf("Error building ethernet header: %s",
		               libnet_geterror(libnet));
		goto out;
	}

	pcap_t *pcap = pcap_open_live(dst_if_s, 100, 0, 10, errbuf);
	if (pcap == NULL) {
		log_err_printf("Error in pcap_open_live(): %s\n", errbuf);
		goto out;
	}

	if (pcap_compile(pcap, &bp, "arp", 0, -1) == -1) {
		log_err_printf("Error in pcap_compile(): %s\n",
		               pcap_geterr(pcap));
		goto out2;
	}
	if (pcap_setfilter(pcap, &bp) == -1) {
		log_err_printf("Error in pcap_setfilter(): %s\n",
		               pcap_geterr(pcap));
		goto out3;
	}

	do {
		if (libnet_write(libnet) != -1) {
			/* Limit # of packets to process, so we can loop to
			 * send arp requests on busy networks. */
			if (pcap_dispatch(pcap, 1000,
			                  (pcap_handler)logpkt_recv_arp_reply,
			                  (u_char*)&ctx) < 0) {
				log_err_printf("Error in pcap_dispatch(): %s\n",
				               pcap_geterr(pcap));
				break;
			}
		} else {
			log_err_printf("Error writing arp packet: %s",
			               libnet_geterror(libnet));
			break;
		}
		sleep(1);
	} while (ctx.result == -1 && --count > 0);

	if (ctx.result == 0) {
		memcpy(dst_ether, &ctx.ether, ETHER_ADDR_LEN);
		log_dbg_printf("Mirror target is up: "
		               "%02x:%02x:%02x:%02x:%02x:%02x\n",
		               dst_ether[0], dst_ether[1], dst_ether[2],
		               dst_ether[3], dst_ether[4], dst_ether[5]);
	}

out3:
	pcap_freecode(&bp);
out2:
	pcap_close(pcap);
out:
	libnet_clear_packet(libnet);
	return ctx.result;
}

