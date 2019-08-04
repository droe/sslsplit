/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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
#include <errno.h>

#ifndef WITHOUT_MIRROR
#include <pcap.h>
#endif /* !WITHOUT_MIRROR */

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

#define PCAP_MAGIC      0xa1b2c3d4

typedef struct __attribute__((packed)) {
	uint8_t  dst_mac[ETHER_ADDR_LEN];
	uint8_t  src_mac[ETHER_ADDR_LEN];
	uint16_t ethertype;
} ether_hdr_t;

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP    0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

typedef struct __attribute__((packed)) {
	uint8_t  version_ihl;
	uint8_t  dscp_ecn;
	uint16_t len;
	uint16_t id;
	uint16_t frag;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t chksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip4_hdr_t;

typedef struct __attribute__((packed)) {
	uint32_t flags;
	uint16_t len;
	uint8_t  next_hdr;
	uint8_t  hop_limit;
	uint8_t  src_addr[16];
	uint8_t  dst_addr[16];
} ip6_hdr_t;

typedef struct __attribute__((packed)) {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint16_t flags;
	uint16_t win;
	uint16_t chksum;
	uint16_t urgp;
} tcp_hdr_t;

#ifndef TH_FIN
#define TH_FIN          0x01
#endif
#ifndef TH_SYN
#define TH_SYN          0x02
#endif
#ifndef TH_RST
#define TH_RST          0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH         0x08
#endif
#ifndef TH_ACK
#define TH_ACK          0x10
#endif

/*
 * *MTU* is the size of the largest layer 3 packet, including IP header.
 *
 * *MAX_PKTSZ* is the buffer size needed to construct a layer 2 frame
 * containing the largest possible layer 3 packet allowed by MTU.
 *
 * *MSS_IP4* and *MSS_IP6* are the maximum TCP segment sizes that fit into a
 * single IPv4 and IPv6 packet, respectively.
 *
 * The calculations assume no IPv4 options and no IPv6 option headers.
 *
 * These constants are only used for PCAP writing, not for mirroring.
 */
#define MTU             1500
#define MAX_PKTSZ       (MTU + sizeof(ether_hdr_t))
#define MSS_IP4         (MTU - sizeof(ip4_hdr_t) - sizeof(tcp_hdr_t))
#define MSS_IP6         (MTU - sizeof(ip6_hdr_t) - sizeof(tcp_hdr_t))

/*
 * IP/TCP checksumming operating on uint32_t intermediate state variable C.
 */
#define CHKSUM_INIT(C) \
	{ \
		(C) = 0; \
	}
#define CHKSUM_ADD_RANGE(C,B,S) \
	{ \
		uint16_t *p = (uint16_t *)(B); \
		size_t words = (S) >> 1; \
		while (words--) { \
			(C) += *p++; \
		} \
		if ((S) & 1) { \
			(C) += htons(*((char *)p) << 8); \
		} \
	}
#define CHKSUM_ADD_UINT32(C,U) \
	{ \
		(C) += ((U) >> 16) + ((U) & 0xFFFF); \
	}
#define CHKSUM_ADD_UINT16(C,U) \
	{ \
		(C) += (U); \
	}
#define CHKSUM_FINALIZE(C) \
	{ \
		(C) = ((C) >> 16) + ((C) & 0xffff); \
		(C) += ((C) >> 16); \
		(C) = ~(C); \
	}

/* Socket address typecasting shorthand notations. */
#define CSA(X)          ((const struct sockaddr *)(X))
#define CSIN(X)         ((const struct sockaddr_in *)(X))
#define CSIN6(X)        ((const struct sockaddr_in6 *)(X))

/*
 * Write the PCAP file-level header to file descriptor *fd* open for writing,
 * positioned at the beginning of an empty file.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
logpkt_write_global_pcap_hdr(int fd)
{
	pcap_file_hdr_t hdr;

	memset(&hdr, 0x0, sizeof(hdr));
	hdr.magic_number = PCAP_MAGIC;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.snaplen = MAX_PKTSZ;
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
 * Initialize the per-connection packet crafting context.  For mirroring,
 * *libnet* must be an initialized libnet instance and *mtu* must be the
 * target interface MTU greater than 0.  For PCAP writing, *libnet* must be
 * NULL and *mtu* must be 0.  The ether and sockaddr addresses are used as the
 * layer 2 and layer 3 addresses respectively.  For mirroring, the ethers must
 * match the actual link layer addresses to be used when sending traffic, not
 * some emulated addresses.
 */
void
logpkt_ctx_init(logpkt_ctx_t *ctx, libnet_t *libnet, size_t mtu,
                const uint8_t *src_ether, const uint8_t *dst_ether,
                const struct sockaddr *src_addr, socklen_t src_addr_len,
                const struct sockaddr *dst_addr, socklen_t dst_addr_len)
{
	ctx->libnet = libnet;
	memcpy(ctx->src_ether, src_ether, ETHER_ADDR_LEN);
	memcpy(ctx->dst_ether, dst_ether, ETHER_ADDR_LEN);
	memcpy(&ctx->src_addr, src_addr, src_addr_len);
	memcpy(&ctx->dst_addr, dst_addr, dst_addr_len);
	ctx->src_seq = 0;
	ctx->dst_seq = 0;
	if (mtu) {
		ctx->mss = mtu - sizeof(tcp_hdr_t)
		               - (dst_addr->sa_family == AF_INET
		                  ? sizeof(ip4_hdr_t)
		                  : sizeof(ip6_hdr_t));
	} else {
		ctx->mss = dst_addr->sa_family == AF_INET ? MSS_IP4 : MSS_IP6;
	}
}

/*
 * Write the layer 2 frame contained in *pkt* to file descriptor *fd* already
 * open for writing.  First writes a PCAP record header, then the actual frame.
 */
static int
logpkt_pcap_write(const uint8_t *pkt, size_t pktsz, int fd)
{
	pcap_rec_hdr_t rec_hdr;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	rec_hdr.ts_sec = tv.tv_sec;
	rec_hdr.ts_usec = tv.tv_usec;
	rec_hdr.orig_len = rec_hdr.incl_len = pktsz;

	if (write(fd, &rec_hdr, sizeof(rec_hdr)) != sizeof(rec_hdr)) {
		log_err_printf("Error writing pcap record hdr: %s\n",
		               strerror(errno));
		return -1;
	}
	if (write(fd, pkt, pktsz) != (ssize_t)pktsz) {
		log_err_printf("Error writing pcap record: %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Build a frame from the given layer 2, layer 3 and layer 4 parameters plus
 * payload, write the resulting bytes into buffer pointed to by *pkt*, and fix
 * the checksums on all layers.  The receiving buffer must be at least
 * MAX_PKTSZ bytes large and payload must be a maximum of MSS_IP4 or MSS_IP6
 * respectively.  Layer 2 is Ethernet II, layer 3 is IPv4 or IPv6 depending on
 * the address family of *dst_addr*, and layer 4 is TCP.
 *
 * This function is stateless.  For header fields that cannot be directly
 * derived from the arguments, default values will be used.
 */
static size_t
logpkt_pcap_build(uint8_t *pkt,
                  uint8_t *src_ether, uint8_t *dst_ether,
                  const struct sockaddr *src_addr,
                  const struct sockaddr *dst_addr,
                  char flags, uint32_t seq, uint32_t ack,
                  const uint8_t *payload, size_t payloadlen)
{
	ether_hdr_t *ether_hdr;
	ip4_hdr_t *ip4_hdr;
	ip6_hdr_t *ip6_hdr;
	tcp_hdr_t *tcp_hdr;
	size_t sz;
	uint32_t sum;

	ether_hdr = (ether_hdr_t *)pkt;
	memcpy(ether_hdr->src_mac, src_ether, sizeof(ether_hdr->src_mac));
	memcpy(ether_hdr->dst_mac, dst_ether, sizeof(ether_hdr->dst_mac));
	sz = sizeof(ether_hdr_t);

	if (dst_addr->sa_family == AF_INET) {
		ether_hdr->ethertype = htons(ETHERTYPE_IP);
		ip4_hdr = (ip4_hdr_t *)(((uint8_t *)ether_hdr) +
		                        sizeof(ether_hdr_t));
		ip4_hdr->version_ihl = 0x45; /* version 4, ihl 5 words */
		ip4_hdr->dscp_ecn = 0;
		ip4_hdr->len = htons(sizeof(ip4_hdr_t) +
		                     sizeof(tcp_hdr_t) + payloadlen);
		ip4_hdr->id = sys_rand16(),
		ip4_hdr->frag = 0;
		ip4_hdr->ttl = 64;
		ip4_hdr->proto = IPPROTO_TCP;
		ip4_hdr->src_addr = CSIN(src_addr)->sin_addr.s_addr;
		ip4_hdr->dst_addr = CSIN(dst_addr)->sin_addr.s_addr;
		ip4_hdr->chksum = 0;
		CHKSUM_INIT(sum);
		CHKSUM_ADD_RANGE(sum, ip4_hdr, sizeof(ip4_hdr_t));
		CHKSUM_FINALIZE(sum);
		ip4_hdr->chksum = sum;
		sz += sizeof(ip4_hdr_t);
		tcp_hdr = (tcp_hdr_t *)(((uint8_t *)ip4_hdr) +
		                        sizeof(ip4_hdr_t));
		tcp_hdr->src_port = CSIN(src_addr)->sin_port;
		tcp_hdr->dst_port = CSIN(dst_addr)->sin_port;
		/* pseudo header */
		CHKSUM_INIT(sum);
		CHKSUM_ADD_UINT32(sum, ip4_hdr->src_addr);
		CHKSUM_ADD_UINT32(sum, ip4_hdr->dst_addr);
		CHKSUM_ADD_UINT16(sum, htons(ip4_hdr->proto));
		CHKSUM_ADD_UINT16(sum, htons(sizeof(tcp_hdr_t) + payloadlen));
	} else {
		ether_hdr->ethertype = htons(ETHERTYPE_IPV6);
		ip6_hdr = (ip6_hdr_t *)(((uint8_t *)ether_hdr) +
		                        sizeof(ether_hdr_t));
		ip6_hdr->flags = htonl(0x60000000UL); /* version 6 */
		ip6_hdr->len = htons(sizeof(tcp_hdr_t) + payloadlen);
		ip6_hdr->next_hdr = IPPROTO_TCP;
		ip6_hdr->hop_limit = 255;
		memcpy(ip6_hdr->src_addr, CSIN6(src_addr)->sin6_addr.s6_addr,
		       sizeof(ip6_hdr->src_addr));
		memcpy(ip6_hdr->dst_addr, CSIN6(dst_addr)->sin6_addr.s6_addr,
		       sizeof(ip6_hdr->dst_addr));
		sz += sizeof(ip6_hdr_t);
		tcp_hdr = (tcp_hdr_t *)(((uint8_t *)ip6_hdr) +
		                        sizeof(ip6_hdr_t));
		tcp_hdr->src_port = CSIN6(src_addr)->sin6_port;
		tcp_hdr->dst_port = CSIN6(dst_addr)->sin6_port;
		/* pseudo header */
		CHKSUM_INIT(sum);
		CHKSUM_ADD_RANGE(sum, ip6_hdr->src_addr,
		                 sizeof(ip6_hdr->src_addr));
		CHKSUM_ADD_RANGE(sum, ip6_hdr->dst_addr,
		                 sizeof(ip6_hdr->dst_addr));
		CHKSUM_ADD_UINT32(sum, ip6_hdr->len);
		CHKSUM_ADD_UINT16(sum, htons(IPPROTO_TCP));
	}
	tcp_hdr->seq = htonl(seq);
	tcp_hdr->ack = htonl(ack);
	tcp_hdr->flags = htons(0x5000|flags); /* data offset 5 words */
	tcp_hdr->win = htons(32767);
	tcp_hdr->urgp = 0;
	tcp_hdr->chksum = 0;
	sz += sizeof(tcp_hdr_t);
	memcpy(((uint8_t *)tcp_hdr) + sizeof(tcp_hdr_t), payload, payloadlen);
	CHKSUM_ADD_RANGE(sum, tcp_hdr, sizeof(tcp_hdr_t) + payloadlen);
	CHKSUM_FINALIZE(sum);
	tcp_hdr->chksum = sum;
	return sz + payloadlen;
}

#ifndef WITHOUT_MIRROR
/*
 * Build a packet using libnet intended for mirroring mode.  The packet will
 * be dynamically allocated on the heap by the libnet instance *libnet*.
 */
static int
logpkt_mirror_build(libnet_t *libnet,
                    uint8_t *src_ether, uint8_t *dst_ether,
                    const struct sockaddr *src_addr,
                    const struct sockaddr *dst_addr,
                    char flags, uint32_t seq, uint32_t ack,
                    const uint8_t *payload, size_t payloadlen)
{
	libnet_ptag_t ptag;

	ptag = libnet_build_tcp(htons(src_addr->sa_family == AF_INET
	                        ? CSIN(src_addr)->sin_port
	                        : CSIN6(src_addr)->sin6_port),
	                        htons(dst_addr->sa_family == AF_INET
	                        ? CSIN(dst_addr)->sin_port
	                        : CSIN6(dst_addr)->sin6_port),
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

	if (dst_addr->sa_family == AF_INET) {
		ptag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H +
		                         payloadlen,
		                         0,             /* TOS */
		                         (uint16_t)
		                         sys_rand16(),  /* id */
		                         0x4000,        /* frag */
		                         64,            /* TTL */
		                         IPPROTO_TCP,   /* protocol */
		                         0,             /* checksum */
		                         CSIN(src_addr)->sin_addr.s_addr,
		                         CSIN(dst_addr)->sin_addr.s_addr,
		                         NULL, 0,
		                         libnet, 0);
	} else {
		ptag = libnet_build_ipv6(0,             /* traffic class */
		                         0,             /* flow label */
		                         LIBNET_IPV6_H + LIBNET_TCP_H +
		                         payloadlen,
		                         IPPROTO_TCP,
		                         255,           /* hop limit */
		                         *(struct libnet_in6_addr *)
		                         &CSIN6(src_addr)->sin6_addr,
		                         *(struct libnet_in6_addr *)
		                         &CSIN6(dst_addr)->sin6_addr,
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
	                             dst_addr->sa_family == AF_INET
	                                     ? ETHERTYPE_IP : ETHERTYPE_IPV6,
	                             NULL, 0,
	                             libnet, 0);
	if (ptag == -1) {
		log_err_printf("Error building ethernet header: %s",
		               libnet_geterror(libnet));
		return -1;
	}
	return 0;
}
#endif /* !WITHOUT_MIRROR */

/*
 * Write a single packet to either PCAP (*fd* != -1) or a network interface
 * (*fd* == -1).  Caller must ensure that *ctx* was initialized accordingly.
 * The packet will be in direction *direction*, use TCP flags *flags*, and
 * transmit a payload *payload*.  TCP sequence and acknowledgement numbers as
 * well as source and destination identifiers are taken from *ctx*.
 *
 * Caller must ensure that *payload* fits into a frame depending on the MTU
 * selected (interface in mirroring mode, MTU value in PCAP writing mode).
 */
static int
logpkt_write_packet(logpkt_ctx_t *ctx, int fd, int direction, char flags,
                    const uint8_t *payload, size_t payloadlen)
{
	int rv;

	if (fd != -1) {
		uint8_t buf[MAX_PKTSZ];
		size_t sz;
		if (direction == LOGPKT_REQUEST) {
			sz = logpkt_pcap_build(buf,
			                       ctx->src_ether, ctx->dst_ether,
			                       CSA(&ctx->src_addr),
			                       CSA(&ctx->dst_addr),
			                       flags,
			                       ctx->src_seq, ctx->dst_seq,
			                       payload, payloadlen);
		} else {
			sz = logpkt_pcap_build(buf,
			                       ctx->dst_ether, ctx->src_ether,
			                       CSA(&ctx->dst_addr),
			                       CSA(&ctx->src_addr),
			                       flags,
			                       ctx->dst_seq, ctx->src_seq,
			                       payload, payloadlen);
		}
		rv = logpkt_pcap_write(buf, sz, fd);
		if (rv == -1) {
			log_err_printf("Error writing packet to PCAP file\n");
			return -1;
		}
	} else {
#ifndef WITHOUT_MIRROR
		/* Source and destination ether are determined by the actual
		 * local MAC address and target MAC address for mirroring the
		 * packets to; use them as-is for both directions. */
		if (direction == LOGPKT_REQUEST) {
			rv = logpkt_mirror_build(ctx->libnet,
			                         ctx->src_ether, ctx->dst_ether,
			                         CSA(&ctx->src_addr),
			                         CSA(&ctx->dst_addr),
			                         flags,
			                         ctx->src_seq, ctx->dst_seq,
			                         payload, payloadlen);
		} else {
			rv = logpkt_mirror_build(ctx->libnet,
			                         ctx->src_ether, ctx->dst_ether,
			                         CSA(&ctx->dst_addr),
			                         CSA(&ctx->src_addr),
			                         flags,
			                         ctx->dst_seq, ctx->src_seq,
			                         payload, payloadlen);
		}
		if (rv == -1) {
			log_err_printf("Error building packet\n");
			return -1;
		}
		rv = libnet_write(ctx->libnet);
		if (rv == -1) {
			log_err_printf("Error writing packet: %s\n",
			               libnet_geterror(ctx->libnet));
		}
		libnet_clear_packet(ctx->libnet);
#else /* WITHOUT_MIRROR */
		rv = -1;
#endif /* WITHOUT_MIRROR */
	}
	return rv;
}

/*
 * Emulate the initial SYN handshake.
 */
static int
logpkt_write_syn_handshake(logpkt_ctx_t *ctx, int fd)
{
	ctx->src_seq = sys_rand32();
	if (logpkt_write_packet(ctx, fd, LOGPKT_REQUEST,
	                        TH_SYN, NULL, 0) == -1)
		return -1;
	ctx->src_seq += 1;
	ctx->dst_seq = sys_rand32();
	if (logpkt_write_packet(ctx, fd, LOGPKT_RESPONSE,
	                        TH_SYN|TH_ACK, NULL, 0) == -1)
		return -1;
	ctx->dst_seq += 1;
	if (logpkt_write_packet(ctx, fd, LOGPKT_REQUEST,
	                        TH_ACK, NULL, 0) == -1)
		return -1;
	return 0;
}

/*
 * Emulate the necessary packets to write a single payload segment.  If
 * necessary, a SYN handshake will automatically be generated before emitting
 * the packet carrying the payload plus a matching ACK.
 */
int
logpkt_write_payload(logpkt_ctx_t *ctx, int fd, int direction,
                     const uint8_t *payload, size_t payloadlen)
{
	int other_direction = (direction == LOGPKT_REQUEST) ? LOGPKT_RESPONSE
	                                                    : LOGPKT_REQUEST;

	if (ctx->src_seq == 0) {
		if (logpkt_write_syn_handshake(ctx, fd) == -1)
			return -1;
	}

	while (payloadlen > 0) {
		size_t n = payloadlen > ctx->mss ? ctx->mss : payloadlen;
		if (logpkt_write_packet(ctx, fd, direction,
		                        TH_PUSH|TH_ACK, payload, n) == -1) {
			log_err_printf("Warning: Failed to write to pcap log"
			               ": %s\n", strerror(errno));
			return -1;
		}
		if (direction == LOGPKT_REQUEST) {
			ctx->src_seq += n;
		} else {
			ctx->dst_seq += n;
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

/*
 * Emulate a connection close, emitting a FIN handshake in the correct
 * direction.  Does not close the file descriptor.
 */
int
logpkt_write_close(logpkt_ctx_t *ctx, int fd, int direction) {
	int other_direction = (direction == LOGPKT_REQUEST) ? LOGPKT_RESPONSE
	                                                    : LOGPKT_REQUEST;

	if (ctx->src_seq == 0) {
		if (logpkt_write_syn_handshake(ctx, fd) == -1)
			return -1;
	}

	if (logpkt_write_packet(ctx, fd, direction,
	                        TH_FIN|TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}
	if (direction == LOGPKT_REQUEST) {
		ctx->src_seq += 1;
	} else {
		ctx->dst_seq += 1;
	}

	if (logpkt_write_packet(ctx, fd, other_direction,
	                        TH_FIN|TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}
	if (other_direction == LOGPKT_REQUEST) {
		ctx->src_seq += 1;
	} else {
		ctx->dst_seq += 1;
	}

	if (logpkt_write_packet(ctx, fd, direction,
	                        TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write packet\n");
		return -1;
	}

	return 0;
}

#ifndef WITHOUT_MIRROR
typedef struct {
	uint32_t ip;
	int result;
	uint8_t ether[ETHER_ADDR_LEN];
} logpkt_recv_arp_reply_ctx_t;

/*
 * Receive a single ARP reply and copy the resulting ether to ctx->ether.
 */
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
	char errbuf[PCAP_ERRBUF_SIZE];
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
#endif /* !WITHOUT_MIRROR */

/* vim: set noet ft=c: */
