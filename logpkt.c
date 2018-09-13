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

libnet_t *libnet_pcap = NULL;
libnet_t *libnet_mirror = NULL;
struct libnet_ether_addr *mirrorsender_ether = NULL;

static unsigned int mirrortarget_ip = 0; /* Pcap handler input */
static unsigned char mirrortarget_ether[ETHER_ADDR_LEN]; /* Pcap handler output */
static int mirrortarget_result = -1; /* Pcap handler retval */

int
logpkt_write_global_pcap_hdr(int fd)
{
	pcap_file_hdr_t hdr;

	memset(&hdr, 0x0, sizeof(hdr));

	hdr.magic_number = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.snaplen = 1500;
	hdr.network = 1;

	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		return -1;
	}
	return 0;
}

/*
 * Returns -1 if addr is equal to ip6 error addr, 0 otherwise.
 */
static int
logpkt_ip6addr_error(struct libnet_in6_addr addr)
{
	uint32_t *p1 = (uint32_t*)&addr.__u6_addr;
	uint32_t *p2 = (uint32_t*)&in6addr_error.__u6_addr;

	if ((p1[0] == p2[0]) && (p1[1] == p2[1]) && (p1[2] == p2[2]) && (p1[3] == p2[3])) {
		return -1;
	}
	return 0;
}

static int
logpkt_str2ip46addr(libnet_t *libnet, char *addr, int af, unsigned int *ip4addr, struct libnet_in6_addr *ip6addr)
{
	if (af == AF_INET) {
		*ip4addr = inet_addr(addr);
		if (*ip4addr == 0) {
			log_err_printf("Error converting IPv4 address: %s\n", addr);
			goto out;
		}
	} else {
		*ip6addr = libnet_name2addr6(libnet, addr, LIBNET_DONT_RESOLVE);
		if (logpkt_ip6addr_error(*ip6addr) == -1) {
			log_err_printf("Error converting IPv6 address: %s\n", addr);
			goto out;
		}
	}
	return 0;
out:
	return -1;
}

int
logpkt_set_packet_fields(libnet_t *libnet, pcap_packet_t *pcap, char *src_addr, char *src_port, char *dst_addr, char *dst_port)
{
	pcap->af = sys_get_af(src_addr);
	if (pcap->af == AF_UNSPEC) {
		log_err_printf("Unspec address family: %s\n", src_addr);
		goto out;
	}
	if (sys_get_af(dst_addr) != pcap->af) {
		log_err_printf("Src and dst address families do not match: %s, %s\n", src_addr, dst_addr);
		goto out;
	}

	if (logpkt_str2ip46addr(libnet, src_addr, pcap->af, &pcap->src_ip, &pcap->src_ip6) == -1) {
		goto out;
	}
	pcap->src_port = atoi(src_port);

	if (logpkt_str2ip46addr(libnet, dst_addr, pcap->af, &pcap->dst_ip, &pcap->dst_ip6) == -1) {
		goto out;
	}
	pcap->dst_port = atoi(dst_port);

	pcap->epoch = time(NULL);
	pcap->seq = 0;
	pcap->ack = 0;
	return 0;
out:
	return -1;
}

static int
logpkt_write_pcap_record(int fd)
{
	u_int32_t len;
	u_int8_t *packet = NULL;
	pcap_rec_hdr_t packet_record_hdr;
	struct timeval tv;
	int rv = -1;

	if (libnet_pblock_coalesce(libnet_pcap, &packet, &len) == -1) {
		log_err_printf("Error in libnet_pblock_coalesce(): %s", libnet_geterror(libnet_pcap));
		goto out;
	}

	gettimeofday(&tv, NULL);
	packet_record_hdr.ts_sec = tv.tv_sec;
	packet_record_hdr.ts_usec = tv.tv_usec;
	packet_record_hdr.orig_len = packet_record_hdr.incl_len = len;

	if (write(fd, &packet_record_hdr, sizeof(packet_record_hdr)) == sizeof(packet_record_hdr)) {
		if (write(fd, packet, len) != (int)len) {
			log_err_printf("Error writing pcap record packet: %s\n", strerror(errno));
			goto out2;
		}
	} else {
		log_err_printf("Error writing pcap record hdr: %s\n", strerror(errno));
		goto out2;
	}

	rv = 0;
out2:
	if (libnet_pcap->aligner > 0) {
		// Don't forget to free aligned bytes
		packet = packet - libnet_pcap->aligner;
	}
	free(packet);
out:
	return rv;
}

int
logpkt_write_payload(libnet_t *libnet, int fd, pcap_packet_t *from, pcap_packet_t *to, char flags, const unsigned char *payload, size_t payloadlen)
{
	int sendsize = 0;

	while (payloadlen > 0) {
		payload += sendsize;
		sendsize = payloadlen > MSS_VAL ? MSS_VAL : payloadlen;

		if (logpkt_write_packet(libnet, fd, from, flags, payload, sendsize) == -1) {
			log_err_printf("Warning: Failed to write to pcap log: %s\n",
					strerror(errno));
			return -1;
		}

		to->ack += sendsize;
		payloadlen -= sendsize;
	}

	if (logpkt_write_packet(libnet, fd, to, TH_ACK, NULL, 0) == -1) {
		log_err_printf("Warning: Failed to write to pcap log: %s\n",
				strerror(errno));
		return -1;
	}
	return 0;
}

static int
logpkt_build_packet(libnet_t *libnet, unsigned char src_ether[], pcap_packet_t *pcap, char flags, const unsigned char *payload, size_t payloadlen)
{
	libnet_ptag_t ptag;

	if (flags & TH_SYN) {
		pcap->seq = libnet_get_prand(LIBNET_PRu32);
	}

	ptag = libnet_build_tcp(
			pcap->src_port, /* source port */
			pcap->dst_port, /* destination port */
			pcap->seq, /* sequence number */
			pcap->ack, /* acknowledgement num */
			flags, /* control flags */
			32767, /* window size */
			0, /* checksum */
			0, /* urgent pointer */
			LIBNET_TCP_H + payloadlen, /* TCP packet size */
			// payload type differs in different libnet versions
			(unsigned char *)payload, /* payload */
			payloadlen, /* payload size */
			libnet, /* libnet handle */
			0); /* libnet id */
	if (ptag == -1) {
		log_err_printf("Error building tcp header: %s", libnet_geterror(libnet));
		goto out;
	}

	if (pcap->af == AF_INET) {
		ptag = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + payloadlen, /* length */
				0, /* TOS */
				(u_int16_t)libnet_get_prand(LIBNET_PRu16), /* IP ID */
				0x4000, /* IP Frag */
				64, /* TTL */
				IPPROTO_TCP, /* protocol */
				0, /* checksum */
				pcap->src_ip, /* source IP */
				pcap->dst_ip, /* destination IP */
				NULL, /* payload */
				0, /* payload size */
				libnet, /* libnet handle */
				0); /* libnet id */
	} else {
		// TODO: Check values of tc, fl, nh, and hl
		ptag = libnet_build_ipv6(
				0, /* traffic class */
				0, /* flow label */
				LIBNET_IPV6_H + LIBNET_TCP_H + payloadlen, /* total length of the IP packet */
				IPPROTO_TCP, /* next header */
				255, /* hop limit */
				pcap->src_ip6, /* source IPv6 address */
				pcap->dst_ip6, /* destination IPv6 address */
				NULL, /* optional payload or NULL */
				0, /* payload length or 0 */
				libnet, /* pointer to a libnet context */
				0); /* protocol tag to modify an existing header, 0 to build a new one */
	}
	if (ptag == -1) {
		log_err_printf("Error building ip header: %s", libnet_geterror(libnet));
		goto out;
	}

	ptag = libnet_build_ethernet(
			pcap->dst_ether, /* ethernet destination */
			src_ether, /* ethernet source */
			pcap->af == AF_INET ? ETHERTYPE_IP : ETHERTYPE_IPV6, /* protocol type */
			NULL, /* payload */
			0, /* payload size */
			libnet, /* libnet handle */
			0); /* libnet id */
	if (ptag == -1) {
		log_err_printf("Error building ethernet header: %s", libnet_geterror(libnet));
		goto out;
	}

	pcap->seq += payloadlen;
out:
	return ptag;
}

static int
logpkt_write_pcap_packet(libnet_t *libnet, int fd, pcap_packet_t *pcap, char flags, const unsigned char *payload, size_t payloadlen)
{
	// TODO: Check init
	unsigned char src_ether[ETHER_ADDR_LEN] = {0x84, 0x34, 0xC3, 0x50, 0x68, 0x8A};
	int rv = -1;

	if (logpkt_build_packet(libnet, src_ether, pcap, flags, payload, payloadlen) == -1) {
		log_err_printf("Error building pcap packet\n");
		goto out;
	}
	rv = logpkt_write_pcap_record(fd);
	if (rv == -1) {
		log_err_printf("Error writing pcap record\n");
	}
out:
	return rv;
}

static int
logpkt_write_mirror_packet(libnet_t *libnet, pcap_packet_t *pcap, char flags, const unsigned char *payload, size_t payloadlen)
{
	int rv = -1;

	if (logpkt_build_packet(libnet, mirrorsender_ether->ether_addr_octet, pcap, flags, payload, payloadlen) == -1) {
		log_err_printf("Error building mirror packet\n");
		goto out;
	}
	rv = libnet_write(libnet);
	if (rv == -1) {
		log_err_printf("Error writing mirror packet: %s", libnet_geterror(libnet));
	}
out:
	return rv;
}

int
logpkt_write_packet(libnet_t *libnet, int fd, pcap_packet_t *pcap, char flags, const unsigned char *payload, size_t payloadlen)
{
	int rv;

	if (libnet == libnet_pcap) {
		rv = logpkt_write_pcap_packet(libnet, fd, pcap, flags, payload, payloadlen);
	} else {
		rv = logpkt_write_mirror_packet(libnet, pcap, flags, payload, payloadlen);
	}
	libnet_clear_packet(libnet);
	return rv;
}

/* Pcap handler */
static void
logpkt_recv_arp_reply(UNUSED const char *user, UNUSED struct pcap_pkthdr *h, uint8_t *packet)
{
	struct libnet_802_3_hdr *heth;
	struct libnet_arp_hdr *harp;
	unsigned char *ether;
	uint32_t ip;

	heth = (void*)packet;
	harp = (void*)((char*)heth + LIBNET_ETH_H);

	/* Check if ARP reply */
	if (htons(harp->ar_op) != ARPOP_REPLY) {
		/* Not an error, as we filter to recv all arp packets */
		return;
	}

	/* Check if IPv4 address reply */
	if (htons(harp->ar_pro) != ETHERTYPE_IP) {
		log_err_printf("Not ETHERTYPE_IP: %u\n", harp->ar_pro);
		return;
	}

	/* Check if ethernet address reply */
	if (htons(harp->ar_hrd) != ARPHRD_ETHER) {
		log_err_printf("Not ARPHRD_ETHER: %u\n", harp->ar_hrd);
		return;
	}

	/* Check if IPv4 address is the one we asked for */
	memcpy(&ip, (char*)harp + harp->ar_hln + LIBNET_ARP_H, 4);
	if (mirrortarget_ip != ip) {
		log_err_printf("Reply not for mirror target ip: %.2x != %.2x\n", ip, mirrortarget_ip);
		return;
	}

	/* Must be sent from mirror target, so we know it is reachable */
	if (memcmp((u_char*)harp + sizeof(struct libnet_arp_hdr),
			   heth->_802_3_shost, ETHER_ADDR_LEN)) {
		ether = heth->_802_3_shost;
		log_err_printf("Reply not from mirror target ether: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                ether[0], ether[1], ether[2], ether[3], ether[4], ether[5]);
		return;
	}

	/* Success: Got ethernet address of mirror target, and it is up */
	memcpy(&mirrortarget_ether, (u_char*)harp + sizeof(struct libnet_arp_hdr), 6);
	mirrortarget_result = 0;
}

int
logpkt_check_mirrortarget(char *ip, char *ether, char *mirrorif)
{
	char errbuf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE];
	unsigned int src_ip;
	struct libnet_ether_addr *src_ether;
	unsigned char broadcast_ether[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char zero_ether[ETHER_ADDR_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	struct bpf_program bp;
	int count = 50;

	libnet_t *libnet = libnet_init(LIBNET_LINK, mirrorif, errbuf);
	if (libnet == NULL) {
		log_err_printf("Error initializing libnet: %s", errbuf);
		goto out;
	}

	/* Get destination IP address */
	mirrortarget_ip = libnet_name2addr4(libnet, ip, LIBNET_DONT_RESOLVE);
	if ((int)mirrortarget_ip == -1) {
		log_err_printf("Error converting IP address\n");
		goto out2;
	}

	// TODO: IPv6?
	/* Get our own IP and ethernet addresses */
	src_ip = libnet_get_ipaddr4(libnet);
	if ((int32_t)src_ip == -1) {
		log_err_printf("Error getting IP address: %s", libnet_geterror(libnet));
		goto out2;
	}

	src_ether = libnet_get_hwaddr(libnet);
	if (src_ether == NULL) {
		log_err_printf("Error getting ethernet address: %s", libnet_geterror(libnet));
		goto out2;
	}

	/* Build ARP header */
	if (libnet_autobuild_arp(ARPOP_REQUEST,
			src_ether->ether_addr_octet,
			(u_int8_t*)&src_ip, zero_ether,
			(u_int8_t*)&mirrortarget_ip, libnet) == -1) {
		log_err_printf("Error building arp header: %s", libnet_geterror(libnet));
		goto out2;
	}

	/* Build ethernet header */
	if (libnet_autobuild_ethernet(broadcast_ether, ETHERTYPE_ARP, libnet) == -1) {
		log_err_printf("Error building ethernet header: %s", libnet_geterror(libnet));
		goto out2;
	}

	pcap_t *pcap = pcap_open_live(mirrorif, 100, 0, 10, errbuf);
	if (pcap == NULL) {
		log_err_printf("Error in pcap_open_live(): %s\n", errbuf);
		goto out2;
	}

	/* Interested in ARP packets only */
	if (pcap_compile(pcap, &bp, "arp", 0, -1) == -1) {
		log_err_printf("Error in pcap_compile(): %s\n", pcap_geterr(pcap));
		goto out3;
	}
	if (pcap_setfilter(pcap, &bp) == -1) {
		log_err_printf("Error in pcap_setfilter(): %s\n", pcap_geterr(pcap));
		goto out4;
	}

	do {
		fprintf(stderr, ".");

		if (libnet_write(libnet) != -1) {
			/* Limit # of packets to process, so we can loop to send arp requests on busy networks */
			if (pcap_dispatch(pcap, 1000, (pcap_handler)logpkt_recv_arp_reply, NULL) < 0) {
				log_err_printf("Error in pcap_dispatch(): %s\n", pcap_geterr(pcap));
			}
		} else {
			log_err_printf("Error writing arp packet: %s", libnet_geterror(libnet));
		}

		sleep(1);
	} while (mirrortarget_result == -1 && --count > 0);

	fprintf(stderr, "\n");
	
	if (mirrortarget_result == 0) {
		memcpy(ether, &mirrortarget_ether, 6);
		fprintf(stderr, "Mirroring target is up: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
				ether[0], ether[1], ether[2], ether[3], ether[4], ether[5]);
	}
out4:
	pcap_freecode(&bp);
out3:
	pcap_close(pcap);
out2:
	libnet_destroy(libnet);
out:
	return mirrortarget_result;
}
