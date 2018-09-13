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

#ifndef LOGPKT_H
#define LOGPKT_H

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <errno.h>

#ifdef OPENBSD
#include <libnet-1.1/libnet.h>
#include <netinet/if_ether.h>
#else /* !OPENBSD */
#include <libnet.h>
#include <net/ethernet.h>
#endif /* !OPENBSD */

#define MSS_VAL 1420

#ifdef OPENBSD
#define PF_PACKET PF_ROUTE /* Packet family */
#endif /* OPENBSD */

typedef struct pcap_file_hdr {
	unsigned int magic_number; /* magic number */
	unsigned short version_major; /* major version number */
	unsigned short version_minor; /* minor version number */
	unsigned int thiszone; /* GMT to local correction */
	unsigned int sigfigs; /* accuracy of timestamps */
	unsigned int snaplen; /* max length of captured packets, in octets */
	unsigned int network; /* data link type */
} pcap_file_hdr_t;

typedef struct pcap_rec_hdr {
	unsigned int ts_sec; /* timestamp seconds */
	unsigned int ts_usec; /* timestamp microseconds */
	unsigned int incl_len; /* number of octets of packet saved in file */
	unsigned int orig_len; /* actual length of packet */
} pcap_rec_hdr_t;

typedef struct pcap_packet {
	time_t epoch;
	unsigned int src_ip;
	struct libnet_in6_addr src_ip6;
	unsigned int dst_ip;
	struct libnet_in6_addr dst_ip6;
	int af;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int ack;
	unsigned int seq;
	unsigned char dst_ether[ETHER_ADDR_LEN];
} pcap_packet_t;

libnet_t *libnet_pcap;
libnet_t *libnet_mirror;
struct libnet_ether_addr *mirrorsender_ether;

int logpkt_write_global_pcap_hdr(int);
int logpkt_set_packet_fields(libnet_t *, pcap_packet_t *, char *, char *, char *, char *);
int logpkt_write_packet(libnet_t *, int, pcap_packet_t *, char, const unsigned char *, size_t);
int logpkt_write_payload(libnet_t *, int, pcap_packet_t *, pcap_packet_t *, char, const unsigned char *, size_t);
int logpkt_check_mirrortarget(char *, char *, char *);

#endif /* !LOGPKT_H */
