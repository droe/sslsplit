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

#include "attrib.h"

#include <stdint.h>
#include <time.h>

#include <libnet.h>

typedef union {
	uint32_t ip4;
	struct libnet_in6_addr ip6;
} logpkt_ip46addr_t;

typedef struct {
	libnet_t *libnet;
	uint8_t src_ether[ETHER_ADDR_LEN];
	uint8_t dst_ether[ETHER_ADDR_LEN];
	logpkt_ip46addr_t src_ip;
	logpkt_ip46addr_t dst_ip;
	int af;
	size_t mss;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_seq;
	uint32_t dst_seq;
} logpkt_ctx_t;

#define LOGPKT_REQUEST  0
#define LOGPKT_RESPONSE 1

int logpkt_pcap_open_fd(int fd) WUNRES;
int logpkt_ctx_init(logpkt_ctx_t *, libnet_t *,
                    const uint8_t *, const uint8_t *,
                    const char *, const char *, const char *, const char *)
    WUNRES;
int logpkt_write_payload(logpkt_ctx_t *, int, int,
                         const unsigned char *, size_t) WUNRES;
int logpkt_write_close(logpkt_ctx_t *, int, int);
int logpkt_ether_lookup(libnet_t *, uint8_t *, uint8_t *,
                        const char *, const char *) WUNRES;

#endif /* !LOGPKT_H */
