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

#ifndef LOGPKT_H
#define LOGPKT_H

#include "attrib.h"

#include <sys/socket.h>
#include <stdint.h>
#include <time.h>

#ifndef WITHOUT_MIRROR
#include <libnet.h>
#else /* WITHOUT_MIRROR */
#define libnet_t void
#define ETHER_ADDR_LEN 6
#endif /* WITHOUT_MIRROR */

typedef struct {
	libnet_t *libnet;
	uint8_t src_ether[ETHER_ADDR_LEN];
	uint8_t dst_ether[ETHER_ADDR_LEN];
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	uint32_t src_seq;
	uint32_t dst_seq;
	size_t mss;
} logpkt_ctx_t;

#define LOGPKT_REQUEST  0
#define LOGPKT_RESPONSE 1

int logpkt_pcap_open_fd(int fd) WUNRES;
void logpkt_ctx_init(logpkt_ctx_t *, libnet_t *, size_t,
                     const uint8_t *, const uint8_t *,
                     const struct sockaddr *, socklen_t,
                     const struct sockaddr *, socklen_t);
int logpkt_write_payload(logpkt_ctx_t *, int, int,
                         const unsigned char *, size_t) WUNRES;
int logpkt_write_close(logpkt_ctx_t *, int, int);
int logpkt_ether_lookup(libnet_t *, uint8_t *, uint8_t *,
                        const char *, const char *) WUNRES;

#endif /* !LOGPKT_H */
