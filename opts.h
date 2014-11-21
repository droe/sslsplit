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

#ifndef OPTS_H
#define OPTS_H

#include "proc.h"
#include "nat.h"
#include "ssl.h"
#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

typedef struct proxyspec {
	unsigned int ssl : 1;
	unsigned int http : 1;
	struct sockaddr_storage listen_addr;
	socklen_t listen_addrlen;
	/* connect_addr and connect_addrlen are set: static mode;
	 * natlookup is set: NAT mode; natsocket /may/ be set too;
	 * sni_port is set, in which case we use SNI lookups */
	struct sockaddr_storage connect_addr;
	socklen_t connect_addrlen;
	unsigned short sni_port;
	char *natengine;
	nat_lookup_cb_t natlookup;
	nat_socket_cb_t natsocket;
	struct proxyspec *next;
} proxyspec_t;

typedef struct opts {
	unsigned int debug : 1;
	unsigned int detach : 1;
	unsigned int sslcomp : 1;
#if defined(SSL_OP_NO_SSLv2) && defined(WITH_SSLV2)
	unsigned int no_ssl2 : 1;
#endif /* SSL_OP_NO_SSLv2 && WITH_SSLV2 */
#ifdef SSL_OP_NO_SSLv3
	unsigned int no_ssl3 : 1;
#endif /* SSL_OP_NO_SSLv3 */
#ifdef SSL_OP_NO_TLSv1
	unsigned int no_tls10 : 1;
#endif /* SSL_OP_NO_TLSv1 */
#ifdef SSL_OP_NO_TLSv1_1
	unsigned int no_tls11 : 1;
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
	unsigned int no_tls12 : 1;
#endif /* SSL_OP_NO_TLSv1_2 */
	unsigned int passthrough : 1;
	unsigned int deny_ocsp : 1;
	unsigned int contentlog_isdir : 1;
	unsigned int contentlog_isspec : 1;
#ifdef HAVE_LOCAL_PROCINFO
	unsigned int lprocinfo : 1;
#endif /* HAVE_LOCAL_PROCINFO */
	char *ciphers;
	char *tgcrtdir;
	char *dropuser;
	char *dropgroup;
	char *jaildir;
	char *pidfile;
	char *connectlog;
	char *contentlog;
	CONST_SSL_METHOD *(*sslmethod)(void);
	X509 *cacrt;
	EVP_PKEY *cakey;
	EVP_PKEY *key;
	STACK_OF(X509) *chain;
#ifndef OPENSSL_NO_DH
	DH *dh;
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	char *ecdhcurve;
#endif /* !OPENSSL_NO_ECDH */
	proxyspec_t *spec;
} opts_t;

opts_t *opts_new(void) MALLOC;
void opts_free(opts_t *) NONNULL(1);
int opts_has_ssl_spec(opts_t *) NONNULL(1) WUNRES;
void opts_proto_force(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_proto_disable(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_proto_dbg_dump(opts_t *) NONNULL(1);
#define OPTS_DEBUG(opts) unlikely((opts)->debug)

proxyspec_t * proxyspec_parse(int *, char **[], const char *) MALLOC;
void proxyspec_free(proxyspec_t *) NONNULL(1);

#endif /* !OPTS_H */

/* vim: set noet ft=c: */
