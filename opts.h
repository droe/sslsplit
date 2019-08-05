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

#ifndef OPTS_H
#define OPTS_H

#include "proc.h"
#include "nat.h"
#include "ssl.h"
#include "cert.h"
#include "attrib.h"

typedef struct proxyspec {
	unsigned int ssl : 1;
	unsigned int http : 1;
	unsigned int upgrade: 1;
	unsigned int dns : 1;		/* set if spec needs DNS lookups */
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
#ifdef HAVE_SSLV2
	unsigned int no_ssl2 : 1;
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	unsigned int no_ssl3 : 1;
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	unsigned int no_tls10 : 1;
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	unsigned int no_tls11 : 1;
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	unsigned int no_tls12 : 1;
#endif /* HAVE_TLSV12 */
	unsigned int passthrough : 1;
	unsigned int deny_ocsp : 1;
	unsigned int contentlog_isdir : 1;
	unsigned int contentlog_isspec : 1;
	unsigned int pcaplog_isdir : 1;
	unsigned int pcaplog_isspec : 1;
#ifdef HAVE_LOCAL_PROCINFO
	unsigned int lprocinfo : 1;
#endif /* HAVE_LOCAL_PROCINFO */
	unsigned int certgen_writeall : 1;
#ifndef OPENSSL_NO_ENGINE
	char *openssl_engine;
#endif /* !OPENSSL_NO_ENGINE */
	char *ciphers;
	char *certgendir;
	char *leafcertdir;
	char *leafcrlurl;
	char *dropuser;
	char *dropgroup;
	char *jaildir;
	char *pidfile;
	char *conffile;
	char *connectlog;
	char *contentlog;
	char *contentlog_basedir; /* static part of logspec for privsep srv */
	char *masterkeylog;
	char *pcaplog;
	char *pcaplog_basedir; /* static part of pcap logspec for privsep srv */
#ifndef WITHOUT_MIRROR
	char *mirrorif;
	char *mirrortarget;
#endif /* !WITHOUT_MIRROR */
	CONST_SSL_METHOD *(*sslmethod)(void);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	int sslversion;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	X509 *cacrt;
	EVP_PKEY *cakey;
	STACK_OF(X509) *cachain;
	EVP_PKEY *leafkey;
	cert_t *defaultleafcert;
	X509 *clientcrt;
	EVP_PKEY *clientkey;
#ifndef OPENSSL_NO_DH
	DH *dh;
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	char *ecdhcurve;
#endif /* !OPENSSL_NO_ECDH */
	proxyspec_t *spec;
	unsigned int verify_peer: 1;
	unsigned int allow_wrong_host: 1;
} opts_t;

void NORET oom_die(const char *) NONNULL(1);
cert_t *opts_load_cert_chain_key(const char *) NONNULL(1);

opts_t *opts_new(void) MALLOC;
void opts_free(opts_t *) NONNULL(1);
int opts_has_ssl_spec(opts_t *) NONNULL(1) WUNRES;
int opts_has_dns_spec(opts_t *) NONNULL(1) WUNRES;
void opts_proto_dbg_dump(opts_t *) NONNULL(1);
#define OPTS_DEBUG(opts) unlikely((opts)->debug)

void proxyspec_parse(int *, char **[], const char *, proxyspec_t **);
void proxyspec_free(proxyspec_t *) NONNULL(1);
char *proxyspec_str(proxyspec_t *) NONNULL(1) MALLOC;

void opts_set_cacrt(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_cakey(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_cachain(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_leafkey(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_leafcrlurl(opts_t *, const char *) NONNULL(1,2);
void opts_set_leafcertdir(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_defaultleafcert(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_certgendir_writeall(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_certgendir_writegencerts(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_deny_ocsp(opts_t *) NONNULL(1);
void opts_set_passthrough(opts_t *) NONNULL(1);
void opts_set_clientcrt(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_clientkey(opts_t *, const char *, const char *) NONNULL(1,2,3);
#ifndef OPENSSL_NO_DH
void opts_set_dh(opts_t *, const char *, const char *) NONNULL(1,2,3);
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
void opts_set_ecdhcurve(opts_t *, const char *, const char *) NONNULL(1,2,3);
#endif /* !OPENSSL_NO_ECDH */
void opts_unset_sslcomp(opts_t *) NONNULL(1);
void opts_force_proto(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_disable_proto(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_ciphers(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_openssl_engine(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_user(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_group(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_jaildir(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_pidfile(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_connectlog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_contentlog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_contentlogdir(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_contentlogpathspec(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
#ifdef HAVE_LOCAL_PROCINFO
void opts_set_lprocinfo(opts_t *) NONNULL(1);
#endif /* HAVE_LOCAL_PROCINFO */
void opts_set_masterkeylog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_pcaplog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_pcaplogdir(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_pcaplogpathspec(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
#ifndef WITHOUT_MIRROR
void opts_set_mirrorif(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_mirrortarget(opts_t *, const char *, const char *) NONNULL(1,2,3);
#endif /* !WITHOUT_MIRROR */
void opts_set_daemon(opts_t *) NONNULL(1);
void opts_set_debug(opts_t *) NONNULL(1);
int opts_set_option(opts_t *, const char *, const char *, char **)
    NONNULL(1,2,3);

int load_conffile(opts_t *, const char *, char **) NONNULL(1,2);
#endif /* !OPTS_H */

/* vim: set noet ft=c: */
