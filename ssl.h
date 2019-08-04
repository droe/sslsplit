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

#ifndef SSL_H
#define SSL_H

#include "attrib.h"

#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/*
 * LibreSSL seems to ship engine support on a source code level, but it seems
 * to be broken.  Tested with LibreSSL 2.7.4 on OpenBSD and macOS.  For now,
 * disable engine support when building against LibreSSL.
 */
#if defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_NO_ENGINE)
#define OPENSSL_NO_ENGINE
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10000000L) && !defined(OPENSSL_NO_THREADID)
#define OPENSSL_NO_THREADID
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090806FL) && !defined(OPENSSL_NO_TLSEXT)
#define OPENSSL_NO_TLSEXT
#endif

/*
 * ECDH is disabled when building against OpenSSL < 1.0.0e due to issues with
 * thread-safety and security in server mode ephemereal ECDH cipher suites.
 * http://www.openssl.org/news/secadv_20110906.txt
 */
#if (OPENSSL_VERSION_NUMBER < 0x1000005FL) && !defined(OPENSSL_NO_ECDH)
#define OPENSSL_NO_ECDH
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090802FL) && !defined(OPENSSL_NO_ECDSA)
#define OPENSSL_NO_ECDSA
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090802FL) && !defined(OPENSSL_NO_EC)
#define OPENSSL_NO_EC
#endif

/*
 * SHA0 was removed in OpenSSL 1.1.0, including OPENSSL_NO_SHA0.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_NO_SHA0)
#define OPENSSL_NO_SHA0
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x2050100fL
#define SSL_is_server(ssl) ((ssl)->server)
#else /* < LibreSSL 2.5.1 and OpenSSL < 1.1.0 */
#define SSL_is_server(ssl) ((ssl)->type != SSL_ST_CONNECT)
#endif /* < LibreSSL 2.5.1 and OpenSSL < 1.1.0 */
#define ASN1_STRING_get0_data(value) ASN1_STRING_data(value)
#define X509_get_signature_nid(x509) (OBJ_obj2nid(x509->sig_alg->algorithm))
int DH_set0_pqg(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
#endif /* < OpenSSL 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x1000000fL
static inline int EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
	return EVP_PKEY_type(pkey->type);
}
static inline int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub)
{
	if (ppkalg)
		*ppkalg = pub->algor->algorithm;
	if (pk) {
		*pk = pub->public_key->data;
		*ppklen = pub->public_key->length;
	}
	if (pa)
		*pa = pub->algor;
	return 1;
}
#ifndef X509_get_X509_PUBKEY
#define X509_get_X509_PUBKEY(x) ((x)->cert_info->key
#endif
#endif /* OpenSSL < 1.0.0 */

/*
 * The constructors returning a SSL_METHOD * were changed to return
 * a const SSL_METHOD * between 0.9.8 and 1.0.0.
 */
#if (OPENSSL_VERSION_NUMBER < 0x1000000fL)
#define CONST_SSL_METHOD SSL_METHOD
#else /* >= OpenSSL 1.0.0 */
#define CONST_SSL_METHOD const SSL_METHOD
#endif /* >= OpensSL 1.0.0 */

/*
 * Workaround for bug in OpenSSL 0.9.8y, 1.0.0k and 1.0.1e
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=703031
 * http://openssl.6102.n7.nabble.com/NULL-ptr-deref-when-calling-SSL-get-certificate-with-1-0-0k-td43636.html
 */
#if (OPENSSL_VERSION_NUMBER == 0x0090819fL) || \
    (OPENSSL_VERSION_NUMBER == 0x100000bfL) || \
    (OPENSSL_VERSION_NUMBER == 0x1000105fL)
#define SSL_get_certificate(x) ssl_ssl_cert_get(x)
X509 * ssl_ssl_cert_get(SSL *);
#endif /* OpenSSL 0.9.8y or 1.0.0k or 1.0.1e */

#ifdef OPENSSL_NO_TLSEXT
#ifndef TLSEXT_MAXLEN_host_name
#define TLSEXT_MAXLEN_host_name 255
#endif /* !TLSEXT_MAXLEN_host_name */
#endif /* OPENSSL_NO_TLSEXT */

/*
 * SSL_OP_NO_* is used as an indication that OpenSSL is sufficiently recent
 * to have the respective protocol implemented.
 *
 * OPENSSL_NO_SSL2 indicates the complete removal of SSL 2.0 support.
 *
 * OPENSSL_NO_SSL3 indicates that no SSL 3.0 connections will be made by
 * default, but support is still present, unless OPENSSL_NO_SSL3_METHOD is
 * also defined.
 */
#if defined(SSL_OP_NO_SSLv2) && !defined(OPENSSL_NO_SSL2) && \
    defined(WITH_SSLV2)
#define HAVE_SSLV2
#endif /* SSL_OP_NO_SSLv2 && !OPENSSL_NO_SSL2 && WITH_SSLV2 */
#if defined(SSL_OP_NO_SSLv3) && !defined(OPENSSL_NO_SSL3_METHOD)
#define HAVE_SSLV3
#endif /* SSL_OP_NO_SSLv2 && !OPENSSL_NO_SSL3_METHOD */
#ifdef SSL_OP_NO_TLSv1
#define HAVE_TLSV10
#endif /* SSL_OP_NO_TLSv1 */
#ifdef SSL_OP_NO_TLSv1_1
#define HAVE_TLSV11
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
#define HAVE_TLSV12
#endif /* SSL_OP_NO_TLSv1_2 */

#ifdef HAVE_SSLV2
#define SSL2_S "ssl2 "
#else /* !HAVE_SSLV2 */
#define SSL2_S ""
#endif /* !HAVE_SSLV2 */
#ifdef HAVE_SSLV3
#define SSL3_S "ssl3 "
#else /* !HAVE_SSLV3 */
#define SSL3_S ""
#endif /* !HAVE_SSLV3 */
#ifdef HAVE_TLSV10
#define TLS10_S "tls10 "
#else /* !HAVE_TLSV10 */
#define TLS10_S ""
#endif /* !HAVE_TLSV10 */
#ifdef HAVE_TLSV11
#define TLS11_S "tls11 "
#else /* !HAVE_TLSV11 */
#define TLS11_S ""
#endif /* !HAVE_TLSV11 */
#ifdef HAVE_TLSV12
#define TLS12_S "tls12 "
#else /* !HAVE_TLSV12 */
#define TLS12_S ""
#endif /* !HAVE_TLSV12 */
#define SSL_PROTO_SUPPORT_S SSL2_S SSL3_S TLS10_S TLS11_S TLS12_S

void ssl_openssl_version(void);
int ssl_init(void) WUNRES;
int ssl_reinit(void) WUNRES;
void ssl_fini(void);

#ifndef OPENSSL_NO_ENGINE
int ssl_engine(const char *) WUNRES;
#endif /* !OPENSSL_NO_ENGINE */

char * ssl_sha1_to_str(unsigned char *, int) NONNULL(1) MALLOC;

char * ssl_ssl_state_to_str(SSL *) NONNULL(1) MALLOC;
char * ssl_ssl_masterkey_to_str(SSL *) NONNULL(1) MALLOC;

#ifndef OPENSSL_NO_DH
DH * ssl_tmp_dh_callback(SSL *, int, int) NONNULL(1) MALLOC;
DH * ssl_dh_load(const char *) NONNULL(1) MALLOC;
void ssl_dh_refcount_inc(DH *) NONNULL(1);
#endif /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC
EC_KEY * ssl_ec_by_name(const char *) MALLOC;
#endif /* !OPENSSL_NO_EC */

EVP_PKEY * ssl_key_load(const char *) NONNULL(1) MALLOC;
EVP_PKEY * ssl_key_genrsa(const int) MALLOC;
void ssl_key_refcount_inc(EVP_PKEY *) NONNULL(1);
#define SSL_KEY_IDSZ 20
int ssl_key_identifier_sha1(EVP_PKEY *, unsigned char *) NONNULL(1,2);
char * ssl_key_identifier(EVP_PKEY *, int) NONNULL(1) MALLOC;

#ifndef OPENSSL_NO_TLSEXT
int ssl_x509_v3ext_add(X509V3_CTX *, X509 *, char *, char *) NONNULL(1,2,3,4);
int ssl_x509_v3ext_copy_by_nid(X509 *, X509 *, int) NONNULL(1,2);
#endif /* !OPENSSL_NO_TLSEXT */
int ssl_x509_serial_copyrand(X509 *, X509 *) NONNULL(1,2);
X509 * ssl_x509_forge(X509 *, EVP_PKEY *, X509 *, EVP_PKEY *,
                      const char *, const char *)
       NONNULL(1,2,3,4) MALLOC;
X509 * ssl_x509_load(const char *) NONNULL(1) MALLOC;
char * ssl_x509_subject(X509 *) NONNULL(1) MALLOC;
char * ssl_x509_subject_cn(X509 *, size_t *) NONNULL(1,2) MALLOC;
#define SSL_X509_FPRSZ 20
int ssl_x509_fingerprint_sha1(X509 *, unsigned char *) NONNULL(1,2);
char * ssl_x509_fingerprint(X509 *, int) NONNULL(1) MALLOC;
char ** ssl_x509_names(X509 *) NONNULL(1) MALLOC;
int ssl_x509_names_match(X509 *, const char *) NONNULL(1,2);
char * ssl_x509_names_to_str(X509 *) NONNULL(1) MALLOC;
char ** ssl_x509_aias(X509 *, const int) NONNULL(1) MALLOC;
char ** ssl_x509_ocsps(X509 *) NONNULL(1) MALLOC;
int ssl_x509_is_valid(X509 *) NONNULL(1) WUNRES;
char * ssl_x509_to_str(X509 *) NONNULL(1) MALLOC;
char * ssl_x509_to_pem(X509 *) NONNULL(1) MALLOC;
void ssl_x509_refcount_inc(X509 *) NONNULL(1);

int ssl_x509chain_load(X509 **, STACK_OF(X509) **, const char *) NONNULL(2,3);
int ssl_x509chain_use(SSL_CTX *, X509 *, STACK_OF(X509) *)
    NONNULL(1,2,3) WUNRES;

char * ssl_session_to_str(SSL_SESSION *) NONNULL(1) MALLOC;
int ssl_session_is_valid(SSL_SESSION *) NONNULL(1);

int ssl_is_ocspreq(const unsigned char *, size_t) NONNULL(1) WUNRES;

int ssl_tls_clienthello_parse(const unsigned char *, ssize_t, int,
                              const unsigned char **, char **)
    NONNULL(1,4) WUNRES;
int ssl_dnsname_match(const char *, size_t, const char *, size_t)
    NONNULL(1,3) WUNRES;
char * ssl_wildcardify(const char *) NONNULL(1) MALLOC;

#endif /* !SSL_H */

/* vim: set noet ft=c: */
