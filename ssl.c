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

#include "ssl.h"

#include "log.h"
#include "defaults.h"
#include "attrib.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <openssl/crypto.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* !OPENSSL_NO_ENGINE */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif /* !OPENSSL_NO_DH */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>


/*
 * Collection of helper functions on top of the OpenSSL API.
 */


/*
 * Workaround for bug in OpenSSL 1.0.0k and 1.0.1e
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=703031
 * http://openssl.6102.n7.nabble.com/NULL-ptr-deref-when-calling-SSL-get-certificate-with-1-0-0k-td43636.html
 */
#if (OPENSSL_VERSION_NUMBER == 0x0090819fL) || \
    (OPENSSL_VERSION_NUMBER == 0x100000bfL) || \
    (OPENSSL_VERSION_NUMBER == 0x1000105fL)
/*
 * OpenSSL internal declarations from ssl_locl.h, reduced to what is needed.
 */
struct cert_pkey_st {
	X509 *x509;
	/*
	EVP_PKEY *privatekey;
	const EVP_MD *digest;
	*/
};
struct cert_st {
	struct cert_pkey_st *key;
	/* ... */
};

/*
 * Replacement function for SSL_get_certificate().
 */
X509 *
ssl_ssl_cert_get(SSL *s)
{
	return s->cert ? s->cert->key->x509 : NULL;
}
#endif /* OpenSSL 0.9.8y, 1.0.0k or 1.0.1e */

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/*
	 * If the fields p and g in d are NULL, the corresponding input
	 * parameters MUST be non-NULL.  q may remain NULL.
	 */
	if ((dh->p == NULL && p == NULL) || (dh->g == NULL && g == NULL))
		return 0;

	if (p != NULL) {
		BN_free(dh->p);
		dh->p = p;
	}
	if (q != NULL) {
		BN_free(dh->q);
		dh->q = q;
		dh->length = BN_num_bits(q);
	}
	if (g != NULL) {
		BN_free(dh->g);
		dh->g = g;
	}

	return 1;
}
#endif


/*
 * Print OpenSSL version and build-time configuration to standard error and
 * return.
 */
void
ssl_openssl_version(void)
{
	fprintf(stderr, "compiled against %s (%lx)\n",
	                OPENSSL_VERSION_TEXT,
	                (long unsigned int)OPENSSL_VERSION_NUMBER);
	fprintf(stderr, "rtlinked against %s (%lx)\n",
	                SSLeay_version(SSLEAY_VERSION),
	                SSLeay());
	if ((OPENSSL_VERSION_NUMBER ^ SSLeay()) & 0xfffff000L) {
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
		fprintf(stderr, "WARNING: OpenSSL version mismatch may "
		                "lead to crashes or other problems!\n");
		fprintf(stderr, "If there are multiple versions of "
		                "OpenSSL available, make sure to use\n");
		fprintf(stderr, "the same version of the library at "
		                "runtime as well as for compiling against.\n");
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
	}
#ifdef LIBRESSL_VERSION_NUMBER
	fprintf(stderr, "OpenSSL API provided by LibreSSL: %s (%lx)\n",
	                LIBRESSL_VERSION_TEXT,
	                (long unsigned int)LIBRESSL_VERSION_NUMBER);
#endif /* LIBRESSL_VERSION_NUMBER */
#ifdef OPENSSL_IS_BORINGSSL
	fprintf(stderr, "OpenSSL API provided by BoringSSL\n")
#endif /* OPENSSL_IS_BORINGSSL */
#ifndef OPENSSL_NO_TLSEXT
	fprintf(stderr, "OpenSSL has support for TLS extensions\n"
	                "TLS Server Name Indication (SNI) supported\n");
#else /* OPENSSL_NO_TLSEXT */
	fprintf(stderr, "OpenSSL has no support for TLS extensions\n"
	                "TLS Server Name Indication (SNI) not supported\n");
#endif /* OPENSSL_NO_TLSEXT */
#ifdef OPENSSL_THREADS
#ifndef OPENSSL_NO_THREADID
	fprintf(stderr, "OpenSSL is thread-safe with THREADID\n");
#else /* OPENSSL_NO_THREADID */
	fprintf(stderr, "OpenSSL is thread-safe without THREADID\n");
#endif /* OPENSSL_NO_THREADID */
#else /* !OPENSSL_THREADS */
	fprintf(stderr, "OpenSSL is not thread-safe\n");
#endif /* !OPENSSL_THREADS */
#ifndef OPENSSL_NO_ENGINE
	fprintf(stderr, "OpenSSL has engine support\n");
#else /* OPENSSL_NO_ENGINE */
	fprintf(stderr, "OpenSSL has no engine support\n");
#endif /* OPENSSL_NO_ENGINE */
#ifdef SSL_MODE_RELEASE_BUFFERS
	fprintf(stderr, "Using SSL_MODE_RELEASE_BUFFERS\n");
#else /* !SSL_MODE_RELEASE_BUFFERS */
	fprintf(stderr, "Not using SSL_MODE_RELEASE_BUFFERS\n");
#endif /* !SSL_MODE_RELEASE_BUFFERS */
#if (OPENSSL_VERSION_NUMBER == 0x0090819fL) || \
    (OPENSSL_VERSION_NUMBER == 0x100000bfL) || \
    (OPENSSL_VERSION_NUMBER == 0x1000105fL)
	fprintf(stderr, "Using direct access workaround when loading certs\n");
#endif /* OpenSSL 0.9.8y, 1.0.0k or 1.0.1e */

	fprintf(stderr, "SSL/TLS protocol availability: %s\n",
	                SSL_PROTO_SUPPORT_S);

	fprintf(stderr, "SSL/TLS algorithm availability:");
#ifndef OPENSSL_NO_SHA0
	fprintf(stderr, " SHA0");
#else /* !OPENSSL_NO_SHA0 */
	fprintf(stderr, " !SHA0");
#endif /* !OPENSSL_NO_SHA0 */
#ifndef OPENSSL_NO_RSA
	fprintf(stderr, " RSA");
#else /* !OPENSSL_NO_RSA */
	fprintf(stderr, " !RSA");
#endif /* !OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	fprintf(stderr, " DSA");
#else /* !OPENSSL_NO_DSA */
	fprintf(stderr, " !DSA");
#endif /* !OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
	fprintf(stderr, " ECDSA");
#else /* !OPENSSL_NO_ECDSA */
	fprintf(stderr, " !ECDSA");
#endif /* !OPENSSL_NO_ECDSA */
#ifndef OPENSSL_NO_DH
	fprintf(stderr, " DH");
#else /* !OPENSSL_NO_DH */
	fprintf(stderr, " !DH");
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	fprintf(stderr, " ECDH");
#else /* !OPENSSL_NO_ECDH */
	fprintf(stderr, " !ECDH");
#endif /* !OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_EC
	fprintf(stderr, " EC");
#else /* !OPENSSL_NO_EC */
	fprintf(stderr, " !EC");
#endif /* !OPENSSL_NO_EC */
	fprintf(stderr, "\n");

	fprintf(stderr, "OpenSSL option availability:");
#ifdef SSL_OP_NO_COMPRESSION
	fprintf(stderr, " SSL_OP_NO_COMPRESSION");
#else /* !SSL_OP_NO_COMPRESSION */
	fprintf(stderr, " !SSL_OP_NO_COMPRESSION");
#endif /* SSL_OP_NO_COMPRESSION */
#ifdef SSL_OP_NO_TICKET
	fprintf(stderr, " SSL_OP_NO_TICKET");
#else /* !SSL_OP_NO_TICKET */
	fprintf(stderr, " !SSL_OP_NO_TICKET");
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	fprintf(stderr, " SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION");
#else /* !SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
	fprintf(stderr, " !SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION");
#endif /* !SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	fprintf(stderr, " SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS");
#else /* !SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
	fprintf(stderr, " !SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS");
#endif /* !SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	fprintf(stderr, " SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION");
#else /* !SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */
	fprintf(stderr, " !SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION");
#endif /* !SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	fprintf(stderr, " SSL_OP_TLS_ROLLBACK_BUG");
#else /* !SSL_OP_TLS_ROLLBACK_BUG */
	fprintf(stderr, " !SSL_OP_TLS_ROLLBACK_BUG");
#endif /* !SSL_OP_TLS_ROLLBACK_BUG */
	fprintf(stderr, "\n");
}

/*
 * 1 if OpenSSL has been initialized, 0 if not.  When calling a _load()
 * function the first time, OpenSSL will automatically be initialized.
 * Not protected by a mutex and thus not thread-safe.
 */
static int ssl_initialized = 0;

#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
};
static pthread_mutex_t *ssl_mutex;
static int ssl_mutex_num;

/*
 * OpenSSL thread-safety locking callback, #1.
 */
static void
ssl_thr_locking_cb(int mode, int type, UNUSED const char *file,
                   UNUSED int line) {
	if (type < ssl_mutex_num) {
		if (mode & CRYPTO_LOCK)
			pthread_mutex_lock(&ssl_mutex[type]);
		else
			pthread_mutex_unlock(&ssl_mutex[type]);
	}
}

/*
 * OpenSSL thread-safety locking callback, #2.
 */
static struct CRYPTO_dynlock_value *
ssl_thr_dyn_create_cb(UNUSED const char *file, UNUSED int line)
{
	struct CRYPTO_dynlock_value *dl;

	if ((dl = malloc(sizeof(struct CRYPTO_dynlock_value)))) {
		if (pthread_mutex_init(&dl->mutex, NULL)) {
			free(dl);
			return NULL;
		}
	}
	return dl;
}

/*
 * OpenSSL thread-safety locking callback, #3.
 */
static void
ssl_thr_dyn_lock_cb(int mode, struct CRYPTO_dynlock_value *dl,
                    UNUSED const char *file, UNUSED int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&dl->mutex);
	} else {
		pthread_mutex_unlock(&dl->mutex);
	}
}

/*
 * OpenSSL thread-safety locking callback, #4.
 */
static void
ssl_thr_dyn_destroy_cb(struct CRYPTO_dynlock_value *dl,
                       UNUSED const char *file, UNUSED int line)
{
	pthread_mutex_destroy(&dl->mutex);
	free(dl);
}

#ifdef OPENSSL_NO_THREADID
/*
 * OpenSSL thread-safety thread ID callback, legacy version.
 */
static unsigned long
ssl_thr_id_cb(void) {
	return (unsigned long) pthread_self();
}
#else /* !OPENSSL_NO_THREADID */
/*
 * OpenSSL thread-safety thread ID callback, up-to-date version.
 */
static void
ssl_thr_id_cb(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long) pthread_self());
}
#endif /* !OPENSSL_NO_THREADID */
#endif /* OPENSSL_THREADS */

/*
 * Initialize OpenSSL and verify the random number generator works.
 * Returns -1 on failure, 0 on success.
 */
int
ssl_init(void)
{
#ifndef PURIFY
	int fd;
#endif /* !PURIFY */
	char buf[256];

	if (ssl_initialized)
		return 0;

	/* general initialization */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG
#ifndef OPENSSL_NO_ENGINE
	                    |OPENSSL_INIT_ENGINE_ALL_BUILTIN
#endif /* !OPENSSL_NO_ENGINE */
	                    , NULL);
	OPENSSL_init_ssl(0, NULL);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	SSL_library_init();
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef PURIFY
	CRYPTO_malloc_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif /* PURIFY */
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	OPENSSL_config(NULL);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

	/* thread-safety */
#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	ssl_mutex_num = CRYPTO_num_locks();
	ssl_mutex = malloc(ssl_mutex_num * sizeof(*ssl_mutex));
	for (int i = 0; i < ssl_mutex_num; i++) {
		if (pthread_mutex_init(&ssl_mutex[i], NULL)) {
			log_err_printf("Failed to initialize mutex\n");
			return -1;
		}
	}
	CRYPTO_set_locking_callback(ssl_thr_locking_cb);
	CRYPTO_set_dynlock_create_callback(ssl_thr_dyn_create_cb);
	CRYPTO_set_dynlock_lock_callback(ssl_thr_dyn_lock_cb);
	CRYPTO_set_dynlock_destroy_callback(ssl_thr_dyn_destroy_cb);
#ifdef OPENSSL_NO_THREADID
	CRYPTO_set_id_callback(ssl_thr_id_cb);
#else /* !OPENSSL_NO_THREADID */
	CRYPTO_THREADID_set_callback(ssl_thr_id_cb);
#endif /* !OPENSSL_NO_THREADID */
#endif /* OPENSSL_THREADS && OPENSSL_VERSION_NUMBER < 0x10100000L */

	/* randomness */
#ifndef PURIFY
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		log_err_printf("Error opening /dev/urandom for reading: %s\n",
		               strerror(errno));
		return -1;
	}
	while (!RAND_status()) {
		if (read(fd, buf, sizeof(buf)) == -1) {
			log_err_printf("Error reading from /dev/urandom: %s\n",
			               strerror(errno));
			close(fd);
			return -1;
		}
		RAND_seed(buf, sizeof(buf));
	}
	close(fd);
	if (!RAND_poll()) {
		log_err_printf("RAND_poll() failed.\n");
		return -1;
	}
#else /* PURIFY */
	log_err_printf("Warning: not seeding OpenSSL RAND due to PURITY!\n");
	memset(buf, 0, sizeof(buf));
	while (!RAND_status()) {
		RAND_seed(buf, sizeof(buf));
	}
#endif /* PURIFY */

#ifdef USE_FOOTPRINT_HACKS
	/* HACK: disable compression by zeroing the global comp algo stack.
	 * This lowers the per-connection memory footprint by ~500k. */
	STACK_OF(SSL_COMP)* comp_methods = SSL_COMP_get_compression_methods();
	sk_SSL_COMP_zero(comp_methods);
#endif /* USE_FOOTPRINT_HACKS */

	ssl_initialized = 1;
	return 0;
}

/*
 * Re-initialize OpenSSL after forking.  Returns 0 on success, -1 on failure.
 */
int
ssl_reinit(void)
{
	if (!ssl_initialized)
		return 0;

#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	for (int i = 0; i < ssl_mutex_num; i++) {
		if (pthread_mutex_init(&ssl_mutex[i], NULL)) {
			return -1;
		}
	}
#endif /* OPENSSL_THREADS */

	return 0;
}

/*
 * Deinitialize OpenSSL and free as much memory as possible.
 * Some 10k-100k will still remain resident no matter what.
 */
void
ssl_fini(void)
{
	if (!ssl_initialized)
		return;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	ERR_remove_state(0); /* current thread */
#endif

#if defined(OPENSSL_THREADS) && \
    ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	CRYPTO_set_id_callback(NULL);
#else /* !OPENSSL_NO_THREADID */
	CRYPTO_THREADID_set_callback(NULL);
#endif /* !OPENSSL_NO_THREADID */
	for (int i = 0; i < ssl_mutex_num; i++) {
		pthread_mutex_destroy(&ssl_mutex[i]);
	}
	free(ssl_mutex);
#endif

#if !defined(OPENSSL_NO_ENGINE) && \
    ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	ENGINE_cleanup();
#endif /* !OPENSSL_NO_ENGINE && OPENSSL_VERSION_NUMBER < 0x10100000L */
	CONF_modules_finish();
	CONF_modules_unload(1);
	CONF_modules_free();

	EVP_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();

	ssl_initialized = 0;
}

/*
 * Look up an OpenSSL engine by ID or by full path and load it as default
 * engine.  This works globally, not on specific SSL_CTX or SSL instances.
 * OpenSSL must already have been initialized when calling this function.
 * Returns 0 on success, -1 on failure.
 */
#ifndef OPENSSL_NO_ENGINE
int
ssl_engine(const char *name) {
	ENGINE *engine;

	engine = ENGINE_by_id(name);
	if (!engine)
		return -1;

	if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL))
		return -1;
	return 0;
}
#endif /* !OPENSSL_NO_ENGINE */

/*
 * Format raw SHA1 hash into newly allocated string, with or without colons.
 */
char *
ssl_sha1_to_str(unsigned char *rawhash, int colons)
{
	char *str;
	int rv;

	rv = asprintf(&str, colons ?
	              "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:"
	              "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X" :
	              "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	              rawhash[ 0], rawhash[ 1], rawhash[ 2], rawhash[ 3],
	              rawhash[ 4], rawhash[ 5], rawhash[ 6], rawhash[ 7],
	              rawhash[ 8], rawhash[ 9], rawhash[10], rawhash[11],
	              rawhash[12], rawhash[13], rawhash[14], rawhash[15],
	              rawhash[16], rawhash[17], rawhash[18], rawhash[19]);
	if (rv == -1)
		return NULL;
	return str;
}

/*
 * Format SSL state into newly allocated string.
 * Returns pointer to string that must be freed by caller, or NULL on error.
 */
char *
ssl_ssl_state_to_str(SSL *ssl)
{
	char *str = NULL;
	int rv;

	rv = asprintf(&str, "%08x = %s%s%04x = %s (%s) [%s]",
	              SSL_get_state(ssl),
	              (SSL_get_state(ssl) & SSL_ST_CONNECT) ? "SSL_ST_CONNECT|" : "",
	              (SSL_get_state(ssl) & SSL_ST_ACCEPT) ? "SSL_ST_ACCEPT|" : "",
	              SSL_get_state(ssl) & SSL_ST_MASK,
	              SSL_state_string(ssl),
	              SSL_state_string_long(ssl),
	              SSL_is_server(ssl) ? "accept socket" : "connect socket");

	return (rv < 0) ? NULL : str;
}

/*
 * Generates a NSS key log format compatible string containing the client
 * random and the master key, intended to be used to decrypt externally
 * captured network traffic using tools like Wireshark.
 *
 * Only supports the CLIENT_RANDOM method (SSL 3.0 - TLS 1.2).
 *
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 */
char *
ssl_ssl_masterkey_to_str(SSL *ssl)
{
	char *str = NULL;
	int rv;
	unsigned char *k, *r;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	unsigned char kbuf[48], rbuf[32];
	k = &kbuf[0];
	r = &rbuf[0];
	SSL_SESSION_get_master_key(SSL_get0_session(ssl), k, sizeof(kbuf));
	SSL_get_client_random(ssl, r, sizeof(rbuf));
#else /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	k = ssl->session->master_key;
	r = ssl->s3->client_random;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	rv = asprintf(&str,
	              "CLIENT_RANDOM "
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              " "
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "%02X%02X%02X%02X%02X%02X%02X%02X"
	              "\n",
	              r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
	              r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
	              r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
	              r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
	              k[ 0], k[ 1], k[ 2], k[ 3], k[ 4], k[ 5], k[ 6], k[ 7],
	              k[ 8], k[ 9], k[10], k[11], k[12], k[13], k[14], k[15],
	              k[16], k[17], k[18], k[19], k[20], k[21], k[22], k[23],
	              k[24], k[25], k[26], k[27], k[28], k[29], k[30], k[31],
	              k[32], k[33], k[34], k[35], k[36], k[37], k[38], k[39],
	              k[40], k[41], k[42], k[43], k[44], k[45], k[46], k[47]);

	return (rv < 0) ? NULL : str;
}

#ifndef OPENSSL_NO_DH
static unsigned char dh_g[] = { 0x02 };
static unsigned char dh512_p[] = {
	0xAB, 0xC0, 0x34, 0x16, 0x95, 0x8B, 0x57, 0xE5, 0x5C, 0xB3, 0x4E, 0x6E,
	0x16, 0x0B, 0x35, 0xC5, 0x6A, 0xCC, 0x4F, 0xD3, 0xE5, 0x46, 0xE2, 0x23,
	0x6A, 0x5B, 0xBB, 0x5D, 0x3D, 0x52, 0xEA, 0xCE, 0x4F, 0x7D, 0xCA, 0xFF,
	0xB4, 0x8B, 0xC9, 0x78, 0xDC, 0xA0, 0xFC, 0xBE, 0xF3, 0xB5, 0xE6, 0x61,
	0xA6, 0x6D, 0x58, 0xFC, 0xA0, 0x0F, 0xF7, 0x9B, 0x97, 0xE6, 0xC7, 0xE8,
	0x1F, 0xCD, 0x16, 0x73 };
static unsigned char dh1024_p[] = {
	0x99, 0x28, 0x34, 0x48, 0x9E, 0xB7, 0xD1, 0x4F, 0x0D, 0x17, 0x09, 0x97,
	0xB9, 0x9B, 0x20, 0xFE, 0xE5, 0x65, 0xE0, 0xE2, 0x56, 0x37, 0x80, 0xA2,
	0x9F, 0x2C, 0x2D, 0x87, 0x10, 0x58, 0x39, 0xAD, 0xF3, 0xC5, 0xA9, 0x08,
	0x24, 0xC7, 0xAA, 0xA9, 0x29, 0x3A, 0x13, 0xDF, 0x4E, 0x0A, 0x6D, 0x11,
	0x39, 0xB1, 0x1C, 0x3F, 0xFE, 0xFE, 0x0A, 0x5E, 0xAD, 0x2E, 0x5C, 0x10,
	0x97, 0x38, 0xAC, 0xE8, 0xEB, 0xAA, 0x4A, 0xA1, 0xC0, 0x5C, 0x1D, 0x27,
	0x65, 0x9C, 0xC8, 0x53, 0xAC, 0x35, 0xDD, 0x84, 0x1F, 0x47, 0x0E, 0x04,
	0xF1, 0x90, 0x61, 0x62, 0x2E, 0x29, 0x2C, 0xC6, 0x28, 0x91, 0x6D, 0xF0,
	0xE2, 0x5E, 0xCE, 0x60, 0x3E, 0xF7, 0xF8, 0x37, 0x99, 0x4D, 0x9F, 0xFB,
	0x68, 0xEC, 0x7F, 0x9D, 0x32, 0x74, 0xD1, 0xAA, 0xD4, 0x4C, 0xF5, 0xCD,
	0xC2, 0xD7, 0xD7, 0xAC, 0xDA, 0x69, 0xF5, 0x2B };
static unsigned char dh2048_p[] = {
	0xAB, 0x88, 0x97, 0xCA, 0xF1, 0xE1, 0x60, 0x39, 0xFA, 0xB1, 0xA8, 0x7D,
	0xB3, 0x7A, 0x38, 0x08, 0xF0, 0x7A, 0x3D, 0x21, 0xC4, 0xE6, 0xB8, 0x32,
	0x3D, 0xAB, 0x0F, 0xE7, 0x8C, 0xA1, 0x59, 0x47, 0xB2, 0x0A, 0x7A, 0x3A,
	0x20, 0x2A, 0x1B, 0xD4, 0xBA, 0xFC, 0x4C, 0xC5, 0xEE, 0xA2, 0xB9, 0xB9,
	0x65, 0x47, 0xCC, 0x13, 0x99, 0xD7, 0xA6, 0xCA, 0xFF, 0x23, 0x05, 0x91,
	0xAB, 0x5C, 0x82, 0xB8, 0xB4, 0xFD, 0xB1, 0x2E, 0x5B, 0x0F, 0x8E, 0x03,
	0x3C, 0x23, 0xD6, 0x6A, 0xE2, 0x83, 0x95, 0xD2, 0x8E, 0xEB, 0xDF, 0x3A,
	0xAF, 0x89, 0xF0, 0xA0, 0x14, 0x09, 0x12, 0xF6, 0x54, 0x54, 0x93, 0xF4,
	0xD4, 0x41, 0x56, 0x7A, 0x0E, 0x56, 0x20, 0x1F, 0x1D, 0xBA, 0x3F, 0x07,
	0xD2, 0x89, 0x1B, 0x40, 0xD0, 0x1C, 0x08, 0xDF, 0x00, 0x7F, 0x34, 0xF4,
	0x28, 0x4E, 0xF7, 0x53, 0x8D, 0x4A, 0x00, 0xC3, 0xC0, 0x89, 0x9E, 0x63,
	0x96, 0xE9, 0x52, 0xDF, 0xA5, 0x2C, 0x00, 0x4E, 0xB0, 0x82, 0x6A, 0x10,
	0x28, 0x8D, 0xB9, 0xE7, 0x7A, 0xCB, 0xC3, 0xD6, 0xC1, 0xC0, 0x4D, 0x91,
	0xC4, 0x6F, 0xD3, 0x99, 0xD1, 0x86, 0x71, 0x67, 0x0A, 0xA1, 0xFC, 0xF4,
	0x7D, 0x40, 0x88, 0x8D, 0xAC, 0xCB, 0xBC, 0xEA, 0x17, 0x85, 0x0B, 0xC6,
	0x12, 0x3E, 0x4A, 0xB9, 0x60, 0x74, 0x93, 0x54, 0x14, 0x39, 0x10, 0xBF,
	0x21, 0xB0, 0x8B, 0xB1, 0x55, 0x3F, 0xBB, 0x6A, 0x1F, 0x42, 0x82, 0x0A,
	0x40, 0x3A, 0x15, 0xCD, 0xD3, 0x79, 0xD0, 0x02, 0xA4, 0xF5, 0x79, 0x78,
	0x03, 0xBD, 0x47, 0xCC, 0xD5, 0x08, 0x6A, 0x46, 0xAE, 0x36, 0xE4, 0xCD,
	0xB1, 0x17, 0x48, 0x30, 0xB4, 0x02, 0xBC, 0x50, 0x68, 0xE3, 0xA2, 0x76,
	0xD0, 0x5C, 0xB9, 0xE6, 0xBE, 0x4C, 0xFD, 0x50, 0xEF, 0xD0, 0x3F, 0x39,
	0x4F, 0x53, 0x16, 0x3B };
static unsigned char dh4096_p[] = {
	0xB1, 0xCC, 0x09, 0x86, 0xEE, 0xF9, 0xB9, 0xC9, 0xB9, 0x87, 0xC4, 0xB9,
	0xD7, 0x31, 0x95, 0x84, 0x94, 0x65, 0xED, 0x82, 0x64, 0x11, 0xA7, 0x0A,
	0xFE, 0xC2, 0x60, 0xAE, 0x7C, 0x74, 0xFB, 0x72, 0x8F, 0x0D, 0xA6, 0xDD,
	0x02, 0x49, 0x5B, 0x69, 0xD6, 0x96, 0x05, 0xBE, 0x5E, 0x9B, 0x09, 0x83,
	0xD8, 0xF3, 0x91, 0x55, 0x30, 0x86, 0x97, 0x6C, 0x48, 0x7B, 0x99, 0x82,
	0xCC, 0x1E, 0x1E, 0x25, 0xE6, 0x25, 0xCC, 0xA3, 0x66, 0xDE, 0x8A, 0x78,
	0xEE, 0x7F, 0x4F, 0x86, 0x95, 0x06, 0xBE, 0x64, 0x86, 0xFD, 0x60, 0x6A,
	0x3F, 0x0D, 0x8F, 0x62, 0x17, 0x89, 0xDB, 0xE1, 0x01, 0xC1, 0x75, 0x3A,
	0x78, 0x42, 0xA8, 0x26, 0xEC, 0x00, 0x78, 0xF3, 0xDA, 0x40, 0x8D, 0x0D,
	0x4D, 0x53, 0x82, 0xD7, 0x21, 0xC8, 0x46, 0xC9, 0xE3, 0x80, 0xB4, 0xCF,
	0xEA, 0x46, 0x85, 0xE9, 0xC4, 0x9D, 0xD0, 0xC0, 0x4D, 0x27, 0x0F, 0xF8,
	0x34, 0x3B, 0x86, 0x8F, 0xFC, 0x40, 0x56, 0x49, 0x64, 0x76, 0x61, 0xBC,
	0x35, 0x6A, 0xB8, 0xC5, 0x32, 0x19, 0x00, 0x5E, 0x21, 0x1C, 0x34, 0xCB,
	0x74, 0x5B, 0x60, 0x85, 0x8C, 0x38, 0x52, 0x50, 0x4D, 0xAA, 0x25, 0xE4,
	0x1A, 0xE6, 0xE4, 0xDF, 0x0A, 0xD2, 0x8F, 0x2B, 0xD1, 0x35, 0xC7, 0x92,
	0x7D, 0x6F, 0x54, 0x61, 0x8E, 0x3F, 0xFB, 0xE2, 0xC8, 0x81, 0xD0, 0xAC,
	0x64, 0xE2, 0xA8, 0x30, 0xEA, 0x8E, 0xAD, 0xFE, 0xC0, 0x9E, 0x0B, 0xBF,
	0x34, 0xAC, 0x79, 0x96, 0x38, 0x31, 0x1E, 0xEA, 0xF2, 0x7E, 0xEE, 0x0A,
	0x10, 0x34, 0x7C, 0x1A, 0x30, 0x5F, 0xAF, 0x96, 0x2F, 0x7F, 0xB5, 0x1D,
	0xA7, 0x3D, 0x35, 0x7A, 0x30, 0x70, 0x40, 0xE7, 0xD6, 0x22, 0x1E, 0xD0,
	0x9A, 0x34, 0xC7, 0x6B, 0xE4, 0xF1, 0x78, 0xED, 0xD9, 0xCD, 0x18, 0xBF,
	0x2A, 0x1A, 0x98, 0xB7, 0x6C, 0x6E, 0x18, 0x40, 0xB5, 0xBE, 0xDF, 0xE4,
	0x78, 0x8E, 0x34, 0xB2, 0x7B, 0xE5, 0x88, 0xE6, 0xFD, 0x24, 0xBD, 0xBB,
	0x2E, 0x30, 0x72, 0x54, 0xC7, 0xF4, 0xA0, 0xF1, 0x25, 0xFF, 0xB1, 0x37,
	0x42, 0x07, 0x8C, 0xF2, 0xB9, 0xA1, 0xA4, 0xA7, 0x76, 0x39, 0xB8, 0x11,
	0x17, 0xF3, 0xA8, 0x2E, 0x78, 0x68, 0xF4, 0xBF, 0x98, 0x25, 0x59, 0x17,
	0x59, 0x9B, 0x0D, 0x0B, 0x9B, 0xE3, 0x0F, 0xFF, 0xDC, 0xC8, 0x47, 0x21,
	0xE1, 0x0B, 0x9A, 0x44, 0x79, 0xC7, 0x5F, 0x8E, 0x83, 0x1E, 0x04, 0xA1,
	0xB2, 0x9F, 0x9B, 0xFC, 0xB3, 0x4E, 0xD9, 0xF9, 0x8F, 0x03, 0xBC, 0x0A,
	0x04, 0x00, 0x5C, 0x59, 0xB7, 0x51, 0xAA, 0x75, 0xF8, 0x7A, 0x03, 0x07,
	0x81, 0x6D, 0x67, 0x3E, 0x28, 0x37, 0xE4, 0x74, 0x5B, 0x8C, 0x2A, 0x4B,
	0x6C, 0x10, 0x92, 0x75, 0xA5, 0x79, 0x4B, 0x6D, 0x30, 0xB7, 0x6E, 0xD6,
	0x9E, 0x16, 0xC2, 0x87, 0x69, 0x34, 0xFE, 0xD7, 0x2A, 0x4F, 0xD6, 0xC0,
	0xF3, 0xCD, 0x9C, 0x46, 0xED, 0xC0, 0xB2, 0x84, 0x8D, 0x7E, 0x93, 0xD2,
	0xE9, 0xBE, 0x59, 0x18, 0x92, 0xC1, 0x2C, 0xD6, 0x6C, 0x71, 0x50, 0xA1,
	0x98, 0xDA, 0xD1, 0xAC, 0xDB, 0x88, 0x40, 0x1F, 0x69, 0xDC, 0xDB, 0xB2,
	0xA0, 0x90, 0x01, 0x8E, 0x12, 0xD6, 0x40, 0x1A, 0x8E, 0xC5, 0x69, 0x9C,
	0x91, 0x67, 0xAC, 0xD8, 0x4C, 0x27, 0xCD, 0x08, 0xB8, 0x32, 0x97, 0xE1,
	0x13, 0x0C, 0xFF, 0xB1, 0x06, 0x65, 0x03, 0x98, 0x6F, 0x9E, 0xF7, 0xB8,
	0xA8, 0x75, 0xBA, 0x59, 0xFD, 0x23, 0x98, 0x94, 0x80, 0x9C, 0xA7, 0x46,
	0x32, 0x98, 0x28, 0x7A, 0x0A, 0x3A, 0xA6, 0x95, 0x16, 0x6A, 0x52, 0x8E,
	0x8F, 0x2C, 0xC9, 0x49, 0xB7, 0x59, 0x99, 0x2A, 0xE6, 0xCA, 0x82, 0x88,
	0x36, 0xD3, 0x2B, 0xA4, 0x73, 0xFA, 0x89, 0xBB,
};

/*
 * OpenSSL temporary DH callback which loads DH parameters from static memory.
 */
DH *
ssl_tmp_dh_callback(UNUSED SSL *s, int is_export, int keylength)
{
	DH *dh;
	int rv = 0;

	if (!(dh = DH_new())) {
		log_err_printf("DH_new() failed\n");
		return NULL;
	}
	switch (keylength) {
	case 512:
		rv = DH_set0_pqg(dh,
		                 BN_bin2bn(dh512_p, sizeof(dh512_p), NULL),
		                 NULL,
		                 BN_bin2bn(dh_g, sizeof(dh_g), NULL));
		break;
	case 1024:
		rv = DH_set0_pqg(dh,
		                 BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL),
		                 NULL,
		                 BN_bin2bn(dh_g, sizeof(dh_g), NULL));
		break;
	case 2048:
		rv = DH_set0_pqg(dh,
		                 BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL),
		                 NULL,
		                 BN_bin2bn(dh_g, sizeof(dh_g), NULL));
		break;
	case 4096:
		rv = DH_set0_pqg(dh,
		                 BN_bin2bn(dh4096_p, sizeof(dh4096_p), NULL),
		                 NULL,
		                 BN_bin2bn(dh_g, sizeof(dh_g), NULL));
		break;
	default:
		log_err_printf("Unhandled DH keylength %i%s\n",
		               keylength,
		               (is_export ? " (export)" : ""));
		DH_free(dh);
		return NULL;
	}
	if (!rv) {
		log_err_printf("Failed to load DH p and g from memory\n");
		DH_free(dh);
		return NULL;
	}
	return(dh);
}

/*
 * Load DH parameters from a PEM file.
 * Not thread-safe.
 */
DH *
ssl_dh_load(const char *filename)
{
	DH *dh;
	FILE *fh;

	if (ssl_init() == -1)
		return NULL;

	if (!(fh = fopen(filename, "r"))) {
		return NULL;
	}
	dh = PEM_read_DHparams(fh, NULL, NULL, NULL);
	fclose(fh);
	return dh;
}
#endif /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC
/*
 * Load an Elliptic Curve by name.  If curvename is NULL, a default curve is
 * loaded.
 */
EC_KEY *
ssl_ec_by_name(const char *curvename)
{
	int nid;

	if (!curvename)
		curvename = DFLT_CURVE;

	if ((nid = OBJ_sn2nid(curvename)) == NID_undef) {
		return NULL;
	}
	return EC_KEY_new_by_curve_name(nid);
}
#endif /* !OPENSSL_NO_EC */

/*
 * Add a X509v3 extension to a certificate and handle errors.
 * Returns -1 on errors, 0 on success.
 */
int
ssl_x509_v3ext_add(X509V3_CTX *ctx, X509 *crt, char *k, char *v)
{
	X509_EXTENSION *ext;

	if (!(ext = X509V3_EXT_conf(NULL, ctx, k, v))) {
		return -1;
	}
	if (X509_add_ext(crt, ext, -1) != 1) {
		X509_EXTENSION_free(ext);
		return -1;
	}
	X509_EXTENSION_free(ext);
	return 0;
}

/*
 * Copy a X509v3 extension from one certificate to another.
 * If the extension is not present in the original certificate,
 * the extension will not be added to the destination certificate.
 * Returns 1 if ext was copied, 0 if not present in origcrt, -1 on error.
 */
int
ssl_x509_v3ext_copy_by_nid(X509 *crt, X509 *origcrt, int nid)
{
	X509_EXTENSION *ext;
	int pos;

	pos = X509_get_ext_by_NID(origcrt, nid, -1);
	if (pos == -1)
		return 0;
	ext = X509_get_ext(origcrt, pos);
	if (!ext)
		return -1;
	if (X509_add_ext(crt, ext, -1) != 1)
		return -1;
	return 1;
}

/*
 * Best effort randomness generator.
 * Not for real life cryptography applications.
 * Returns 0 on success, -1 on failure.
 */
int
ssl_rand(void *p, size_t sz)
{
	int rv;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	rv = RAND_pseudo_bytes((unsigned char*)p, sz);
	if (rv == 1)
		return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	rv = RAND_bytes((unsigned char*)p, sz);
	if (rv == 1)
		return 0;
	return -1;
}

/*
 * Copy the serial number from src certificate to dst certificate
 * and modify it by a random offset.
 * If reading the serial fails for some reason, generate a new
 * random serial and store it in the dst certificate.
 * Using the same serial is not a good idea since some SSL stacks
 * check for duplicate certificate serials.
 * Returns 0 on success, -1 on error.
 */
int
ssl_x509_serial_copyrand(X509 *dstcrt, X509 *srccrt)
{
	ASN1_INTEGER *srcptr, *dstptr;
	BIGNUM *bnserial;
	unsigned int rand;
	int rv;

#ifndef PURIFY
	rv = ssl_rand(&rand, sizeof(rand));
#else /* PURIFY */
	rand = 0xF001;
	rv = 0;
#endif /* PURIFY */
	dstptr = X509_get_serialNumber(dstcrt);
	srcptr = X509_get_serialNumber(srccrt);
	if ((rv == -1) || !dstptr || !srcptr)
		return -1;
	bnserial = ASN1_INTEGER_to_BN(srcptr, NULL);
	if (!bnserial) {
		/* random 32-bit serial */
		ASN1_INTEGER_set(dstptr, rand);
	} else {
		/* original serial plus random 32-bit offset */
		BN_add_word(bnserial, rand);
		BN_to_ASN1_INTEGER(bnserial, dstptr);
		BN_free(bnserial);
	}
	return 0;
}

/*
 * Returns the appropriate key usage strings for the type of server key.
 * Return value should conceptually be const, but OpenSSL does not use const
 * appropriately.
 */
static char *
ssl_key_usage_for_key(EVP_PKEY *key)
{
	switch (EVP_PKEY_type(EVP_PKEY_base_id(key))) {
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		return "keyEncipherment,digitalSignature";
#endif /* !OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DH
	case EVP_PKEY_DH:
		return "keyAgreement";
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_DSA
	case EVP_PKEY_DSA:
		return "digitalSignature";
#endif /* !OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
	case EVP_PKEY_EC:
		return "digitalSignature,keyAgreement";
#endif /* !OPENSSL_NO_ECDSA */
	default:
		return "keyEncipherment,keyAgreement,digitalSignature";
	}
}

/*
 * Create a fake X509v3 certificate, signed by the provided CA,
 * based on the original certificate retrieved from the real server.
 * The returned certificate is created using X509_new() and thus must
 * be freed by the caller using X509_free().
 * The optional argument extraname is added to subjectAltNames if provided.
 */
X509 *
ssl_x509_forge(X509 *cacrt, EVP_PKEY *cakey, X509 *origcrt, EVP_PKEY *key,
               const char *extraname, const char *crlurl)
{
	X509_NAME *subject, *issuer;
	GENERAL_NAMES *names;
	GENERAL_NAME *gn;
	X509 *crt;
	int rv;

	subject = X509_get_subject_name(origcrt);
	issuer = X509_get_subject_name(cacrt);
	if (!subject || !issuer)
		return NULL;

	crt = X509_new();
	if (!crt)
		return NULL;

	if (!X509_set_version(crt, 0x02) ||
	    !X509_set_subject_name(crt, subject) ||
	    !X509_set_issuer_name(crt, issuer) ||
	    ssl_x509_serial_copyrand(crt, origcrt) == -1 ||
	    !X509_gmtime_adj(X509_get_notBefore(crt), (long)-60*60*24) ||
	    !X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*364) ||
	    !X509_set_pubkey(crt, key))
		goto errout;

	/* add standard v3 extensions; cf. RFC 2459 */

	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, cacrt, crt, NULL, NULL, 0);
	if (ssl_x509_v3ext_add(&ctx, crt, "subjectKeyIdentifier",
	                                  "hash") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "authorityKeyIdentifier",
	                                  "keyid,issuer:always") == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt,
	                                NID_basic_constraints);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "basicConstraints",
		                                   "CA:FALSE");
	if (rv == -1)
		goto errout;

	/* key usage depends on the key type, do not copy from original */
	rv = ssl_x509_v3ext_add(&ctx, crt, "keyUsage",
	                        ssl_key_usage_for_key(key));
	if (rv == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt,
	                                NID_ext_key_usage);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "extendedKeyUsage",
		                                   "serverAuth");
	if (rv == -1)
		goto errout;

	if (crlurl) {
		char *crlurlval;
		if (asprintf(&crlurlval, "URI:%s", crlurl) < 0)
			goto errout;
		if (ssl_x509_v3ext_add(&ctx, crt, "crlDistributionPoints",
		                       crlurlval) == -1) {
			free(crlurlval);
			goto errout;
		}
		free(crlurlval);
	}

	if (!extraname) {
		/* no extraname provided: copy original subjectAltName ext */
		if (ssl_x509_v3ext_copy_by_nid(crt, origcrt,
		                               NID_subject_alt_name) == -1)
			goto errout;
	} else {
		names = X509_get_ext_d2i(origcrt, NID_subject_alt_name, 0, 0);
		if (!names) {
			/* no subjectAltName present: add new one */
			char *cfval;
			if (asprintf(&cfval, "DNS:%s", extraname) < 0)
				goto errout;
			if (ssl_x509_v3ext_add(&ctx, crt, "subjectAltName",
			                       cfval) == -1) {
				free(cfval);
				goto errout;
			}
			free(cfval);
		} else {
			/* add extraname to original subjectAltName
			 * and add it to the new certificate */
			gn = GENERAL_NAME_new();
			if (!gn)
				goto errout2;
			gn->type = GEN_DNS;
			gn->d.dNSName = ASN1_IA5STRING_new();
			if (!gn->d.dNSName)
				goto errout3;
			ASN1_STRING_set(gn->d.dNSName,
			                (unsigned char *)extraname,
			                strlen(extraname));
			sk_GENERAL_NAME_push(names, gn);
			X509_EXTENSION *ext = X509V3_EXT_i2d(
			                      NID_subject_alt_name, 0, names);
			if (!X509_add_ext(crt, ext, -1)) {
				if (ext) {
					X509_EXTENSION_free(ext);
				}
				goto errout3;
			}
			X509_EXTENSION_free(ext);
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		}
	}
#ifdef DEBUG_CERTIFICATE
	ssl_x509_v3ext_add(&ctx, crt, "nsComment", "Generated by " PKGLABEL);
#endif /* DEBUG_CERTIFICATE */

	const EVP_MD *md;
	switch (EVP_PKEY_type(EVP_PKEY_base_id(cakey))) {
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_md5WithRSAEncryption:
			md = EVP_md5();
			break;
		case NID_ripemd160WithRSA:
			md = EVP_ripemd160();
			break;
		case NID_sha1WithRSAEncryption:
			md = EVP_sha1();
			break;
		case NID_sha224WithRSAEncryption:
			md = EVP_sha224();
			break;
		case NID_sha256WithRSAEncryption:
			md = EVP_sha256();
			break;
		case NID_sha384WithRSAEncryption:
			md = EVP_sha384();
			break;
		case NID_sha512WithRSAEncryption:
			md = EVP_sha512();
			break;
#ifndef OPENSSL_NO_SHA0
		case NID_shaWithRSAEncryption:
			md = EVP_sha();
			break;
#endif /* !OPENSSL_NO_SHA0 */
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	case EVP_PKEY_DSA:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_dsaWithSHA1:
		case NID_dsaWithSHA1_2:
			md = EVP_sha1();
			break;
		case NID_dsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_dsa_with_SHA256:
			md = EVP_sha256();
			break;
#ifndef OPENSSL_NO_SHA0
		case NID_dsaWithSHA:
			md = EVP_sha();
			break;
#endif /* !OPENSSL_NO_SHA0 */
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
	case EVP_PKEY_EC:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_ecdsa_with_SHA1:
			md = EVP_sha1();
			break;
		case NID_ecdsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_ecdsa_with_SHA256:
			md = EVP_sha256();
			break;
		case NID_ecdsa_with_SHA384:
			md = EVP_sha384();
			break;
		case NID_ecdsa_with_SHA512:
			md = EVP_sha512();
			break;
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_ECDSA */
	default:
		goto errout;
	}
	if (!X509_sign(crt, cakey, md))
		goto errout;

	return crt;

errout3:
	GENERAL_NAME_free(gn);
errout2:
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
errout:
	X509_free(crt);
	return NULL;
}

/*
 * Load a X509 certificate chain from a PEM file.
 * Returns the first certificate in *crt and all subsequent certificates in
 * *chain.  If crt is NULL, the first certificate is prepended to *chain
 * instead of returned separately.  If *chain is NULL, a new stack of X509*
 * is created in *chain, else the certs are pushed onto an existing stack.
 * Returns -1 on error.
 * Not thread-safe.
 *
 * By accessing (SSLCTX*)->extra_certs directly on OpenSSL before 1.0.2, we
 * depend on OpenSSL internals in this function.  OpenSSL 1.0.2 introduced
 * the SSL_get0_chain_certs() API for accessing the certificate chain.
 */
int
ssl_x509chain_load(X509 **crt, STACK_OF(X509) **chain, const char *filename)
{
	X509 *tmpcrt;
	SSL_CTX *tmpctx;
	SSL *tmpssl;
	STACK_OF(X509) *tmpchain;
	int rv;

	if (ssl_init() == -1)
		return -1;

	tmpctx = SSL_CTX_new(SSLv23_server_method());
	if (!tmpctx)
		goto leave1;

	rv = SSL_CTX_use_certificate_chain_file(tmpctx, filename);
	if (rv != 1)
		goto leave2;
	tmpssl = SSL_new(tmpctx);
	if (!tmpssl)
		goto leave2;

	tmpcrt = SSL_get_certificate(tmpssl);
	if (!tmpcrt)
		goto leave3;

	if (!*chain) {
		*chain = sk_X509_new_null();
		if (!*chain)
			goto leave3;
	}

#if (OPENSSL_VERSION_NUMBER < 0x1000200fL) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20902000L)
	tmpchain = tmpctx->extra_certs;
#else /* OpenSSL >= 1.0.2 || LIBRESSL_VERSION_NUMBER >= 0x20902000L */
	rv = SSL_CTX_get0_chain_certs(tmpctx, &tmpchain);
	if (rv != 1)
		goto leave3;
#endif /* OpenSSL >= 1.0.2 */

	if (crt) {
		*crt = tmpcrt;
	} else {
		sk_X509_push(*chain, tmpcrt);
	}
	ssl_x509_refcount_inc(tmpcrt);

	for (int i = 0; i < sk_X509_num(tmpchain); i++) {
		tmpcrt = sk_X509_value(tmpchain, i);
		ssl_x509_refcount_inc(tmpcrt);
		sk_X509_push(*chain, tmpcrt);
	}
	SSL_free(tmpssl);
	SSL_CTX_free(tmpctx);
	return 0;

leave3:
	SSL_free(tmpssl);
leave2:
	SSL_CTX_free(tmpctx);
leave1:
	return -1;
}

/*
 * Use a X509 certificate chain for an SSL context.
 * Copies the certificate stack to the SSL_CTX internal data structures
 * and increases reference counts accordingly.
 */
int
ssl_x509chain_use(SSL_CTX *sslctx, X509 *crt, STACK_OF(X509) *chain)
{
	if (SSL_CTX_use_certificate(sslctx, crt) != 1)
		return -1;

	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *tmpcrt;

		tmpcrt = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(tmpcrt);
		if (SSL_CTX_add_extra_chain_cert(sslctx, tmpcrt) != 1)
			return -1;
	}
	return 0;
}

/*
 * Load a X509 certificate from a PEM file.
 * Returned X509 must be freed using X509_free() by the caller.
 * Not thread-safe.
 */
X509 *
ssl_x509_load(const char *filename)
{
	X509 *crt = NULL;
	SSL_CTX *tmpctx;
	SSL *tmpssl;
	int rv;

	if (ssl_init() == -1)
		return NULL;

	tmpctx = SSL_CTX_new(SSLv23_server_method());
	if (!tmpctx)
		goto leave1;
	rv = SSL_CTX_use_certificate_file(tmpctx, filename, SSL_FILETYPE_PEM);
	if (rv != 1)
		goto leave2;
	tmpssl = SSL_new(tmpctx);
	if (!tmpssl)
		goto leave2;
	crt = SSL_get_certificate(tmpssl);
	if (crt)
		ssl_x509_refcount_inc(crt);
	SSL_free(tmpssl);
leave2:
	SSL_CTX_free(tmpctx);
leave1:
	return crt;
}

/*
 * Load a private key from a PEM file.
 * Returned EVP_PKEY must be freed using EVP_PKEY_free() by the caller.
 * Not thread-safe.
 */
EVP_PKEY *
ssl_key_load(const char *filename)
{
	EVP_PKEY *key = NULL;
	SSL_CTX *tmpctx;
	SSL *tmpssl;
	int rv;

	if (ssl_init() == -1)
		return NULL;

	tmpctx = SSL_CTX_new(SSLv23_server_method());
	if (!tmpctx)
		goto leave1;
	rv = SSL_CTX_use_PrivateKey_file(tmpctx, filename, SSL_FILETYPE_PEM);
	if (rv != 1)
		goto leave2;
	tmpssl = SSL_new(tmpctx);
	if (!tmpssl)
		goto leave2;
	key = SSL_get_privatekey(tmpssl);
	if (key)
		ssl_key_refcount_inc(key);
	SSL_free(tmpssl);
leave2:
	SSL_CTX_free(tmpctx);
leave1:
	return key;
}

/*
 * Generate a new RSA key.
 * Returned EVP_PKEY must be freed using EVP_PKEY_free() by the caller.
 */
EVP_PKEY *
ssl_key_genrsa(const int keysize)
{
	EVP_PKEY *pkey;
	RSA *rsa;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	BIGNUM *bn;
	int rv;
	rsa = RSA_new();
	bn = BN_new();
	BN_dec2bn(&bn, "3");
	rv = RSA_generate_key_ex(rsa, keysize, bn, NULL);
	BN_free(bn);
	if (rv != 1) {
		RSA_free(rsa);
		return NULL;
	}
#else /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	rsa = RSA_generate_key(keysize, 3, NULL, NULL);
	if (!rsa)
		return NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa); /* does not increment refcount */
	return pkey;
}

/*
 * Returns the subjectKeyIdentifier compatible key id of the public key.
 * keyid will receive a binary SHA-1 hash of SSL_KEY_IDSZ bytes.
 * Returns 0 on success, -1 on failure.
 */
int
ssl_key_identifier_sha1(EVP_PKEY *key, unsigned char *keyid)
{
	X509_PUBKEY *pubkey = NULL;
	const unsigned char *pk;
	int length;

	/* X509_PUBKEY_set() will attempt to free pubkey if != NULL */
	if (X509_PUBKEY_set(&pubkey, key) != 1 || !pubkey)
		return -1;
	if (!X509_PUBKEY_get0_param(NULL, &pk, &length, NULL, pubkey))
		goto errout;
	if (!EVP_Digest(pk, length, keyid, NULL, EVP_sha1(), NULL))
		goto errout;
	X509_PUBKEY_free(pubkey);
	return 0;

errout:
	X509_PUBKEY_free(pubkey);
	return -1;
}

/*
 * Returns the result of ssl_key_identifier_sha1() as hex characters with or
 * without colons in a newly allocated string.
 */
char *
ssl_key_identifier(EVP_PKEY *key, int colons)
{
	unsigned char id[SSL_KEY_IDSZ];

	if (ssl_key_identifier_sha1(key, id) == -1)
		return NULL;

	return ssl_sha1_to_str(id, colons);
}

/*
 * Returns the one-line representation of the subject DN in a newly allocated
 * string which must be freed by the caller.
 */
char *
ssl_x509_subject(X509 *crt)
{
	return X509_NAME_oneline(X509_get_subject_name(crt), NULL, 0);
}

/*
 * Parse the common name from the subject distinguished name.
 * Returns string allocated using malloc(), caller must free().
 * Returns NULL on errors.
 */
char *
ssl_x509_subject_cn(X509 *crt, size_t *psz)
{
	X509_NAME *ptr;
	char *cn;
	size_t sz;

	ptr = X509_get_subject_name(crt); /* does not inc refcounts */
	if (!ptr)
		return NULL;
	sz = X509_NAME_get_text_by_NID(ptr, NID_commonName, NULL, 0) + 1;
	if ((sz == 0) || !(cn = malloc(sz)))
		return NULL;
	if (X509_NAME_get_text_by_NID(ptr, NID_commonName, cn, sz) == -1) {
		free(cn);
		return NULL;
	}
	*psz = sz;
	return cn;
}

/*
 * Write the SHA1 fingerprint of certificate to fpr as SSL_X509_FPRSZ (20)
 * bytes long binary buffer.
 * Returns -1 on error, 0 on success.
 */
int
ssl_x509_fingerprint_sha1(X509 *crt, unsigned char *fpr)
{
	unsigned int sz = SSL_X509_FPRSZ;

	return X509_digest(crt, EVP_sha1(), fpr, &sz) ? 0 : -1;
}

/*
 * Returns the result of ssl_x509_fingerprint_sha1() as hex characters with or
 * without colons in a newly allocated string.
 */
char *
ssl_x509_fingerprint(X509 *crt, int colons)
{
	unsigned char fpr[SSL_X509_FPRSZ];

	if (ssl_x509_fingerprint_sha1(crt, fpr) == -1)
		return NULL;

	return ssl_sha1_to_str(fpr, colons);
}

#ifndef OPENSSL_NO_DH
/*
 * Increment the reference count of DH parameters in a thread-safe
 * manner.
 */
void
ssl_dh_refcount_inc(DH *dh)
{
#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	CRYPTO_add(&dh->references, 1, CRYPTO_LOCK_DH);
#else /* !OPENSSL_THREADS */
	DH_up_ref(dh);
#endif /* !OPENSSL_THREADS */
}
#endif /* !OPENSSL_NO_DH */

/*
 * Increment the reference count of an X509 certificate in a thread-safe
 * manner.
 */
void
ssl_key_refcount_inc(EVP_PKEY *key)
{
#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	CRYPTO_add(&key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else /* !OPENSSL_THREADS */
	EVP_PKEY_up_ref(key);
#endif /* !OPENSSL_THREADS */
}

/*
 * Increment the reference count of an X509 certificate in a thread-safe
 * manner.  This differs from X509_dup() in that it does not create new,
 * full copy of the certificate, but only increases the reference count.
 */
void
ssl_x509_refcount_inc(X509 *crt)
{
#if defined(OPENSSL_THREADS) && ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
	CRYPTO_add(&crt->references, 1, CRYPTO_LOCK_X509);
#else /* !OPENSSL_THREADS */
	X509_up_ref(crt);
#endif /* !OPENSSL_THREADS */
}

/*
 * Match a URL/URI hostname against a single certificate DNS name
 * using RFC 6125 rules (6.4.3 Checking of Wildcard Certificates):
 *
 *   1.  The client SHOULD NOT attempt to match a presented identifier in
 *       which the wildcard character comprises a label other than the
 *       left-most label (e.g., do not match bar.*.example.net).
 *
 *   2.  If the wildcard character is the only character of the left-most
 *       label in the presented identifier, the client SHOULD NOT compare
 *       against anything but the left-most label of the reference
 *       identifier (e.g., *.example.com would match foo.example.com but
 *       not bar.foo.example.com or example.com).
 *
 *   3.  The client MAY match a presented identifier in which the wildcard
 *       character is not the only character of the label (e.g.,
 *       baz*.example.net and *baz.example.net and b*z.example.net would
 *       be taken to match baz1.example.net and foobaz.example.net and
 *       buzz.example.net, respectively).  However, the client SHOULD NOT
 *       attempt to match a presented identifier where the wildcard
 *       character is embedded within an A-label or U-label [IDNA-DEFS] of
 *       an internationalized domain name [IDNA-PROTO].
 *
 * The optional partial matching in rule 3 is not implemented.
 * Returns 1 on match, 0 on no match.
 */
int
ssl_dnsname_match(const char *certname, size_t certnamesz,
                  const char *hostname, size_t hostnamesz)
{
	if (hostnamesz < certnamesz)
		return 0;
	if ((hostnamesz == certnamesz) &&
	    !memcmp(certname, hostname, certnamesz))
		return 1;
	if (!memcmp(certname, "xn--", 4))
		return 0;
	if ((certnamesz == 1) && (certname[0] == '*') &&
	    !memchr(hostname, '.', hostnamesz))
		return 1;
	if ((certnamesz > 2) && (certname[0] == '*') && (certname[1] == '.') &&
	    !memcmp(&certname[1],
	            &hostname[hostnamesz - (certnamesz - 1)],
	            certnamesz - 1) &&
	    (memchr(hostname, '.', hostnamesz) ==
	     &hostname[hostnamesz - (certnamesz - 1)]))
		return 1;
	return 0;
}

/*
 * Transform a NULL-terminated hostname into a matching wildcard hostname,
 * e.g. "test.example.org" -> "*.example.org".
 * Returns string which must be free()'d by the caller, or NULL on error.
 */
char *
ssl_wildcardify(const char *hostname)
{
	char *dot, *wildcarded;
	size_t dotsz;

	if (!(dot = strchr(hostname, '.')))
		return strdup("*");
	dotsz = strlen(dot);
	if (!(wildcarded = malloc(dotsz + 2)))
		return NULL;
	wildcarded[0] = '*';
	for (size_t i = 0; i < dotsz; i++) {
		wildcarded[i+1] = dot[i];
	}
	wildcarded[dotsz+1] = '\0';
	return wildcarded;
}

/*
 * Match DNS name against certificate subject CN and subjectAltNames DNS names.
 * Returns 1 if any name matches, 0 if none matches.
 */
int
ssl_x509_names_match(X509 *crt, const char *dnsname)
{
	GENERAL_NAMES *altnames;
	char *cn;
	size_t cnsz, dnsnamesz;

	dnsnamesz = strlen(dnsname);

	cn = ssl_x509_subject_cn(crt, &cnsz);
	if (cn && ssl_dnsname_match(cn, cnsz, dnsname, dnsnamesz)) {
		free(cn);
		return 1;
	}
	if (cn) {
		free(cn);
	}

	altnames = X509_get_ext_d2i(crt, NID_subject_alt_name, 0, 0);
	if (!altnames)
		return 0;
	for (int i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
		GENERAL_NAME *gn = sk_GENERAL_NAME_value(altnames, i);
		if (gn->type == GEN_DNS) {
			unsigned char *altname;
			int altnamesz;
			ASN1_STRING_to_UTF8(&altname, gn->d.dNSName);
			altnamesz = ASN1_STRING_length(gn->d.dNSName);
			if (altnamesz < 0)
				break;
			if (ssl_dnsname_match((char *)altname,
			                      (size_t)altnamesz,
			                      dnsname, dnsnamesz)) {
				OPENSSL_free((char*)altname);
				GENERAL_NAMES_free(altnames);
				return 1;
			}
			OPENSSL_free((char*)altname);
		}
	}
	GENERAL_NAMES_free(altnames);
	return 0;
}

/*
 * Returns a NULL terminated array of pointers to all common names found
 * in the Subject DN CN and subjectAltNames extension (DNSName only).
 * Caller must free returned buffer and all pointers within.
 * Embedded NULL characters in hostnames are replaced with '!'.
 */
char **
ssl_x509_names(X509 *crt)
{
	GENERAL_NAMES *altnames;
	char *cn;
	size_t cnsz;
	char **res, **p;
	size_t count;

	cn = ssl_x509_subject_cn(crt, &cnsz);
	altnames = X509_get_ext_d2i(crt, NID_subject_alt_name, NULL, NULL);

	count = (altnames ? sk_GENERAL_NAME_num(altnames) : 0) + (cn ? 2 : 1);
	res = malloc(count * sizeof(char*));
	if (!res)
		return NULL;
	p = res;
	if (cn)
		*(p++) = cn;
	if (!altnames) {
		*p = NULL;
		return res;
	}
	for (int i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
		GENERAL_NAME *gn = sk_GENERAL_NAME_value(altnames, i);
		if (gn->type == GEN_DNS) {
			unsigned char *altname;
			int altnamesz;

			ASN1_STRING_to_UTF8(&altname, gn->d.dNSName);
			if (!altname)
				break;
			altnamesz = ASN1_STRING_length(gn->d.dNSName);
			if (altnamesz < 0) {
				OPENSSL_free((char*)altname);
				break;
			}
			*p = malloc(altnamesz + 1);
			if (!*p) {
				OPENSSL_free((char*)altname);
				GENERAL_NAMES_free(altnames);
				for (p = res; *p; p++)
					free(*p);
				free(res);
				return NULL;
			}
			for (int j = 0; j < altnamesz; j++) {
				(*p)[j] = altname[j] ? altname[j] : '!';
			}
			(*p)[altnamesz] = '\0';
			OPENSSL_free((char*)altname);
			p++;
		}
	}
	*p = NULL;
	GENERAL_NAMES_free(altnames);
	return res;
}

/*
 * Returns a printable representation of a certificate's common names found
 * in the Subject DN CN and subjectAltNames extension, separated by slashes.
 * Caller must free returned buffer.
 * Embedded NULL characters in hostnames are replaced with '!'.
 * If no CN and no subjectAltNames are found, returns "-".
 */
char *
ssl_x509_names_to_str(X509 *crt)
{
	char **names;
	size_t sz;
	char *buf = NULL, *next;

	names = ssl_x509_names(crt);
	if (!names)
		return strdup("-");

	sz = 0;
	for (char **p = names; *p; p++) {
		sz += strlen(*p) + 1;
	}
	if (!sz) {
		buf = strdup("-");
		goto out1;
	}

	if (!(buf = malloc(sz)))
		goto out2;
	next = buf;
	for (char **p = names; *p; p++) {
		char *src = *p;
		while (*src) {
			*next++ = *src++;
		}
		*next++ = '/';
	}
	*--next = '\0';
out2:
	for (char **p = names; *p; p++)
		free(*p);
out1:
	free(names);
	return buf;
}

/*
 * Returns a zero-terminated buffer containing the ASN1 IA5 string.
 * Returned buffer must be free()'d by caller.
 */
static char *
ssl_ia5string_strdup(ASN1_IA5STRING *ia5)
{
	char *str;

	if (!ia5 || !ia5->length)
		return NULL;
	str = malloc(ia5->length + 1);
	if (!str)
		return NULL;
	memcpy(str, ia5->data, ia5->length);
	str[ia5->length] = 0;
	return str;
}

/*
 * Returns a NULL terminated array of pointers to copies of Authority
 * Information Access (AIA) URLs of a given type contained in the certificate.
 * Caller must free returned buffer and all pointers within.
 */
char **
ssl_x509_aias(X509 *crt, const int type)
{
	AUTHORITY_INFO_ACCESS *aias;
	char **res;
	int count, i, j;

	aias = X509_get_ext_d2i(crt, NID_info_access, NULL, NULL);
	if (!aias || !(count = sk_ACCESS_DESCRIPTION_num(aias)))
		return NULL;

	res = malloc((count + 1) * sizeof(char *));
	if (!res) {
		sk_ACCESS_DESCRIPTION_pop_free(aias, ACCESS_DESCRIPTION_free);
		return NULL;
	}

	for (i = 0, j = 0; i < count; i++) {
		ACCESS_DESCRIPTION *aia;

		aia = sk_ACCESS_DESCRIPTION_value(aias, i);
		if (aia &&
		    OBJ_obj2nid(aia->method) == type &&
		    aia->location->type == GEN_URI) {
			res[j] = ssl_ia5string_strdup(aia->location->d.ia5);
			if (res[j])
				j++;
		}
	}
	res[j] = NULL;
	sk_ACCESS_DESCRIPTION_pop_free(aias, ACCESS_DESCRIPTION_free);
	return res;
}

/*
 * Returns a NULL terminated array of pointers to copies of Authority
 * Information Access (AIA) URLs of type OCSP contained in the certificate.
 * Caller must free returned buffer and all pointers within.
 */
char **
ssl_x509_ocsps(X509 *crt)
{
	return ssl_x509_aias(crt, NID_ad_OCSP);
}

/*
 * Check whether the certificate is valid based on current time.
 * Return 1 if valid, 0 otherwise.
 */
int
ssl_x509_is_valid(X509 *crt)
{
	if (X509_cmp_current_time(X509_get_notAfter(crt)) <= 0)
		return 0;
	if (X509_cmp_current_time(X509_get_notBefore(crt)) > 0)
		return 0;
	return 1;
}

/*
 * Print X509 certificate data to a newly allocated string.
 * Caller must free returned string.
 * Returns NULL on errors.
 */
char *
ssl_x509_to_str(X509 *crt)
{
	BIO *bio;
	char *p, *ret;
	size_t sz;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;
	X509_print(bio, crt);
	sz = BIO_get_mem_data(bio, &p);
	if (!(ret = malloc(sz + 1))) {
		BIO_free(bio);
		return NULL;
	}
	memcpy(ret, p, sz);
	ret[sz] = '\0';
	BIO_free(bio);
	return ret;
}

/*
 * Convert X509 certificate to PEM format in a newly allocated string.
 * Caller must free returned string.
 * Returns NULL on errors.
 */
char *
ssl_x509_to_pem(X509 *crt)
{
	BIO *bio;
	char *p, *ret;
	size_t sz;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;
	PEM_write_bio_X509(bio, crt);
	sz = BIO_get_mem_data(bio, &p);
	if (!(ret = malloc(sz + 1))) {
		BIO_free(bio);
		return NULL;
	}
	memcpy(ret, p, sz);
	ret[sz] = '\0';
	BIO_free(bio);
	return ret;
}

/*
 * Print SSL_SESSION data to a newly allocated string.
 * Caller must free returned string.
 * Returns NULL on errors.
 */
char *
ssl_session_to_str(SSL_SESSION *sess)
{
	BIO *bio;
	char *p, *ret;
	size_t sz;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;
	SSL_SESSION_print(bio, sess);
	sz = BIO_get_mem_data(bio, &p); /* sets p to internal buffer */
	if (!(ret = malloc(sz + 1))) {
		BIO_free(bio);
		return NULL;
	}
	memcpy(ret, p, sz);
	ret[sz] = '\0';
	BIO_free(bio);
	return ret;
}

/*
 * Returns non-zero if the session timeout has not expired yet,
 * zero if the session has expired or an error occurred.
 */
int
ssl_session_is_valid(SSL_SESSION *sess)
{
	time_t curtimet;
	long curtime, timeout;

	curtimet = time(NULL);
	if (curtimet == (time_t)-1)
		return 0;
	curtime = curtimet;
	if ((curtime < 0) || ((time_t)curtime != curtimet))
		return 0;
	timeout = SSL_SESSION_get_timeout(sess);
	if (curtime < timeout)
		return 0;
	return (SSL_SESSION_get_time(sess) > curtime - timeout);
}

/*
 * Returns 1 if buf contains a DER encoded OCSP request which can be parsed.
 * Returns 0 otherwise.
 */
int
ssl_is_ocspreq(const unsigned char *buf, size_t sz)
{
	OCSP_REQUEST *req;
	const unsigned char *p;

	p = (const unsigned char *)buf;
	req = d2i_OCSP_REQUEST(NULL, &p, sz); /* increments p */
	if (!req)
		return 0;
	OCSP_REQUEST_free(req);
	return 1;
}

/*
 * Ugly hack to manually parse a clientHello message from a memory buffer.
 * This is needed in order to be able to support SNI and STARTTLS.
 *
 * The OpenSSL SNI API only allows to read the indicated server name at the
 * time when we have to provide the server certificate.  OpenSSL does not
 * allow to asynchronously read the indicated server name, wait for some
 * unrelated event to happen, and then later to provide the server certificate
 * to use and continue the handshake.  Therefore we resort to parsing the
 * server name from the ClientHello manually before OpenSSL gets to work on it.
 *
 * For STARTTLS support in autossl mode, we need to peek into the buffer of
 * received octets and decide whether we have something that resembles a
 * (possibly incomplete) ClientHello message, so we can upgrade the connection
 * to SSL automatically.
 *
 * This function takes a buffer containing (part of) a ClientHello message as
 * seen on the network as input.
 *
 * Returns:
 *  1  if buf does not contain a complete ClientHello message;
 *     *clienthello may point to the start of a truncated ClientHello message,
 *     indicating that the caller should retry later with more bytes available
 *  0  if buf contains a complete ClientHello message;
 *     *clienthello will point to the start of the complete ClientHello message
 *
 * If a servername pointer was supplied by the caller, and a server name
 * extension was found and parsed, the server name is returned in *servername
 * as a newly allocated string that must be freed by the caller.  This may
 * only occur for a return value of 0.
 *
 * If search is non-zero, then the buffer will be searched for a ClientHello
 * message beginning at offsets >= 0, whereas if search is zero, only
 * ClientHello messages starting at offset 0 will be considered.
 *
 * This code currently supports SSL 2.0, SSL 3.0 and TLS 1.0-1.2.
 *
 * References:
 * draft-hickman-netscape-ssl-00: The SSL Protocol
 * RFC 6101: The Secure Sockets Layer (SSL) Protocol Version 3.0
 * RFC 2246: The TLS Protocol Version 1.0
 * RFC 3546: Transport Layer Security (TLS) Extensions
 * RFC 4346: The Transport Layer Security (TLS) Protocol Version 1.1
 * RFC 4366: Transport Layer Security (TLS) Extensions
 * RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
 * RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
 */
int
ssl_tls_clienthello_parse(const unsigned char *buf, ssize_t sz, int search,
                          const unsigned char **clienthello, char **servername)
{
#ifdef DEBUG_CLIENTHELLO_PARSER
#define DBG_printf(...) log_dbg_printf("ClientHello parser: " __VA_ARGS__)
#else /* !DEBUG_CLIENTHELLO_PARSER */
#define DBG_printf(...) 
#endif /* !DEBUG_CLIENTHELLO_PARSER */
	const unsigned char *p = buf;
	ssize_t n = sz;
	char *sn = NULL;

	*clienthello = NULL;

	DBG_printf("parsing buffer of sz %zd\n", sz);

	do {
		if (*clienthello) {
			/*
			 * Rewind after skipping an invalid ClientHello by
			 * restarting the search one byte after the beginning
			 * of the last candidate
			 */
			p = (*clienthello) + 1;
			n = sz - (p - buf);
			if (sn) {
				free(sn);
				sn = NULL;
			}
		}

		if (search) {
			/* Search for a potential ClientHello */
			while ((n > 0) && (*p != 0x16) && (*p != 0x80)) {
				p++; n--;
			}
			if (n <= 0) {
				/* Search completed without a match; reset
				 * clienthello to NULL to indicate to the
				 * caller that this buffer does not need to be
				 * retried */
				DBG_printf("===> No match:"
				           " rv 1, *clienthello NULL\n");
				*clienthello = NULL;
				return 1;
			}
		}
		*clienthello = p;
		DBG_printf("candidate at offset %td\n", p - buf);

		DBG_printf("byte 0: %02x\n", *p);
		/* +0 0x80 +2 0x01 SSLv2 short header, clientHello;
		 * +0 0x16 +1 0x03 SSLv3/TLSv1.x handshake, clientHello */
		if (*p == 0x80) {
			/* SSLv2 handled here */
			p++; n--;

			if (n < 10) { /* length + 9 */
				DBG_printf("===> [SSLv2] Truncated:"
				           " rv 1, *clienthello set\n");
				return 1;
			}

			DBG_printf("length: %02x\n", p[0]);
			if (n - 1 < p[0]) {
				DBG_printf("===> [SSLv2] Truncated:"
				           " rv 1, *clienthello set\n");
				return 1;
			}
			p++; n--;

			DBG_printf("msgtype: %02x\n", p[0]);
			if (*p != 0x01)
				continue;
			p++; n--;

			DBG_printf("version: %02x %02x\n", p[0], p[1]);
			/* byte order is actually swapped for SSLv2 */
			if (!(
#ifdef HAVE_SSLV2
			      (p[0] == 0x00 && p[1] == 0x02) ||
#endif /* HAVE_SSLV2 */
			      (p[0] == 0x03 && p[1] <= 0x03)))
				continue;
			p += 2; n -= 2;

			DBG_printf("cipher-spec-len: %02x %02x\n", p[0], p[1]);
			ssize_t cipherspec_len = p[0] << 8 | p[1];
			p += 2; n -= 2;

			DBG_printf("session-id-len: %02x %02x\n", p[0], p[1]);
			ssize_t sessionid_len = p[0] << 8 | p[1];
			p += 2; n -= 2;

			DBG_printf("challenge-len: %02x %02x\n", p[0], p[1]);
			ssize_t challenge_len = p[0] << 8 | p[1];
			p += 2; n -= 2;
			if (challenge_len < 16 || challenge_len > 32)
				continue;

			if (n < cipherspec_len
			      + sessionid_len
			      + challenge_len) {
				DBG_printf("===> [SSLv2] Truncated:"
				           " rv 1, *clienthello set\n");
				return 1;
			}

			p += cipherspec_len + sessionid_len + challenge_len;
			n -= cipherspec_len + sessionid_len + challenge_len;
			goto done_parsing;
		} else
		if (*p != 0x16) {
			/* this can only happen if search is 0 */
			DBG_printf("===> No match: rv 1, *clienthello NULL\n");
			*clienthello = NULL;
			return 1;
		}
		p++; n--;

		if (n < 2) {
			DBG_printf("===> Truncated: rv 1, *clienthello set\n");
			return 1;
		}
		DBG_printf("version: %02x %02x\n", p[0], p[1]);
		/* This supports up to TLS 1.2 (0x03 0x03) and will need to be
		 * updated for TLS 1.3 once that is standardized and still
		 * compatible with this parser; remember to also update the
		 * inner version check below */
		if (p[0] != 0x03 || p[1] > 0x03)
			continue;
		p += 2; n -= 2;

		if (n < 2) {
			DBG_printf("===> Truncated: rv 1, *clienthello set\n");
			return 1;
		}
		DBG_printf("length: %02x %02x\n", p[0], p[1]);
		ssize_t recordlen = p[1] + (p[0] << 8);
		DBG_printf("recordlen=%zd\n", recordlen);
		p += 2; n -= 2;
		if (recordlen < 36) /* arbitrary size too small for a c-h */
			continue;
		if (n < recordlen) {
			DBG_printf("n < recordlen: n=%zd\n", n);
			DBG_printf("===> Truncated: rv 1, *clienthello set\n");
			return 1;
		}

		/* from here we give up on a candidate if there is not enough
		 * data available in the buffer, because we already checked the
		 * availability of the whole record. */

		if (n < 1)
			continue;
		DBG_printf("message type: %i\n", *p);
		if (*p != 0x01) /* message type: ClientHello */
			continue;
		p++; n--;

		if (n < 3)
			continue;
		DBG_printf("message len: %02x %02x %02x\n", p[0], p[1], p[2]);
		ssize_t msglen = p[2] + (p[1] << 8) + (p[0] << 16);
		DBG_printf("msglen=%zd\n", msglen);
		p += 3; n -= 3;
		if (msglen < 32) /* arbitrary size too small for a c-h */
			continue;
		if (msglen != recordlen - 4) {
			DBG_printf("msglen != recordlen - 4\n");
			continue;
		}
		if (n < msglen)
			continue;
		n = msglen; /* only parse first message */

		if (n < 2)
			continue;
		DBG_printf("clienthello version %02x %02x\n", p[0], p[1]);
		/* inner version check, see outer one above */
		if (p[0] != 0x03 || p[1] > 0x03)
			continue;
		p += 2; n -= 2;

		if (n < 32)
			continue;
		DBG_printf("clienthello random %02x %02x %02x %02x ...\n",
		           p[0], p[1], p[2], p[3]);
		DBG_printf("compare localtime: %08x\n",
		           (unsigned int)time(NULL));
		p += 32; n -= 32;

		if (n < 1)
			continue;
		DBG_printf("clienthello sidlen %02x\n", *p);
		ssize_t sidlen = *p; /* session id length, 0..32 */
		p += 1; n -= 1;
		if (n < sidlen)
			continue;
		p += sidlen; n -= sidlen;

		if (n < 2)
			continue;
		DBG_printf("clienthello cipher suites length %02x %02x\n",
		           p[0], p[1]);
		ssize_t suiteslen = p[1] + (p[0] << 8);
		p += 2; n -= 2;
		if (n < suiteslen)
			continue;
		p += suiteslen;
		n -= suiteslen;

		if (n < 1)
			continue;
		DBG_printf("clienthello compress methods length %02x\n", *p);
		ssize_t compslen = *p;
		p++; n--;
		if (n < compslen)
			continue;
		p += compslen;
		n -= compslen;

		/* begin of extensions */

		if (n == 0) {
			/* valid ClientHello without extensions */
			DBG_printf("===> Match: rv 0, *clienthello set\n");
			if (servername)
				*servername = NULL;
			return 0;
		}
		if (n < 2)
			continue;
		DBG_printf("tlsexts length %02x %02x\n", p[0], p[1]);
		ssize_t tlsextslen = p[1] + (p[0] << 8);
		DBG_printf("tlsextslen %zd\n", tlsextslen);
		p += 2; n -= 2;
		if (n < tlsextslen)
			continue;
		n = tlsextslen; /* only parse exts, ignore trailing bits */

		while (n > 0) {
			if (n < 4)
				goto continue_search;
			DBG_printf("tlsext type %02x %02x len %02x %02x\n",
			           p[0], p[1], p[2], p[3]);
			unsigned short exttype = p[1] + (p[0] << 8);
			ssize_t extlen = p[3] + (p[2] << 8);
			p += 4; n -= 4;
			if (n < extlen)
				goto continue_search;
			switch (exttype) {
			case 0: {
				ssize_t extn = extlen;
				const unsigned char *extp = p;

				if (extn < 2)
					goto continue_search;
				DBG_printf("list length %02x %02x\n",
				           extp[0], extp[1]);
				ssize_t namelistlen = extp[1] + (extp[0] << 8);
				DBG_printf("namelistlen = %zd\n", namelistlen);
				extp += 2;
				extn -= 2;

				if (namelistlen != extn)
					goto continue_search;

				while (extn > 0) {
					if (extn < 3)
						goto continue_search;
					DBG_printf("ServerName type %02x"
					           " len %02x %02x\n",
					           extp[0], extp[1], extp[2]);
					unsigned char sntype = extp[0];
					ssize_t snlen = extp[2] + (extp[1]<<8);
					extp += 3;
					extn -= 3;
					if (snlen > extn)
						goto continue_search;
					if (snlen > TLSEXT_MAXLEN_host_name)
						goto continue_search;
					/*
					 * We copy the first name only.
					 * RFC 6066: "The ServerNameList MUST
					 * NOT contain more than one name of
					 * the same name_type."
					 */
					if (servername &&
					    sntype == 0 && sn == NULL) {
						sn = malloc(snlen + 1);
						memcpy(sn, extp, snlen);
						sn[snlen] = '\0';
						/* deliberately not checking
						 * for malformed hostnames
						 * containing invalid chars */
					}
					extp += snlen;
					extn -= snlen;
				}
				break;
			}
			default:
				DBG_printf("skipped\n");
				break;
			}
			p += extlen;
			n -= extlen;
		} /* while have more extensions */

done_parsing:
		;
#ifdef DEBUG_CLIENTHELLO_PARSER
		if (n > 0) {
			DBG_printf("unparsed next bytes %02x %02x %02x %02x\n",
			           p[0], p[1], p[2], p[3]);
		}
#endif /* DEBUG_CLIENTHELLO_PARSER */
		DBG_printf("%zd bytes unparsed\n", n);

		/* Valid ClientHello with or without server name */
		DBG_printf("===> Match: rv 0, *clienthello set\n");
		if (servername)
			*servername = sn;
		return 0;
continue_search:
		;
	} while (search && n > 0);

	/* No valid ClientHello messages found, not even a truncated one */
	DBG_printf("===> No match: rv 1, *clienthello NULL\n");
	*clienthello = NULL;
	if (sn) {
		free(sn);
		sn = NULL;
	}
	return 1;
}

/* vim: set noet ft=c: */
