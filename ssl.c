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

#include "ssl.h"

#include "log.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
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
#ifndef OPENSSL_NO_TLSEXT
	fprintf(stderr, "TLS Server Name Indication (SNI) supported\n");
#else /* OPENSSL_NO_TLSEXT */
	fprintf(stderr, "TLS Server Name Indication (SNI) not supported\n");
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
#ifndef OPENSSL_NO_RSA
	fprintf(stderr, " RSA");
#else /* OPENSSL_NO_RSA */
	fprintf(stderr, " !RSA");
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	fprintf(stderr, " DSA");
#else /* OPENSSL_NO_DSA */
	fprintf(stderr, " !DSA");
#endif /* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
	fprintf(stderr, " ECDSA");
#else /* OPENSSL_NO_ECDSA */
	fprintf(stderr, " !ECDSA");
#endif /* OPENSSL_NO_ECDSA */
#ifndef OPENSSL_NO_DH
	fprintf(stderr, " DH");
#else /* OPENSSL_NO_DH */
	fprintf(stderr, " !DH");
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	fprintf(stderr, " ECDH");
#else /* OPENSSL_NO_ECDH */
	fprintf(stderr, " !ECDH");
#endif /* OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_EC
	fprintf(stderr, " EC");
#else /* OPENSSL_NO_EC */
	fprintf(stderr, " !EC");
#endif /* OPENSSL_NO_EC */
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

#ifdef OPENSSL_THREADS
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
		pthread_mutex_init(&dl->mutex, NULL);
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
	SSL_library_init();
#ifdef PURIFY
	CRYPTO_malloc_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif /* PURIFY */
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* thread-safety */
#ifdef OPENSSL_THREADS
	ssl_mutex_num = CRYPTO_num_locks();
	ssl_mutex = malloc(ssl_mutex_num * sizeof(*ssl_mutex));
	for (int i = 0; i < ssl_mutex_num; i++) {
		pthread_mutex_init(&ssl_mutex[i], NULL);
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
#endif /* OPENSSL_THREADS */

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
 * Re-initialize OpenSSL after forking.
 */
void
ssl_reinit(void)
{
	if (!ssl_initialized)
		return;

#ifdef OPENSSL_THREADS
	for (int i = 0; i < ssl_mutex_num; i++) {
		pthread_mutex_init(&ssl_mutex[i], NULL);
	}
#endif /* OPENSSL_THREADS */
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

	ERR_remove_state(0); /* current thread */

#ifdef OPENSSL_THREADS
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

	ENGINE_cleanup();
	CONF_modules_finish();
	CONF_modules_unload(1);
	CONF_modules_free();

	EVP_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
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

	rv = asprintf(&str, "%08x = %s%s%s%04x = %s (%s) [%s]",
	              ssl->state,
	              (ssl->state & SSL_ST_CONNECT) ? "SSL_ST_CONNECT|" : "",
	              (ssl->state & SSL_ST_ACCEPT) ? "SSL_ST_ACCEPT|" : "",
	              (ssl->state & SSL_ST_BEFORE) ? "SSL_ST_BEFORE|" : "",
	              ssl->state & SSL_ST_MASK,
	              SSL_state_string(ssl),
	              SSL_state_string_long(ssl),
	              (ssl->type == SSL_ST_CONNECT) ? "connect socket"
	                                            : "accept socket");

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

	if (!(dh = DH_new())) {
		log_err_printf("DH_new() failed\n");
		return NULL;
	}
	switch (keylength) {
		case 512:
			dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
			break;
		case 1024:
			dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
			break;
		case 2048:
			dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
			break;
		case 4096:
			dh->p = BN_bin2bn(dh4096_p, sizeof(dh4096_p), NULL);
			break;
		default:
			log_err_printf("Unhandled DH keylength %i%s\n",
			               keylength,
			               (is_export ? " (export)" : ""));
			DH_free(dh);
			return NULL;
	}
	dh->g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
	if (!dh->p || !dh->g) {
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
		curvename = SSL_EC_KEY_CURVE_DEFAULT;

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

	rv = RAND_pseudo_bytes((unsigned char*)p, sz);
	if (rv == -1) {
		rv = RAND_bytes((unsigned char*)p, sz);
		if (rv != 1)
			return -1;
	}
	return 0;
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
 * Create a fake X509v3 certificate, signed by the provided CA,
 * based on the original certificate retrieved from the real server.
 * The returned certificate is created using X509_new() and thus must
 * be freed by the caller using X509_free().
 * The optional argument extraname is added to subjectAltNames if provided.
 */
X509 *
ssl_x509_forge(X509 *cacrt, EVP_PKEY *cakey, X509 *origcrt,
               const char *extraname, EVP_PKEY *key)
{
	X509_NAME *subject, *issuer;
	GENERAL_NAMES *names;
	GENERAL_NAME *gn;
	X509 *crt;

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
	if (ssl_x509_v3ext_add(&ctx, crt, "basicConstraints",
	                                  "CA:FALSE") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "keyUsage",
	                                  "digitalSignature,"
	                                  "keyEncipherment") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "extendedKeyUsage",
	                                  "serverAuth") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "subjectKeyIdentifier",
	                                  "hash") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "authorityKeyIdentifier",
	                                  "keyid,issuer:always") == -1)
		goto errout;

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
			gn->d.dNSName = M_ASN1_IA5STRING_new();
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
	ssl_x509_v3ext_add(&ctx, crt, "nsComment", "Generated by " PNAME);
#endif /* DEBUG_CERTIFICATE */

	const EVP_MD *md;
	switch (EVP_PKEY_type(cakey->type)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			md = EVP_sha1();
			break;
#endif /* !OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA:
			md = EVP_dss1();
			break;
#endif /* !OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
		case EVP_PKEY_EC:
			md = EVP_ecdsa();
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

#if (OPENSSL_VERSION_NUMBER < 0x1000200fL)
	tmpchain = tmpctx->extra_certs;
#else /* OpenSSL >= 1.0.2 */
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
void
ssl_x509chain_use(SSL_CTX *sslctx, X509 *crt, STACK_OF(X509) *chain)
{
	SSL_CTX_use_certificate(sslctx, crt);

	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *tmpcrt;

		tmpcrt = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(tmpcrt);
		sk_X509_push(sslctx->extra_certs, tmpcrt);
		SSL_CTX_add_extra_chain_cert(sslctx, tmpcrt);
	}
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
	EVP_PKEY * pkey;
	RSA * rsa;

	rsa = RSA_generate_key(keysize, 3, NULL, NULL);
	if (!rsa)
		return NULL;
	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa); /* does not increment refcount */
	return pkey;
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

#ifndef OPENSSL_NO_DH
/*
 * Increment the reference count of DH parameters in a thread-safe
 * manner.
 */
void
ssl_dh_refcount_inc(DH *dh)
{
#ifdef OPENSSL_THREADS
	CRYPTO_add(&dh->references, 1, CRYPTO_LOCK_DH);
#else /* !OPENSSL_THREADS */
	dh->references++;
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
#ifdef OPENSSL_THREADS
	CRYPTO_add(&key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else /* !OPENSSL_THREADS */
	key->references++;
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
#ifdef OPENSSL_THREADS
	CRYPTO_add(&crt->references, 1, CRYPTO_LOCK_X509);
#else /* !OPENSSL_THREADS */
	crt->references++;
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
	strncpy(wildcarded + 1, dot, dotsz);
	wildcarded[dotsz + 1] = '\0';
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
 */
char *
ssl_x509_names_to_str(X509 *crt)
{
	char **names;
	size_t sz;
	char *buf = NULL, *next;

	names = ssl_x509_names(crt);
	if (!names)
		return NULL;

	sz = 0;
	for (char **p = names; *p; p++) {
		sz += strlen(*p) + 1;
	}
	if (!sz) {
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
 * zero if the session has expired or an error occured.
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
	if (curtime > LONG_MAX - timeout)
		return 0;
	return (SSL_SESSION_get_time(sess) < curtime + timeout);
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

#ifndef OPENSSL_NO_TLSEXT
/*
 * Ugly hack to manually parse the SNI TLS extension from a clientHello buf.
 * This is needed because of limitations in the OpenSSL SNI API which only
 * allows to read the indicated server name at the time when we have to
 * provide the server certificate.  It is not possible to asynchroniously
 * read the indicated server name, wait for some event to happen, and then
 * later to provide the server certificate to use and continue the handshake.
 *
 * This function takes a buffer containing (part of) a clientHello message as
 * seen on the network.
 *
 * If server name extension was found and parsed, returns server name buffer
 * that must be free'd by the caller.
 * If parsing failed for inconsistency reasons or if SNI TLS extension was
 * not present in the clientHello, returns NULL.
 * If not enough data was provided in buf, returns NULL and *sz is set to -1
 * to indicate that a call to ssl_tls_clienthello_parse_sni() with more data
 * in buf might succeed.
 *
 * References:
 * RFC 2246: The TLS Protocol Version 1.0
 * RFC 3546: Transport Layer Security (TLS) Extensions
 * RFC 4346: The Transport Layer Security (TLS) Protocol Version 1.1
 * RFC 4366: Transport Layer Security (TLS) Extensions
 * RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
 * RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
 */
char *
ssl_tls_clienthello_parse_sni(const unsigned char *buf, ssize_t *sz)
{
#ifdef DEBUG_SNI_PARSER
#define DBG_printf(...) log_dbg_printf("SNI Parser: " __VA_ARGS__)
#else /* !DEBUG_SNI_PARSER */
#define DBG_printf(...) 
#endif /* !DEBUG_SNI_PARSER */
	const unsigned char *p = buf;
	ssize_t n = *sz;
	char *servername = NULL;

	DBG_printf("buffer length %zd\n", n);

	if (n < 1) {
		*sz = -1;
		goto out;
	}
	DBG_printf("byte 0: %02x\n", *p);
	/* first byte 0x80, third byte 0x01 is SSLv2 clientHello;
	 * first byte 0x22, second byte 0x03 is SSLv3/TLSv1.x clientHello */
	if (*p != 22) /* record type: handshake protocol */
		goto out;
	p++; n--;

	if (n < 2) {
		*sz = -1;
		goto out;
	}
	DBG_printf("version: %02x %02x\n", p[0], p[1]);
	if (p[0] != 3)
		goto out;
	p += 2; n -= 2;

	if (n < 2) {
		*sz = -1;
		goto out;
	}
	DBG_printf("length: %02x %02x\n", p[0], p[1]);
#ifdef DEBUG_SNI_PARSER
	ssize_t recordlen = p[1] + (p[0] << 8);
	DBG_printf("recordlen=%zd\n", recordlen);
#endif /* DEBUG_SNI_PARSER */
	p += 2; n -= 2;

	if (n < 1) {
		*sz = -1;
		goto out;
	}
	DBG_printf("message type: %i\n", *p);
	if (*p != 1) /* message type: ClientHello */
		goto out;
	p++; n--;

	if (n < 3) {
		*sz = -1;
		goto out;
	}
	DBG_printf("message len: %02x %02x %02x\n", p[0], p[1], p[2]);
	ssize_t msglen = p[2] + (p[1] << 8) + (p[0] << 16);
	DBG_printf("msglen=%zd\n", msglen);
	if (msglen < 4)
		goto out;
	p += 3; n -= 3;

	if (n < msglen) {
		*sz = -1;
		goto out;
	}
	n = msglen; /* only parse first message */

	if (n < 2)
		goto out;
	DBG_printf("clienthello version %02x %02x\n", p[0], p[1]);
	if (p[0] != 3)
		goto out;
	p += 2; n -= 2;

	if (n < 32)
		goto out;
	DBG_printf("clienthello random %02x %02x %02x %02x ...\n",
	           p[0], p[1], p[2], p[3]);
	DBG_printf("compare localtime: %08x\n", (unsigned int)time(NULL));
	p += 32; n -= 32;

	if (n < 1)
		goto out;
	DBG_printf("clienthello sidlen %02x\n", *p);
	ssize_t sidlen = *p; /* session id length, 0..32 */
	p += 1; n -= 1;
	if (n < sidlen)
		goto out;
	p += sidlen; n -= sidlen;

	if (n < 2)
		goto out;
	DBG_printf("clienthello cipher suites length %02x %02x\n", p[0], p[1]);
	ssize_t suiteslen = p[1] + (p[0] << 8);
	p += 2; n -= 2;
	if (n < suiteslen) {
		DBG_printf("n < suiteslen (%zd, %zd)\n", n, suiteslen);
		goto out;
	}
	p += suiteslen;
	n -= suiteslen;

	if (n < 1)
		goto out;
	DBG_printf("clienthello compress methods length %02x\n", *p);
	ssize_t compslen = *p;
	p++; n--;
	if (n < compslen)
		goto out;
	p += compslen;
	n -= compslen;

	/* begin of extensions */

	if (n < 2)
		goto out;
	DBG_printf("tlsexts length %02x %02x\n", p[0], p[1]);
	ssize_t tlsextslen = p[1] + (p[0] << 8);
	DBG_printf("tlsextslen %zd\n", tlsextslen);
	p += 2;
	n -= 2;

	if (n < tlsextslen)
		goto out;
	n = tlsextslen; /* only parse extensions, ignore trailing bits */

	while (n > 0) {
		if (n < 4)
			goto out;
		DBG_printf("tlsext type %02x %02x len %02x %02x\n",
		           p[0], p[1], p[2], p[3]);
		unsigned short exttype = p[1] + (p[0] << 8);
		ssize_t extlen = p[3] + (p[2] << 8);
		p += 4;
		n -= 4;
		if (n < extlen)
			goto out;
		switch (exttype) {
			case 0:
			{
				ssize_t extn = extlen;
				const unsigned char *extp = p;

				if (extn < 2)
					goto out;
				DBG_printf("list length %02x %02x\n",
				           extp[0], extp[1]);
				ssize_t namelistlen = extp[1] + (extp[0] << 8);
				DBG_printf("namelistlen = %zd\n", namelistlen);
				extp += 2;
				extn -= 2;

				if (namelistlen != extn)
					goto out;

				while (extn > 0) {
					if (extn < 3)
						goto out;
					DBG_printf("ServerName type %02x"
					           " len %02x %02x\n",
					           extp[0], extp[1], extp[2]);
					unsigned char sntype = extp[0];
					ssize_t snlen = extp[2] + (extp[1]<<8);
					extp += 3;
					extn -= 3;
					if (snlen > extn)
						goto out;
					if (snlen > TLSEXT_MAXLEN_host_name)
						goto out;
					if (sntype == 0) {
						servername = malloc(snlen + 1);
						memcpy(servername, extp, snlen);
						servername[snlen] = '\0';
						/* deliberately not checking
						 * for malformed hostnames
						 * containing invalid chars */
						goto out;
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
	}

#ifdef DEBUG_SNI_PARSER
	if (n > 0) {
		DBG_printf("unparsed next bytes %02x %02x %02x %02x\n",
		           p[0], p[1], p[2], p[3]);
	}
#endif /* DEBUG_SNI_PARSER */
out:
	DBG_printf("%zd bytes unparsed\n", n);
	return servername;
}
#endif /* !OPENSSL_NO_TLSEXT */

/* vim: set noet ft=c: */
