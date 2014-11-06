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

#include "cachefkcrt.h"

#include "ssl.h"
#include "khash.h"

/*
 * Cache for generated fake certificates.
 *
 * key: char[SSL_X509_FPRSZ]  fingerprint of original server cert
 * val: X509 *                generated fake certificate
 */

static inline khint_t
kh_x509fpr_hash_func(void *b)
{
	khint_t *p = (khint_t*)(((char*)b) + SSL_X509_FPRSZ);
	khint_t h = 0;

	/* assumes fpr is uniformly distributed */
	while (--p >= (khint_t*)b)
		h ^= *p;
	return h;
}

#define kh_x509fpr_hash_equal(a, b) \
        (memcmp((char*)(a), (char*)(b), SSL_X509_FPRSZ) == 0)

KHASH_INIT(sha1map_t, void*, void*, 1, kh_x509fpr_hash_func,
           kh_x509fpr_hash_equal)

static khash_t(sha1map_t) *certmap;

static cache_iter_t
cachefkcrt_begin_cb(void)
{
	return kh_begin(certmap);
}

static cache_iter_t
cachefkcrt_end_cb(void)
{
	return kh_end(certmap);
}

static int
cachefkcrt_exist_cb(cache_iter_t it)
{
	return kh_exist(certmap, it);
}

static void
cachefkcrt_del_cb(cache_iter_t it)
{
	kh_del(sha1map_t, certmap, it);
}

static cache_iter_t
cachefkcrt_get_cb(cache_key_t key)
{
	return kh_get(sha1map_t, certmap, key);
}

static cache_iter_t
cachefkcrt_put_cb(cache_key_t key, int *ret)
{
	return kh_put(sha1map_t, certmap, key, ret);
}

static void
cachefkcrt_free_key_cb(cache_key_t key)
{
	free(key);
}

static void
cachefkcrt_free_val_cb(cache_val_t val)
{
	X509_free(val);
}

static cache_key_t
cachefkcrt_get_key_cb(cache_iter_t it)
{
	return kh_key(certmap, it);
}

static cache_val_t
cachefkcrt_get_val_cb(cache_iter_t it)
{
	return kh_val(certmap, it);
}

static void
cachefkcrt_set_val_cb(cache_iter_t it, cache_val_t val)
{
	kh_val(certmap, it) = val;
}

static cache_val_t
cachefkcrt_unpackverify_val_cb(cache_val_t val, int copy)
{
	if (!ssl_x509_is_valid(val))
		return NULL;
	if (copy) {
		ssl_x509_refcount_inc(val);
		return val;
	}
	return ((void*)-1);
}

static void
cachefkcrt_fini_cb(void)
{
	kh_destroy(sha1map_t, certmap);
}

void
cachefkcrt_init_cb(cache_t *cache)
{
	certmap = kh_init(sha1map_t);

	cache->begin_cb                 = cachefkcrt_begin_cb;
	cache->end_cb                   = cachefkcrt_end_cb;
	cache->exist_cb                 = cachefkcrt_exist_cb;
	cache->del_cb                   = cachefkcrt_del_cb;
	cache->get_cb                   = cachefkcrt_get_cb;
	cache->put_cb                   = cachefkcrt_put_cb;
	cache->free_key_cb              = cachefkcrt_free_key_cb;
	cache->free_val_cb              = cachefkcrt_free_val_cb;
	cache->get_key_cb               = cachefkcrt_get_key_cb;
	cache->get_val_cb               = cachefkcrt_get_val_cb;
	cache->set_val_cb               = cachefkcrt_set_val_cb;
	cache->unpackverify_val_cb      = cachefkcrt_unpackverify_val_cb;
	cache->fini_cb                  = cachefkcrt_fini_cb;
}

cache_key_t
cachefkcrt_mkkey(X509 *keycrt)
{
	unsigned char *fpr;

	if (!(fpr = malloc(SSL_X509_FPRSZ)))
		return NULL;
	ssl_x509_fingerprint_sha1(keycrt, fpr);
	return fpr;
}

cache_val_t
cachefkcrt_mkval(X509 *valcrt)
{
	ssl_x509_refcount_inc(valcrt);
	return valcrt;
}

/* vim: set noet ft=c: */
