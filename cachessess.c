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

#include "cachessess.h"

#include "dynbuf.h"
#include "ssl.h"
#include "khash.h"

/*
 * Cache for incoming src connection SSL sessions.
 *
 * key: dynbuf_t *  SSL session ID
 * val: dynbuf_t *  ASN.1 serialized SSL_SESSION
 */

static inline khint_t
kh_dynbuf_hash_func(dynbuf_t *b)
{
	khint_t *p = (khint_t *)b->buf;
	khint_t h;
	int rem;

	if ((rem = b->sz % sizeof(khint_t))) {
		memcpy(&h, b->buf + b->sz - rem, rem);
	} else {
		h = 0;
	}

	while (p < (khint_t*)(b->buf + b->sz - rem)) {
		h ^= *p++;
	}

	return h;
}

#define kh_dynbuf_hash_equal(a, b) \
        (((a)->sz == (b)->sz) && \
         (memcmp((a)->buf, (b)->buf, (a)->sz) == 0))

KHASH_INIT(dynbufmap_t, dynbuf_t*, dynbuf_t*, 1, kh_dynbuf_hash_func,
           kh_dynbuf_hash_equal)

static khash_t(dynbufmap_t) *srcsessmap;

static cache_iter_t
cachessess_begin_cb(void)
{
	return kh_begin(srcsessmap);
}

static cache_iter_t
cachessess_end_cb(void)
{
	return kh_end(srcsessmap);
}

static int
cachessess_exist_cb(cache_iter_t it)
{
	return kh_exist(srcsessmap, it);
}

static void
cachessess_del_cb(cache_iter_t it)
{
	kh_del(dynbufmap_t, srcsessmap, it);
}

static cache_iter_t
cachessess_get_cb(cache_key_t key)
{
	return kh_get(dynbufmap_t, srcsessmap, key);
}

static cache_iter_t
cachessess_put_cb(cache_key_t key, int *ret)
{
	return kh_put(dynbufmap_t, srcsessmap, key, ret);
}

static void
cachessess_free_key_cb(cache_key_t key)
{
	dynbuf_free(key);
}

static void
cachessess_free_val_cb(cache_val_t val)
{
	dynbuf_free(val);
}

static cache_key_t
cachessess_get_key_cb(cache_iter_t it)
{
	return kh_key(srcsessmap, it);
}

static cache_val_t
cachessess_get_val_cb(cache_iter_t it)
{
	return kh_val(srcsessmap, it);
}

static void
cachessess_set_val_cb(cache_iter_t it, cache_val_t val)
{
	kh_val(srcsessmap, it) = val;
}

static cache_val_t
cachessess_unpackverify_val_cb(cache_val_t val, int copy)
{
	dynbuf_t *valbuf = val;
	SSL_SESSION *sess;
	const unsigned char *p;

	p = (const unsigned char *)valbuf->buf;
	sess = d2i_SSL_SESSION(NULL, &p, valbuf->sz); /* increments p */
	if (!sess)
		return NULL;
	if (!ssl_session_is_valid(sess)) {
		SSL_SESSION_free(sess);
		return NULL;
	}
	if (copy)
		return sess;
	SSL_SESSION_free(sess);
	return ((void*)-1);
}

static void
cachessess_fini_cb(void)
{
	kh_destroy(dynbufmap_t, srcsessmap);
}

void
cachessess_init_cb(cache_t *cache)
{
	srcsessmap = kh_init(dynbufmap_t);

	cache->begin_cb                 = cachessess_begin_cb;
	cache->end_cb                   = cachessess_end_cb;
	cache->exist_cb                 = cachessess_exist_cb;
	cache->del_cb                   = cachessess_del_cb;
	cache->get_cb                   = cachessess_get_cb;
	cache->put_cb                   = cachessess_put_cb;
	cache->free_key_cb              = cachessess_free_key_cb;
	cache->free_val_cb              = cachessess_free_val_cb;
	cache->get_key_cb               = cachessess_get_key_cb;
	cache->get_val_cb               = cachessess_get_val_cb;
	cache->set_val_cb               = cachessess_set_val_cb;
	cache->unpackverify_val_cb      = cachessess_unpackverify_val_cb;
	cache->fini_cb                  = cachessess_fini_cb;
}

cache_key_t
cachessess_mkkey(const unsigned char *id, const size_t idlen)
{
	return dynbuf_new_copy(id, idlen);
}

cache_val_t
cachessess_mkval(SSL_SESSION *sess)
{
	dynbuf_t *db;
	unsigned char *p;
	size_t asn1sz;

	asn1sz = i2d_SSL_SESSION(sess, NULL);
	if (!asn1sz || !(db = dynbuf_new_alloc(asn1sz))) {
		return NULL;
	}
	p = db->buf;
	i2d_SSL_SESSION(sess, &p); /* updates p */
	return db;
}

/* vim: set noet ft=c: */
