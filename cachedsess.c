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

#include "cachedsess.h"

#include "dynbuf.h"
#include "ssl.h"
#include "khash.h"

#include <netinet/in.h>

/*
 * Cache for outgoing dst connection SSL sessions.
 *
 * key: dynbuf_t *  original destination IP address, port and SNI string
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

static khash_t(dynbufmap_t) *dstsessmap;

static cache_iter_t
cachedsess_begin_cb(void)
{
	return kh_begin(dstsessmap);
}

static cache_iter_t
cachedsess_end_cb(void)
{
	return kh_end(dstsessmap);
}

static int
cachedsess_exist_cb(cache_iter_t it)
{
	return kh_exist(dstsessmap, it);
}

static void
cachedsess_del_cb(cache_iter_t it)
{
	kh_del(dynbufmap_t, dstsessmap, it);
}

static cache_iter_t
cachedsess_get_cb(cache_key_t key)
{
	return kh_get(dynbufmap_t, dstsessmap, key);
}

static cache_iter_t
cachedsess_put_cb(cache_key_t key, int *ret)
{
	return kh_put(dynbufmap_t, dstsessmap, key, ret);
}

static void
cachedsess_free_key_cb(cache_key_t key)
{
	dynbuf_free(key);
}

static void
cachedsess_free_val_cb(cache_val_t val)
{
	dynbuf_free(val);
}

static cache_key_t
cachedsess_get_key_cb(cache_iter_t it)
{
	return kh_key(dstsessmap, it);
}

static cache_val_t
cachedsess_get_val_cb(cache_iter_t it)
{
	return kh_val(dstsessmap, it);
}

static void
cachedsess_set_val_cb(cache_iter_t it, cache_val_t val)
{
	kh_val(dstsessmap, it) = val;
}

static cache_val_t
cachedsess_unpackverify_val_cb(cache_val_t val, int copy)
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
cachedsess_fini_cb(void)
{
	kh_destroy(dynbufmap_t, dstsessmap);
}

void
cachedsess_init_cb(cache_t *cache)
{
	dstsessmap = kh_init(dynbufmap_t);

	cache->begin_cb                 = cachedsess_begin_cb;
	cache->end_cb                   = cachedsess_end_cb;
	cache->exist_cb                 = cachedsess_exist_cb;
	cache->del_cb                   = cachedsess_del_cb;
	cache->get_cb                   = cachedsess_get_cb;
	cache->put_cb                   = cachedsess_put_cb;
	cache->free_key_cb              = cachedsess_free_key_cb;
	cache->free_val_cb              = cachedsess_free_val_cb;
	cache->get_key_cb               = cachedsess_get_key_cb;
	cache->get_val_cb               = cachedsess_get_val_cb;
	cache->set_val_cb               = cachedsess_set_val_cb;
	cache->unpackverify_val_cb      = cachedsess_unpackverify_val_cb;
	cache->fini_cb                  = cachedsess_fini_cb;
}

cache_key_t
cachedsess_mkkey(const struct sockaddr *addr, UNUSED const socklen_t addrlen,
                 const char *sni)
{
	dynbuf_t tmp, *db;
	short port;
	size_t snilen;

	switch (((struct sockaddr_storage *)addr)->ss_family) {
		case AF_INET:
			tmp.buf = (unsigned char *)
			          &((struct sockaddr_in*)addr)->sin_addr;
			tmp.sz = sizeof(struct in_addr);
			port = ((struct sockaddr_in*)addr)->sin_port;
			break;
		case AF_INET6:
			tmp.buf = (unsigned char *)
			          &((struct sockaddr_in6*)addr)->sin6_addr;
			tmp.sz = sizeof(struct in6_addr);
			port = ((struct sockaddr_in6*)addr)->sin6_port;
			break;
		default:
			return NULL;
	}

	snilen = sni ? strlen(sni) : 0;
	if (!(db = dynbuf_new_alloc(tmp.sz + sizeof(port) + snilen)))
		return NULL;
	memcpy(db->buf, tmp.buf, tmp.sz);
	memcpy(db->buf + tmp.sz, (char*)&port, sizeof(port));
	memcpy(db->buf + tmp.sz + sizeof(port), sni, snilen);
	return db;
}

cache_val_t
cachedsess_mkval(SSL_SESSION *sess)
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
