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

#include "cachetgcrt.h"

#include "ssl.h"
#include "khash.h"

/*
 * Cache for target cert / chain / key tuples read from configured directory.
 * This cache does not need garbage collection.
 *
 * key: char *    common name
 * val: cert_t *  cert / chain / key tuple
 */

KHASH_INIT(cstrmap_t, char*, void*, 1, kh_str_hash_func, kh_str_hash_equal)

static khash_t(cstrmap_t) *certmap;

static cache_iter_t
cachetgcrt_begin_cb(void)
{
	return kh_begin(certmap);
}

static cache_iter_t
cachetgcrt_end_cb(void)
{
	return kh_end(certmap);
}

static int
cachetgcrt_exist_cb(cache_iter_t it)
{
	return kh_exist(certmap, it);
}

static void
cachetgcrt_del_cb(cache_iter_t it)
{
	kh_del(cstrmap_t, certmap, it);
}

static cache_iter_t
cachetgcrt_get_cb(cache_key_t key)
{
	return kh_get(cstrmap_t, certmap, key);
}

static cache_iter_t
cachetgcrt_put_cb(cache_key_t key, int *ret)
{
	return kh_put(cstrmap_t, certmap, key, ret);
}

static void
cachetgcrt_free_key_cb(cache_key_t key)
{
	free(key);
}

static void
cachetgcrt_free_val_cb(cache_val_t val)
{
	cert_free(val);
}

static cache_key_t
cachetgcrt_get_key_cb(cache_iter_t it)
{
	return kh_key(certmap, it);
}

static cache_val_t
cachetgcrt_get_val_cb(cache_iter_t it)
{
	return kh_val(certmap, it);
}

static void
cachetgcrt_set_val_cb(cache_iter_t it, cache_val_t val)
{
	kh_val(certmap, it) = val;
}

static cache_val_t
cachetgcrt_unpackverify_val_cb(cache_val_t val, int copy)
{
	if (copy) {
		cert_refcount_inc(val);
		return val;
	}
	return ((void*)-1);
}

static void
cachetgcrt_fini_cb(void)
{
	kh_destroy(cstrmap_t, certmap);
}

void
cachetgcrt_init_cb(cache_t *cache)
{
	certmap = kh_init(cstrmap_t);

	cache->begin_cb                 = cachetgcrt_begin_cb;
	cache->end_cb                   = cachetgcrt_end_cb;
	cache->exist_cb                 = cachetgcrt_exist_cb;
	cache->del_cb                   = cachetgcrt_del_cb;
	cache->get_cb                   = cachetgcrt_get_cb;
	cache->put_cb                   = cachetgcrt_put_cb;
	cache->free_key_cb              = cachetgcrt_free_key_cb;
	cache->free_val_cb              = cachetgcrt_free_val_cb;
	cache->get_key_cb               = cachetgcrt_get_key_cb;
	cache->get_val_cb               = cachetgcrt_get_val_cb;
	cache->set_val_cb               = cachetgcrt_set_val_cb;
	cache->unpackverify_val_cb      = cachetgcrt_unpackverify_val_cb;
	cache->fini_cb                  = cachetgcrt_fini_cb;
}

cache_key_t
cachetgcrt_mkkey(const char *keycn)
{
	return strdup(keycn);
}

cache_val_t
cachetgcrt_mkval(cert_t *valcrt)
{
	cert_refcount_inc(valcrt);
	return valcrt;
}

/* vim: set noet ft=c: */
