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

#include "cache.h"

#include "log.h"
#include "khash.h"

#include <pthread.h>

/*
 * Generic, thread-safe cache.
 */

/*
 * Create a new cache based on the initializer callback init_cb.
 */
cache_t *
cache_new(cache_init_cb_t init_cb)
{
	cache_t *cache;

	if (!(cache = malloc(sizeof(cache_t))))
		return NULL;

	init_cb(cache);

	pthread_mutex_init(&cache->mutex, NULL);

	return cache;
}

/*
 * Reinitialize cache after fork().
 */
void
cache_reinit(cache_t *cache)
{
	pthread_mutex_init(&cache->mutex, NULL);
}

/*
 * Free a cache and all associated resources.
 * This function is not thread-safe.
 */
void
cache_free(cache_t *cache)
{
	khiter_t it;

	for (it = cache->begin_cb(); it != cache->end_cb(); it++) {
		if (cache->exist_cb(it)) {
			cache->free_key_cb(cache->get_key_cb(it));
			cache->free_val_cb(cache->get_val_cb(it));
		}
	}
	cache->fini_cb();
	pthread_mutex_destroy(&cache->mutex);
	free(cache);
}

void
cache_gc(cache_t *cache)
{
	khiter_t it;
	cache_val_t val;

	pthread_mutex_lock(&cache->mutex);
	for (it = cache->begin_cb(); it != cache->end_cb(); it++) {
		if (cache->exist_cb(it)) {
			val = cache->get_val_cb(it);
			if (!cache->unpackverify_val_cb(val, 0)) {
				cache->free_val_cb(val);
				cache->free_key_cb(cache->get_key_cb(it));
				cache->del_cb(it);
			}
		}
	}
	pthread_mutex_unlock(&cache->mutex);
}

cache_val_t
cache_get(cache_t *cache, cache_key_t key)
{
	cache_val_t rval = NULL;
	khiter_t it;

	if (!key)
		return NULL;

	pthread_mutex_lock(&cache->mutex);
	it = cache->get_cb(key);
	if (it != cache->end_cb()) {
		cache_val_t val;
		val = cache->get_val_cb(it);
		if (!(rval = cache->unpackverify_val_cb(val, 1))) {
			cache->free_val_cb(val);
			cache->free_key_cb(cache->get_key_cb(it));
			cache->del_cb(it);
		}
	}
	cache->free_key_cb(key);
	pthread_mutex_unlock(&cache->mutex);
	return rval;
}

void
cache_set(cache_t *cache, cache_key_t key, cache_val_t val)
{
	khiter_t it;
	int ret;

	if (!key || !val)
		return;

	pthread_mutex_lock(&cache->mutex);
	it = cache->put_cb(key, &ret);
	if (!ret) {
		cache->free_key_cb(key);
		cache->free_val_cb(cache->get_val_cb(it));
	}
	cache->set_val_cb(it, val);
	pthread_mutex_unlock(&cache->mutex);
}

void
cache_del(cache_t *cache, cache_key_t key)
{
	khiter_t it;

	pthread_mutex_lock(&cache->mutex);
	it = cache->get_cb(key);
	if (it != cache->end_cb()) {
		cache->free_val_cb(cache->get_val_cb(it));
		cache->free_key_cb(cache->get_key_cb(it));
		cache->del_cb(it);
	}
	cache->free_key_cb(key);
	pthread_mutex_unlock(&cache->mutex);
}

/* vim: set noet ft=c: */
