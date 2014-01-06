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

#ifndef CACHE_H
#define CACHE_H

#include "attrib.h"

#include <pthread.h>

typedef void * cache_val_t;
typedef void * cache_key_t;
typedef unsigned int cache_iter_t; /* must match khiter_t */

typedef cache_iter_t (*cache_begin_cb_t)(void);
typedef cache_iter_t (*cache_end_cb_t)(void);
typedef int (*cache_exist_cb_t)(cache_iter_t);
typedef void (*cache_del_cb_t)(cache_iter_t);
typedef cache_iter_t (*cache_get_cb_t)(cache_key_t);
typedef cache_iter_t (*cache_put_cb_t)(cache_key_t, int *);
typedef void (*cache_free_key_cb_t)(cache_key_t);
typedef void (*cache_free_val_cb_t)(cache_val_t);
typedef cache_key_t (*cache_get_key_cb_t)(cache_iter_t);
typedef cache_val_t (*cache_get_val_cb_t)(cache_iter_t);
typedef void (*cache_set_val_cb_t)(cache_iter_t, cache_val_t);
typedef cache_val_t (*cache_unpackverify_val_cb_t)(cache_val_t, int);
typedef void (*cache_fini_cb_t)(void);

typedef struct cache {
	pthread_mutex_t mutex;

	cache_begin_cb_t begin_cb;
	cache_end_cb_t end_cb;
	cache_exist_cb_t exist_cb;
	cache_del_cb_t del_cb;
	cache_get_cb_t get_cb;
	cache_put_cb_t put_cb;
	cache_free_key_cb_t free_key_cb;
	cache_free_val_cb_t free_val_cb;
	cache_get_key_cb_t get_key_cb;
	cache_get_val_cb_t get_val_cb;
	cache_set_val_cb_t set_val_cb;
	cache_unpackverify_val_cb_t unpackverify_val_cb;
	cache_fini_cb_t fini_cb;
} cache_t;

typedef void (*cache_init_cb_t)(struct cache *);

cache_t * cache_new(cache_init_cb_t) MALLOC;
void cache_reinit(cache_t *) NONNULL(1);
void cache_free(cache_t *) NONNULL(1);
void cache_gc(cache_t *) NONNULL(1);
cache_val_t cache_get(cache_t *, cache_key_t) NONNULL(1) WUNRES;
void cache_set(cache_t *, cache_key_t, cache_val_t) NONNULL(1);
void cache_del(cache_t *, cache_key_t) NONNULL(1);

#endif /* !CACHE_H */

/* vim: set noet ft=c: */
