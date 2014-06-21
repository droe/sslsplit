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

#include "cachemgr.h"

#include "cachefkcrt.h"
#include "cachetgcrt.h"
#include "cachessess.h"
#include "cachedsess.h"
#include "log.h"
#include "attrib.h"

#include <string.h>
#include <pthread.h>

#include <netinet/in.h>

cache_t *cachemgr_fkcrt;
cache_t *cachemgr_tgcrt;
cache_t *cachemgr_ssess;
cache_t *cachemgr_dsess;

/*
 * Garbage collector thread entry point.
 * Calls the _gc() method on the cache passed as argument, then returns.
 */
static void *
cachemgr_gc_thread(UNUSED void * arg)
{
	cache_gc(arg);
	return NULL;
}

/*
 * Pre-initialize the caches.
 * The caches may be initialized before or after libevent and OpenSSL.
 * Returns -1 on error, 0 on success.
 */
int
cachemgr_preinit(void)
{
	if (!(cachemgr_fkcrt = cache_new(cachefkcrt_init_cb)))
		goto out4;
	if (!(cachemgr_tgcrt = cache_new(cachetgcrt_init_cb)))
		goto out3;
	if (!(cachemgr_ssess = cache_new(cachessess_init_cb)))
		goto out2;
	if (!(cachemgr_dsess = cache_new(cachedsess_init_cb)))
		goto out1;
	return 0;

out1:
	cache_free(cachemgr_ssess);
out2:
	cache_free(cachemgr_tgcrt);
out3:
	cache_free(cachemgr_fkcrt);
out4:
	return -1;
}

/*
 * Post-fork initialization.
 * Returns -1 on error, 0 on success.
 */
int
cachemgr_init(void)
{
	cache_reinit(cachemgr_fkcrt);
	cache_reinit(cachemgr_tgcrt);
	cache_reinit(cachemgr_ssess);
	cache_reinit(cachemgr_dsess);
	return 0;
}

/*
 * Cleanup the caches and free all memory.  Since OpenSSL certificates are
 * being freed, this must be done before calling the OpenSSL cleanup methods.
 * Also, it is not safe to call this while cachemgr_gc() is still running.
 */
void
cachemgr_fini(void)
{
	cache_free(cachemgr_dsess);
	cache_free(cachemgr_ssess);
	cache_free(cachemgr_tgcrt);
	cache_free(cachemgr_fkcrt);
}

/*
 * Garbage collect all the cache contents; free's up resources occupied by
 * certificates and sessions which are no longer valid.
 * This function returns after the cleanup completed and all threads are
 * joined.
 */
void
cachemgr_gc(void)
{
	pthread_t fkcrt_thr, dsess_thr, ssess_thr;
	int rv;

	/* the tgcrt cache does not need cleanup */

	rv = pthread_create(&fkcrt_thr, NULL, cachemgr_gc_thread,
	                    cachemgr_fkcrt);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_create failed: %s\n",
		               strerror(rv));
	}
	rv = pthread_create(&ssess_thr, NULL, cachemgr_gc_thread,
	                    cachemgr_ssess);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_create failed: %s\n",
		               strerror(rv));
	}
	rv = pthread_create(&dsess_thr, NULL, cachemgr_gc_thread,
	                    cachemgr_dsess);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_create failed: %s\n",
		               strerror(rv));
	}

	rv = pthread_join(fkcrt_thr, NULL);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_join failed: %s\n",
		               strerror(rv));
	}
	rv = pthread_join(ssess_thr, NULL);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_join failed: %s\n",
		               strerror(rv));
	}
	rv = pthread_join(dsess_thr, NULL);
	if (rv) {
		log_err_printf("cachemgr_gc: pthread_join failed: %s\n",
		               strerror(rv));
	}
}

/* vim: set noet ft=c: */
