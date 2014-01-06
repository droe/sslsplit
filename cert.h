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

#ifndef CERT_H
#define CERT_H

#include "attrib.h"

#include <openssl/ssl.h>
#include <pthread.h>

typedef struct cert {
	EVP_PKEY *key;
	X509 *crt;
	STACK_OF(X509) * chain;
	pthread_mutex_t mutex;
	size_t references;
} cert_t;

cert_t * cert_new(void) MALLOC;
cert_t * cert_new_load(const char *) MALLOC;
cert_t * cert_new3(EVP_PKEY *, X509 *, STACK_OF(X509) *) MALLOC;
cert_t * cert_new3_copy(EVP_PKEY *, X509 *, STACK_OF(X509) *) MALLOC;
void cert_refcount_inc(cert_t *) NONNULL(1);
void cert_set_key(cert_t *, EVP_PKEY *) NONNULL(1);
void cert_set_crt(cert_t *, X509 *) NONNULL(1);
void cert_set_chain(cert_t *, STACK_OF(X509) *) NONNULL(1);
void cert_free(cert_t *) NONNULL(1);

#endif /* !CERT_H */

/* vim: set noet ft=c: */
