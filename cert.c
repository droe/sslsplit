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

#include "cert.h"

#include "ssl.h"

#include <string.h>

/*
 * Certificate, including private key and certificate chain.
 */

cert_t *
cert_new(void)
{
	cert_t *c;

	if (!(c = malloc(sizeof(cert_t))))
		return NULL;
	memset(c, 0, sizeof(cert_t));
	c->references = 1;
	pthread_mutex_init(&c->mutex, NULL);
	return c;
}

/*
 * Passed OpenSSL objects are owned by cert_t; refcount will not be
 * incremented, stack will not be duplicated.
 */
cert_t *
cert_new3(EVP_PKEY *key, X509 *crt, STACK_OF(X509) *chain)
{
	cert_t *c;

	if (!(c = malloc(sizeof(cert_t))))
		return NULL;
	c->key = key;
	c->crt = crt;
	c->chain = chain;
	c->references = 1;
	pthread_mutex_init(&c->mutex, NULL);
	return c;
}

/*
 * Passed OpenSSL objects are copied by cert_t; crt/key refcount will be
 * incremented, stack will be duplicated.
 */
cert_t *
cert_new3_copy(EVP_PKEY *key, X509 *crt, STACK_OF(X509) *chain)
{
	cert_t *c;

	if (!(c = malloc(sizeof(cert_t))))
		return NULL;
	c->key = key;
	ssl_key_refcount_inc(c->key);
	c->crt = crt;
	ssl_x509_refcount_inc(c->crt);
	c->chain = sk_X509_dup(chain);
	for (int i = 0; i < sk_X509_num(c->chain); i++) {
		ssl_x509_refcount_inc(sk_X509_value(c->chain, i));
	}
	c->references = 1;
	pthread_mutex_init(&c->mutex, NULL);
	return c;
}

/*
 * Load cert_t from file.
 */
cert_t *
cert_new_load(const char *filename)
{
	cert_t *c;

	if (!(c = malloc(sizeof(cert_t))))
		return NULL;
	memset(c, 0, sizeof(cert_t));

	if (ssl_x509chain_load(&c->crt, &c->chain, filename) == -1) {
		free(c);
		return NULL;
	}
	c->key = ssl_key_load(filename);
	if (!c->key) {
		X509_free(c->crt);
		if (c->chain) {
			sk_X509_pop_free(c->chain, X509_free);
		}
		free(c);
		return NULL;
	}
	c->references = 1;
	pthread_mutex_init(&c->mutex, NULL);
	return c;
}

/*
 * Increment reference count.
 */
void
cert_refcount_inc(cert_t *c)
{
	pthread_mutex_lock(&c->mutex);
	c->references++;
	pthread_mutex_unlock(&c->mutex);
}

/*
 * Thread-safe setter functions; they copy the value (refcounts are inc'd).
 */
void
cert_set_key(cert_t *c, EVP_PKEY *key)
{
	pthread_mutex_lock(&c->mutex);
	if (c->key) {
		EVP_PKEY_free(c->key);
	}
	c->key = key;
	if (c->key) {
		ssl_key_refcount_inc(c->key);
	}
	pthread_mutex_unlock(&c->mutex);
}
void
cert_set_crt(cert_t *c, X509 *crt)
{
	pthread_mutex_lock(&c->mutex);
	if (c->crt) {
		X509_free(c->crt);
	}
	c->crt = crt;
	if (c->crt) {
		ssl_x509_refcount_inc(c->crt);
	}
	pthread_mutex_unlock(&c->mutex);
}
void
cert_set_chain(cert_t *c, STACK_OF(X509) *chain)
{
	pthread_mutex_lock(&c->mutex);
	if (c->chain) {
		sk_X509_pop_free(c->chain, X509_free);
	}
	if (chain) {
		c->chain = sk_X509_dup(chain);
		for (int i = 0; i < sk_X509_num(c->chain); i++) {
			ssl_x509_refcount_inc(sk_X509_value(c->chain, i));
		}
	} else {
		c->chain = NULL;
	}
	pthread_mutex_unlock(&c->mutex);
}

/*
 * Free cert including internal objects.
 */
void
cert_free(cert_t *c)
{
	pthread_mutex_lock(&c->mutex);
	c->references--;
	if (c->references) {
		pthread_mutex_unlock(&c->mutex);
		return;
	}
	pthread_mutex_unlock(&c->mutex);
	pthread_mutex_destroy(&c->mutex);
	if (c->key) {
		EVP_PKEY_free(c->key);
	}
	if (c->crt) {
		X509_free(c->crt);
	}
	if (c->chain) {
		sk_X509_pop_free(c->chain, X509_free);
	}
	free(c);
}

/* vim: set noet ft=c: */
