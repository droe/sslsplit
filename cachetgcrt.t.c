/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "ssl.h"
#include "cert.h"
#include "cachemgr.h"

#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define TESTCERT "extra/pki/targets/daniel.roe.ch.pem"

static void
cachemgr_setup(void)
{
	if ((ssl_init() == -1) || (cachemgr_preinit() == -1))
		exit(EXIT_FAILURE);
}

static void
cachemgr_teardown(void)
{
	cachemgr_fini();
	ssl_fini();
}

START_TEST(cache_tgcrt_01)
{
	cert_t *c1, *c2;

	c1 = cert_new_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	cachemgr_tgcrt_set("daniel.roe.ch", c1);
	c2 = cachemgr_tgcrt_get("daniel.roe.ch");
	fail_unless(!!c2, "cache did not return a certificate");
	fail_unless(c2 == c1, "cache did not return same pointer");
	cert_free(c1);
	cert_free(c2);
}
END_TEST

START_TEST(cache_tgcrt_02)
{
	cert_t *c;

	c = cachemgr_tgcrt_get("daniel.roe.ch");
	fail_unless(c == NULL, "certificate was already in empty cache");
}
END_TEST

START_TEST(cache_tgcrt_03)
{
	cert_t *c1, *c2;

	c1 = cert_new_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	cachemgr_tgcrt_set("daniel.roe.ch", c1);
	cachemgr_tgcrt_del("daniel.roe.ch");
	c2 = cachemgr_tgcrt_get("daniel.roe.ch");
	fail_unless(c2 == NULL, "cache returned deleted certificate");
	cert_free(c1);
}
END_TEST

START_TEST(cache_tgcrt_04)
{
	cert_t *c1, *c2;

	c1 = cert_new_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	fail_unless(c1->references == 1, "refcount != 1");
	cachemgr_tgcrt_set("daniel.roe.ch", c1);
	fail_unless(c1->references == 2, "refcount != 2");
	c2 = cachemgr_tgcrt_get("daniel.roe.ch");
	fail_unless(c1->references == 3, "refcount != 3");
	cachemgr_tgcrt_set("daniel.roe.ch", c1);
	fail_unless(c1->references == 3, "refcount != 3");
	cachemgr_tgcrt_del("daniel.roe.ch");
	fail_unless(c1->references == 2, "refcount != 2");
	cachemgr_tgcrt_set("daniel.roe.ch", c1);
	fail_unless(c1->references == 3, "refcount != 3");
	cert_free(c1);
	fail_unless(c1->references == 2, "refcount != 2");
	cachemgr_fini();
	fail_unless(c1->references == 1, "refcount != 1");
	cert_free(c2);
#ifndef LIBRESSL_VERSION_NUMBER
	/* deliberate access of free'd cert_t* */
	fail_unless(c1->references == 0, "refcount != 0");
#else /* LIBRESSL_VERSION_NUMBER */
	fprintf(stderr, "deliberate access after free test in cache_tgcrt_04 "
			"omitted because LibreSSL fails with refcount != 0\n");
#endif /* LIBRESSL_VERSION_NUMBER */
	fail_unless(cachemgr_preinit() != -1, "reinit");
}
END_TEST

Suite *
cachetgcrt_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cachetgcrt");

	tc = tcase_create("cache_tgcrt");
	tcase_add_checked_fixture(tc, cachemgr_setup, cachemgr_teardown);
	tcase_add_test(tc, cache_tgcrt_01);
	tcase_add_test(tc, cache_tgcrt_02);
	tcase_add_test(tc, cache_tgcrt_03);
	tcase_add_test(tc, cache_tgcrt_04);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
