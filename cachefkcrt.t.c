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

#include "ssl.h"
#include "cachemgr.h"

#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define TESTCERT "extra/pki/rsa.crt"

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

START_TEST(cache_fkcrt_01)
{
	X509 *c1, *c2;

	c1 = ssl_x509_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	cachemgr_fkcrt_set(c1, c1);
	c2 = cachemgr_fkcrt_get(c1);
	fail_unless(c2 == c1, "cache did not return same pointer");
	X509_free(c1);
	X509_free(c2);
}
END_TEST

START_TEST(cache_fkcrt_02)
{
	X509 *c1, *c2;

	c1 = ssl_x509_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	c2 = cachemgr_fkcrt_get(c1);
	fail_unless(c2 == NULL, "certificate was already in empty cache");
	X509_free(c1);
}
END_TEST

START_TEST(cache_fkcrt_03)
{
	X509 *c1, *c2;

	c1 = ssl_x509_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	cachemgr_fkcrt_set(c1, c1);
	cachemgr_fkcrt_del(c1);
	c2 = cachemgr_fkcrt_get(c1);
	fail_unless(c2 == NULL, "cache returned deleted certificate");
	X509_free(c1);
}
END_TEST

START_TEST(cache_fkcrt_04)
{
	X509 *c1, *c2;

	c1 = ssl_x509_load(TESTCERT);
	fail_unless(!!c1, "loading certificate failed");
	fail_unless(c1->references == 1, "refcount != 1");
	cachemgr_fkcrt_set(c1, c1);
	fail_unless(c1->references == 2, "refcount != 2");
	c2 = cachemgr_fkcrt_get(c1);
	fail_unless(c1->references == 3, "refcount != 3");
	cachemgr_fkcrt_set(c1, c1);
	fail_unless(c1->references == 3, "refcount != 3");
	cachemgr_fkcrt_del(c1);
	fail_unless(c1->references == 2, "refcount != 2");
	cachemgr_fkcrt_set(c1, c1);
	fail_unless(c1->references == 3, "refcount != 3");
	X509_free(c1);
	fail_unless(c1->references == 2, "refcount != 2");
	cachemgr_fini();
	fail_unless(c1->references == 1, "refcount != 1");
	X509_free(c2);
	/* deliberate access of free'd X509* */
	fail_unless(c1->references == 0, "refcount != 0");
	fail_unless(cachemgr_preinit() != -1, "reinit");
}
END_TEST

Suite *
cachefkcrt_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cachefkcrt");

	tc = tcase_create("cache_fkcrt");
	tcase_add_checked_fixture(tc, cachemgr_setup, cachemgr_teardown);
	tcase_add_test(tc, cache_fkcrt_01);
	tcase_add_test(tc, cache_fkcrt_02);
	tcase_add_test(tc, cache_fkcrt_03);
	tcase_add_test(tc, cache_fkcrt_04);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
