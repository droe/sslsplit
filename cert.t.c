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
#include "cert.h"

#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define TESTCERT "extra/pki/targets/daniel.roe.ch.pem"

START_TEST(cert_new_load_01)
{
	cert_t *c;

	c = cert_new_load(TESTCERT);
	fail_unless(!!c, "loading PEM failed");
	fail_unless(!!c->crt, "loading crt failed");
	fail_unless(!!c->key, "loading key failed");
	fail_unless(!!c->chain, "initializing chain stack failed");
	fail_unless(sk_X509_num(c->chain) == 1, "loading chain failed");
	cert_free(c);
}
END_TEST

START_TEST(cert_refcount_inc_01)
{
	cert_t *c;

	c = cert_new_load(TESTCERT);
	fail_unless(!!c, "loading PEM failed");
	fail_unless(c->references == 1, "refcount mismatch");
	cert_refcount_inc(c);
	fail_unless(c->references == 2, "refcount mismatch");
	cert_free(c);
	fail_unless(c->references == 1, "refcount mismatch");
	cert_free(c);
	/* deliberate access after last free() */
	fail_unless(c->references == 0, "refcount mismatch");
}
END_TEST

Suite *
cert_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cert");

	tc = tcase_create("cert_new_load");
	tcase_add_test(tc, cert_new_load_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("cert_refcount_inc");
	tcase_add_test(tc, cert_refcount_inc_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
