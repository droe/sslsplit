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

#include "dynbuf.h"

#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define TESTCERT "extra/pki/targets/daniel.roe.ch.pem"
static const unsigned char template[] = "Hello World!";
static unsigned char *buf;
static size_t sz;

static void
buf_setup(void)
{
	sz = sizeof(template);
	buf = malloc(sz);
	memcpy(buf, template, sz);
}

static void
buf_teardown(void)
{
	free(buf);
	buf = NULL;
	sz = 0;
}

START_TEST(dynbuf_new_01)
{
	dynbuf_t *db;

	db = dynbuf_new(buf, sz);
	fail_unless(!!db, "dynbuf not allocated");
	fail_unless(!!db->buf, "buffer not set");
	fail_unless(db->buf == buf, "buffer incorrect");
	fail_unless(db->sz == sz, "size incorrect");
	dynbuf_free(db);
	buf = malloc(sz);
}
END_TEST

START_TEST(dynbuf_new_alloc_01)
{
	dynbuf_t *db;

	db = dynbuf_new_alloc(sz);
	fail_unless(!!db, "dynbuf not allocated");
	fail_unless(!!db->buf, "buffer not set");
	fail_unless(db->sz == sz, "size incorrect");
	dynbuf_free(db);
}
END_TEST

START_TEST(dynbuf_new_copy_01)
{
	dynbuf_t *db;

	db = dynbuf_new_copy(buf, sz);
	fail_unless(!!db, "dynbuf not allocated");
	fail_unless(!!db->buf, "buffer not set");
	fail_unless(db->buf != buf, "buffer incorrect");
	fail_unless(db->sz == sz, "size incorrect");
	fail_unless(!memcmp(db->buf, buf, sz), "buffer data incorrect");
	dynbuf_free(db);
}
END_TEST

START_TEST(dynbuf_new_file_01)
{
	dynbuf_t *db;

	db = dynbuf_new_file(TESTCERT);
	fail_unless(!!db, "dynbuf not allocated");
	fail_unless(!!db->buf, "buffer not set");
	fail_unless(db->buf != buf, "buffer incorrect");
	fail_unless(db->sz > 0, "size incorrect");
	fail_unless(!!strstr((char*)db->buf, "-----BEGIN CERTIFICATE-----"),
	            "cannot find begin of cert");
	fail_unless(!!strstr((char*)db->buf, "-----END CERTIFICATE-----"),
	            "cannot find end of cert");
	dynbuf_free(db);
}
END_TEST

Suite *
dynbuf_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("dynbuf");

	tc = tcase_create("dynbuf_new_01");
	tcase_add_checked_fixture(tc, buf_setup, buf_teardown);
	tcase_add_test(tc, dynbuf_new_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("dynbuf_new_alloc_01");
	tcase_add_checked_fixture(tc, buf_setup, buf_teardown);
	tcase_add_test(tc, dynbuf_new_alloc_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("dynbuf_new_copy_01");
	tcase_add_checked_fixture(tc, buf_setup, buf_teardown);
	tcase_add_test(tc, dynbuf_new_copy_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("dynbuf_new_file_01");
	tcase_add_checked_fixture(tc, buf_setup, buf_teardown);
	tcase_add_test(tc, dynbuf_new_file_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
