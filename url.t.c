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

#include "url.h"

#include <string.h>

#include <check.h>

static const char *plain01 = "===1234===";
static const char *plain02 = "\x00\x01\x7F\xFF";

static const char *coded01 = "%3D%3D%3D1234%3D%3D%3D";
static const char *coded02 = "%00%01%7F%FF";

static const char *coded03 = "%";
static const char *coded04 = "foo%zzbar";
static const char *coded05 = "foo%a%3Dbar";

START_TEST(url_dec_01)
{
	char *buf;
	size_t sz;

	buf = url_dec(coded01, strlen(coded01), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain01), "wrong length");
	fail_unless(!memcmp(plain01, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(url_dec_02)
{
	char *buf;
	size_t sz;

	buf = url_dec(coded02, strlen(coded02), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain02 + 1) + 1, "wrong length");
	fail_unless(!memcmp(plain02, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(url_dec_03)
{
	char *buf;
	size_t sz;

	buf = url_dec(coded03, strlen(coded03), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(url_dec_04)
{
	char *buf;
	size_t sz;

	buf = url_dec(coded04, strlen(coded04), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(url_dec_05)
{
	char *buf;
	size_t sz;

	buf = url_dec(coded05, strlen(coded05), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(url_dec_06)
{
	char *buf;
	size_t sz;

	buf = url_dec("", 0, &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(!sz, "length not 0");
	fail_unless(!buf[0], "not empty string");
	free(buf);
}
END_TEST


Suite *
url_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("url");

	tc = tcase_create("url_dec");
	tcase_add_test(tc, url_dec_01);
	tcase_add_test(tc, url_dec_02);
	tcase_add_test(tc, url_dec_03);
	tcase_add_test(tc, url_dec_04);
	tcase_add_test(tc, url_dec_05);
	tcase_add_test(tc, url_dec_06);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
