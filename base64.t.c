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

#include "base64.h"

#include <string.h>

#include <check.h>

static const char *plain01 = "any carnal pleasure.";
static const char *plain02 = "any carnal pleasure";
static const char *plain03 = "any carnal pleasur";
static const char *plain04 = "any carnal pleasu";
static const char *plain05 = "any carnal pleas";

static const char *coded01 = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
static const char *coded02 = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
static const char *coded03 = "YW55IGNhcm5hbCBwbGVhc3Vy";
static const char *coded04 = "YW55IGNhcm5hbCBwbGVhc3U=";
static const char *coded05 = "YW55IGNhcm5hbCBwbGVhcw==";

static const char *coded06 = "YW55=GNhcm5hbCBwbGVhcw==";
static const char *coded07 = "YW55I=Nhcm5hbCBwbGVhcw==";
static const char *coded08 = "YW55IG=hcm5hbCBwbGVhcw==";
static const char *coded09 = "YW55IGN=cm5hbCBwbGVhcw==";
static const char *coded10 = "YW55\nGNhcm5hbCBwbGVhcw==";
static const char *coded11 = "YW55 GNhcm5hbCBwbGVhcw==";
static const char *coded12 = "YW55-GNhcm5hbCBwbGVhcw==";
static const char *coded13 = "YW55%GNhcm5hbCBwbGVhcw==";
static const char *coded14 = "YW55IGNhcm5hbCBwbGVhcw=";
static const char *coded15 = "YW55IGNhcm5hbCBwbGVhcw";

START_TEST(base64_enc_01)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)plain01, strlen(plain01), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(coded01), "wrong length");
	fail_unless(!memcmp(coded01, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_enc_02)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)plain02, strlen(plain02), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(coded02), "wrong length");
	fail_unless(!memcmp(coded02, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_enc_03)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)plain03, strlen(plain03), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(coded03), "wrong length");
	fail_unless(!memcmp(coded03, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_enc_04)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)plain04, strlen(plain04), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(coded04), "wrong length");
	fail_unless(!memcmp(coded04, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_enc_05)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)plain05, strlen(plain05), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(coded05), "wrong length");
	fail_unless(!memcmp(coded05, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_enc_06)
{
	char *buf;
	size_t sz;

	buf = base64_enc((unsigned char *)"", 0, &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(!sz, "length not 0");
	fail_unless(!buf[0], "not empty string");
	free(buf);
}
END_TEST

START_TEST(base64_dec_01)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded01, strlen(coded01), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain01), "wrong length");
	fail_unless(!memcmp(plain01, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_dec_02)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded02, strlen(coded02), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain02), "wrong length");
	fail_unless(!memcmp(plain02, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_dec_03)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded03, strlen(coded03), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain03), "wrong length");
	fail_unless(!memcmp(plain03, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_dec_04)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded04, strlen(coded04), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain04), "wrong length");
	fail_unless(!memcmp(plain04, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_dec_05)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded05, strlen(coded05), &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(sz == strlen(plain05), "wrong length");
	fail_unless(!memcmp(plain05, buf, sz), "wrong data");
	free(buf);
}
END_TEST

START_TEST(base64_dec_06)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded06, strlen(coded06), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_07)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded07, strlen(coded07), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_08)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded08, strlen(coded08), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_09)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded09, strlen(coded09), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_10)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded10, strlen(coded10), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_11)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded11, strlen(coded11), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_12)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded12, strlen(coded12), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_13)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded13, strlen(coded13), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_14)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded14, strlen(coded14), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_15)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(coded15, strlen(coded15), &sz);
	fail_unless(!buf, "buffer returned");
}
END_TEST

START_TEST(base64_dec_16)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec("", 0, &sz);
	fail_unless(!!buf, "no buffer returned");
	fail_unless(!sz, "length not 0");
	fail_unless(!buf[0], "not empty string");
	free(buf);
}
END_TEST

Suite *
base64_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("base64");

	tc = tcase_create("base64_enc");
	tcase_add_test(tc, base64_enc_01);
	tcase_add_test(tc, base64_enc_02);
	tcase_add_test(tc, base64_enc_03);
	tcase_add_test(tc, base64_enc_04);
	tcase_add_test(tc, base64_enc_05);
	tcase_add_test(tc, base64_enc_06);
	suite_add_tcase(s, tc);

	tc = tcase_create("base64_dec");
	tcase_add_test(tc, base64_dec_01);
	tcase_add_test(tc, base64_dec_02);
	tcase_add_test(tc, base64_dec_03);
	tcase_add_test(tc, base64_dec_04);
	tcase_add_test(tc, base64_dec_05);
	tcase_add_test(tc, base64_dec_06);
	tcase_add_test(tc, base64_dec_07);
	tcase_add_test(tc, base64_dec_08);
	tcase_add_test(tc, base64_dec_09);
	tcase_add_test(tc, base64_dec_10);
	tcase_add_test(tc, base64_dec_11);
	tcase_add_test(tc, base64_dec_12);
	tcase_add_test(tc, base64_dec_13);
	tcase_add_test(tc, base64_dec_14);
	tcase_add_test(tc, base64_dec_15);
	tcase_add_test(tc, base64_dec_16);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
