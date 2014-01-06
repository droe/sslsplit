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

#include "util.h"

#include <string.h>

#include <check.h>

static const char *string01 = "test";
static const char *string02 = "    test";
static const char *string03 = "\t\t\t\ttest";
static const char *string04 = "\t \t test";
static const char *string05 = "    \r\ntest";

START_TEST(util_skipws_01)
{
	char *p;

	p = util_skipws(string01);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_02)
{
	char *p;

	p = util_skipws(string02);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_03)
{
	char *p;

	p = util_skipws(string03);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_04)
{
	char *p;

	p = util_skipws(string04);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_05)
{
	char *p;

	p = util_skipws(string05);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "\r\ntest"), "wrong data");
}
END_TEST

START_TEST(util_skipws_06)
{
	char *p;

	p = util_skipws("");
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, ""), "wrong data");
}
END_TEST

Suite *
util_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("util");

	tc = tcase_create("util_skipws");
	tcase_add_test(tc, util_skipws_01);
	tcase_add_test(tc, util_skipws_02);
	tcase_add_test(tc, util_skipws_03);
	tcase_add_test(tc, util_skipws_04);
	tcase_add_test(tc, util_skipws_05);
	tcase_add_test(tc, util_skipws_06);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
