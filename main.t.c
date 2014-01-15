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

#include "attrib.h"
#include "opts.h"
#include "version.h"

#include <stdlib.h>
#include <string.h>

#include <check.h>

Suite *
blank_suite(void)
{
	Suite *s;
	s = suite_create("");
	return s;
}

START_TEST(build_date_01)
{
	fail_unless(strlen(build_date) == 10, "length mismatch");
	fail_unless(build_date[4] == '-', "year/month separator not dash");
	fail_unless(build_date[7] == '-', "month/day separator not dash");
}
END_TEST

Suite *
main_suite(void)
{
	Suite *s;
	TCase *tc;
	s = suite_create("main");

	tc = tcase_create("build_date");
	tcase_add_test(tc, build_date_01);
	suite_add_tcase(s, tc);

	return s;
}

Suite * opts_suite(void);
Suite * dynbuf_suite(void);
Suite * cert_suite(void);
Suite * cachemgr_suite(void);
Suite * cachefkcrt_suite(void);
Suite * cachetgcrt_suite(void);
Suite * cachedsess_suite(void);
Suite * cachessess_suite(void);
Suite * ssl_suite(void);
Suite * sys_suite(void);
Suite * base64_suite(void);
Suite * url_suite(void);
Suite * util_suite(void);
Suite * pxythrmgr_suite(void);

int
main(UNUSED int argc, UNUSED char *argv[])
{
	int nfail;
	SRunner *sr;

	sr = srunner_create(blank_suite());
	srunner_add_suite(sr, main_suite());
	srunner_add_suite(sr, opts_suite());
	srunner_add_suite(sr, dynbuf_suite());
	srunner_add_suite(sr, cert_suite());
	srunner_add_suite(sr, cachemgr_suite());
	srunner_add_suite(sr, cachefkcrt_suite());
	srunner_add_suite(sr, cachetgcrt_suite());
	srunner_add_suite(sr, cachedsess_suite());
	srunner_add_suite(sr, cachessess_suite());
	srunner_add_suite(sr, ssl_suite());
	srunner_add_suite(sr, sys_suite());
	srunner_add_suite(sr, base64_suite());
	srunner_add_suite(sr, url_suite());
	srunner_add_suite(sr, util_suite());
	srunner_add_suite(sr, pxythrmgr_suite());
	srunner_run_all(sr, CK_NORMAL);
	nfail = srunner_ntests_failed(sr);
	srunner_free(sr);

	return !nfail ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim: set noet ft=c: */
