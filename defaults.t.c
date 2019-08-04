/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "sys.h"

#include "defaults.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <check.h>

#define CONNECT_CMD "openssl s_client -connect www.google.com:443" \
                    " -quiet -no_ign_eof </dev/null >/dev/null 2>/dev/null"

#ifndef DOCKER
START_TEST(defaults_dropuser_01)
{
	fail_unless(0 == sys_privdrop(DFLT_DROPUSER, NULL, NULL),
	            "privdrop failed");
}
END_TEST

/*
 * This test is designed to fail in the third assertion if the currently
 * configured default dropuser is not allowed to make outbound network
 * connections.  It also fails if we do not have Internet connection.
 */
START_TEST(defaults_dropuser_02)
{
	fail_unless(0 == system(CONNECT_CMD),
	            "connect failed for user running tests");
	fail_unless(0 == sys_privdrop(DFLT_DROPUSER, NULL, NULL),
	            "privdrop failed");
	fail_unless(0 == system(CONNECT_CMD),
	            "connect failed for default dropuser " DFLT_DROPUSER);
}
END_TEST
#endif /* DOCKER */

Suite *
defaults_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("defaults");

	tc = tcase_create("dropuser");
#ifndef DOCKER
	if (getuid() == 0) {
		tcase_add_test(tc, defaults_dropuser_01);
		tcase_add_test(tc, defaults_dropuser_02);
	} else {
		fprintf(stderr, "defaults: 2 tests omitted because "
		                "not building as root\n");
	}
#else /* DOCKER */
	fprintf(stderr, "defaults: 2 tests omitted because "
	                "building in docker\n");
#endif /* DOCKER */
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
