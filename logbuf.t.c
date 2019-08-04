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

#include "logbuf.h"

#include <string.h>

#include <check.h>

START_TEST(logbuf_make_contiguous_01)
{
	logbuf_t *lb;

	lb = logbuf_new_printf(NULL, "%s", "789");
	lb = logbuf_new_printf(lb, "%s", "456");
	lb = logbuf_new_printf(lb, "%s", "123");
	lb = logbuf_make_contiguous(lb);
	fail_unless(!!lb, "logbuf_make_contiguous failed");
	fail_unless(!lb->next, "multiple buffers");
	fail_unless(logbuf_size(lb) == 9, "buffer size incorrect");
	fail_unless(!memcmp(lb->buf, "123456789", 9), "buffer value incorrect");
	logbuf_free(lb);
}
END_TEST

Suite *
logbuf_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("logbuf");

	tc = tcase_create("");
	tcase_add_test(tc, logbuf_make_contiguous_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
