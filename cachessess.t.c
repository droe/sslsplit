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

#include "ssl.h"
#include "cachemgr.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <check.h>

#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20501000L
#define TMP_SESS_FILE "extra/pki/session-libressl-2.5.0.pem"
#else
#define TMP_SESS_FILE "extra/pki/session.pem"
#endif


static SSL_SESSION *
ssl_session_from_file(const char *filename)
{
	SSL_SESSION *sess;
	FILE *f;

	f = fopen(filename, "r");
	if (!f)
		return NULL;
	sess = PEM_read_SSL_SESSION(f, NULL, NULL, NULL);
	fclose(f);
	/* to avoid having to regenerate the session, just bump its time */
	SSL_SESSION_set_time(sess, time(NULL) - 1);
	return sess;
}

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

START_TEST(cache_ssess_01)
{
	SSL_SESSION *s1, *s2;
	const unsigned char* session_id;
	unsigned int len;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	cachemgr_ssess_set(s1);
	session_id = SSL_SESSION_get_id(s1, &len);
	s2 = cachemgr_ssess_get(session_id, len);
	fail_unless(!!s2, "cache returned no session");
	fail_unless(s2 != s1, "cache returned same pointer");
	SSL_SESSION_free(s1);
	SSL_SESSION_free(s2);
}
END_TEST

START_TEST(cache_ssess_02)
{
	SSL_SESSION *s1, *s2;
	const unsigned char* session_id;
	unsigned int len;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	session_id = SSL_SESSION_get_id(s1, &len);
	s2 = cachemgr_ssess_get(session_id, len);
	fail_unless(s2 == NULL, "session was already in empty cache");
	SSL_SESSION_free(s1);
}
END_TEST

START_TEST(cache_ssess_03)
{
	SSL_SESSION *s1, *s2;
	const unsigned char* session_id;
	unsigned int len;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	cachemgr_ssess_set(s1);
	cachemgr_ssess_del(s1);
	session_id = SSL_SESSION_get_id(s1, &len);
	s2 = cachemgr_ssess_get(session_id, len);
	fail_unless(s2 == NULL, "cache returned deleted session");
	SSL_SESSION_free(s1);
}
END_TEST

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
START_TEST(cache_ssess_04)
{
	SSL_SESSION *s1, *s2;
	const unsigned char* session_id;
	unsigned int len;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_ssess_set(s1);
	fail_unless(s1->references == 1, "refcount != 1");
	session_id = SSL_SESSION_get_id(s1, &len);
	s2 = cachemgr_ssess_get(session_id, len);
	fail_unless(s1->references == 1, "refcount != 1");
	fail_unless(!!s2, "cache returned no session");
	fail_unless(s2->references == 1, "refcount != 1");
	cachemgr_ssess_set(s1);
	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_ssess_del(s1);
	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_ssess_set(s1);
	fail_unless(s1->references == 1, "refcount != 1");
	SSL_SESSION_free(s1);
	SSL_SESSION_free(s2);
}
END_TEST
#endif

Suite *
cachessess_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cachessess");

	tc = tcase_create("cache_ssess");
	tcase_add_checked_fixture(tc, cachemgr_setup, cachemgr_teardown);
	tcase_add_test(tc, cache_ssess_01);
	tcase_add_test(tc, cache_ssess_02);
	tcase_add_test(tc, cache_ssess_03);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	tcase_add_test(tc, cache_ssess_04);
#endif
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
