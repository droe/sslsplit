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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include <check.h>

#define TMP_SESS_FILE "extra/pki/session.pem"

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
	return sess;
}

static struct sockaddr_storage addr;
static socklen_t addrlen;
static char sni[] = "daniel.roe.ch";

static void
cachemgr_setup(void)
{
	if ((ssl_init() == -1) || (cachemgr_preinit() == -1))
		exit(EXIT_FAILURE);
	addrlen = sizeof(struct sockaddr_in);
	memset(&addr, 0, addrlen);
	addr.ss_family = AF_INET;
}

static void
cachemgr_teardown(void)
{
	cachemgr_fini();
	ssl_fini();
}

START_TEST(cache_dsess_01)
{
	SSL_SESSION *s1, *s2;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	cachemgr_dsess_set((struct sockaddr*)&addr, addrlen, sni, s1);
	s2 = cachemgr_dsess_get((struct sockaddr*)&addr, addrlen, sni);
	fail_unless(!!s2, "cache returned no session");
	fail_unless(s2 != s1, "cache returned same pointer");
	SSL_SESSION_free(s1);
	SSL_SESSION_free(s2);
}
END_TEST

START_TEST(cache_dsess_02)
{
	SSL_SESSION *s1, *s2;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	s2 = cachemgr_dsess_get((struct sockaddr*)&addr, addrlen, sni);
	fail_unless(s2 == NULL, "session was already in empty cache");
	SSL_SESSION_free(s1);
}
END_TEST

START_TEST(cache_dsess_03)
{
	SSL_SESSION *s1, *s2;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	cachemgr_dsess_set((struct sockaddr*)&addr, addrlen, sni, s1);
	cachemgr_dsess_del((struct sockaddr*)&addr, addrlen, sni);
	s2 = cachemgr_dsess_get((struct sockaddr*)&addr, addrlen, sni);
	fail_unless(s2 == NULL, "cache returned deleted session");
	SSL_SESSION_free(s1);
}
END_TEST

START_TEST(cache_dsess_04)
{
	SSL_SESSION *s1, *s2;

	s1 = ssl_session_from_file(TMP_SESS_FILE);
	fail_unless(!!s1, "creating session failed");
	fail_unless(ssl_session_is_valid(s1), "session invalid");

	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_dsess_set((struct sockaddr*)&addr, addrlen, sni, s1);
	fail_unless(s1->references == 1, "refcount != 1");
	s2 = cachemgr_dsess_get((struct sockaddr*)&addr, addrlen, sni);
	fail_unless(s1->references == 1, "refcount != 1");
	fail_unless(!!s2, "cache returned no session");
	fail_unless(s2->references == 1, "refcount != 1");
	cachemgr_dsess_set((struct sockaddr*)&addr, addrlen, sni, s1);
	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_dsess_del((struct sockaddr*)&addr, addrlen, sni);
	fail_unless(s1->references == 1, "refcount != 1");
	cachemgr_dsess_set((struct sockaddr*)&addr, addrlen, sni, s1);
	fail_unless(s1->references == 1, "refcount != 1");
	SSL_SESSION_free(s1);
	SSL_SESSION_free(s2);
}
END_TEST

Suite *
cachedsess_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cachedsess");

	tc = tcase_create("cache_dsess");
	tcase_add_checked_fixture(tc, cachemgr_setup, cachemgr_teardown);
	tcase_add_test(tc, cache_dsess_01);
	tcase_add_test(tc, cache_dsess_02);
	tcase_add_test(tc, cache_dsess_03);
	tcase_add_test(tc, cache_dsess_04);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
