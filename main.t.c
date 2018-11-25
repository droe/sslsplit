/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "attrib.h"
#include "proxy.h"
#include "opts.h"
#include "sys.h"
#include "build.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <check.h>

static char *argv01[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443"
};

static char *argv02[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443",
	"http", "127.0.0.1", "10080", "127.0.0.2", "80"
};

static char *argv03[] = {
	"https", "127.0.0.1", "10443", "sni", "443"
};

static int num_thr;
static int dtable_size;
static size_t proxy_fd_count;
static size_t conn_fd_count;
static opts_t *opts;

#ifdef __linux__
#define NATENGINE "netfilter"
#else
#define NATENGINE "pf"
#endif

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

static void
fd_usage_setup(void)
{
	num_thr = 2 * sys_get_cpu_cores();
	dtable_size = getdtablesize();
	/* stdin, stdout, and stderr = 3 fds */
	proxy_fd_count = 3;
	/* src and dst = 2 fds */
	conn_fd_count = 2;
	opts = opts_new();
}

static void
fd_usage_teardown(void)
{
	opts_free(opts);
}

START_TEST(fd_usage_01)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* proxy + conn thr + proxyspec */
	proxy_fd_count += 3 + 3 * num_thr + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with one proxyspec");

	opts->conffile = strdup("sslsplit.conf");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "conffile changes conn_limit");

	opts_set_clientcrt(opts, "sslsplit", "extra/pki/rsa.crt");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "clientcrt changes conn_limit");

	opts_set_clientkey(opts, "sslsplit", "extra/pki/rsa.key");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "clientkey changes conn_limit");

	opts_set_cacrt(opts, "sslsplit", "extra/pki/rsa.crt");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "cacrt changes conn_limit");

	opts_set_cakey(opts, "sslsplit", "extra/pki/rsa.key");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "cakey changes conn_limit");

	opts_set_key(opts, "sslsplit", "extra/pki/rsa.key");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "key changes conn_limit");

#if 0
#ifndef OPENSSL_NO_DH
	/* TODO: Need a dh.pem to enable this test */
	opts_set_dh(opts, "sslsplit", "dh.pem");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "dh changes conn_limit");
#endif /* !OPENSSL_NO_DH */
#endif

#ifndef OPENSSL_NO_ECDH
	opts->ecdhcurve = strdup("prime256v1");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "ecdhcurve changes conn_limit");
#endif /* !OPENSSL_NO_ECDH */

	opts->ciphers = strdup("ALL:-aNULL");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "ciphers changes conn_limit");

	opts->tgcrtdir = strdup("target");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "tgcrtdir changes conn_limit");

	opts->crlurl = strdup("http://example.com/example.crl");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "crlurl changes conn_limit");

#ifndef OPENSSL_NO_ENGINE
	opts->openssl_engine = strdup("cloudhsm");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "openssl_engine changes conn_limit");
#endif /* !OPENSSL_NO_ENGINE */

	opts->dropuser = strdup("sslsplit");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "dropuser changes conn_limit");

	opts->dropgroup = strdup("sslsplit");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "dropgroup changes conn_limit");

	opts->jaildir = strdup(".");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "jaildir changes conn_limit");

	opts->pidfile = strdup("sslsplit.pid");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "pidfile changes conn_limit");
	
	opts->deny_ocsp = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "deny_ocsp changes conn_limit");

	opts->passthrough = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "passthrough changes conn_limit");

	opts->sslcomp = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "sslcomp changes conn_limit");

	opts->detach = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "detach changes conn_limit");

	opts_set_debug(opts);
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "debug changes conn_limit");

	opts->verify_peer = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "verify_peer changes conn_limit");

	opts->allow_wrong_host = 1;
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "allow_wrong_host changes conn_limit");
}
END_TEST

START_TEST(fd_usage_02)
{
	proxyspec_t *spec = NULL;
	int argc = 10;
	char **argv = argv02;

	/* +2 for second proxyspec */
	proxy_fd_count += 3 + 3 * num_thr + 2 * 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with two proxyspecs");
}
END_TEST

START_TEST(fd_usage_03)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv03;

	/* +1 for dns, both for proxy and per conn thr */
	proxy_fd_count += 4 + 4 * num_thr + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with dns");
}
END_TEST

START_TEST(fd_usage_04)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +1 for certgendir */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 1;
	conn_fd_count += 1;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_certgendir_writeall(opts, "sslsplit", ".");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with certgendir_writeall");

	opts_set_certgendir_writegencerts(opts, "sslsplit", ".");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "certgendir_writegencerts changes conn_limit");
}
END_TEST

START_TEST(fd_usage_05)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +2 for connectlog */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_connectlog(opts, "sslsplit", "connect.log");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with connectlog");
}
END_TEST

START_TEST(fd_usage_06)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +2 for contentlog */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_contentlog(opts, "sslsplit", "content.log");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with contentlog");

	conn_fd_count += 1;
	expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	opts_set_contentlogdir(opts, "sslsplit", ".");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with contentlog_isdir");

	opts_set_contentlogpathspec(opts, "sslsplit", "%s-%d-%T.log");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with contentlog_isspec");
}
END_TEST

START_TEST(fd_usage_07)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +2 for pcaplog */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_pcaplog(opts, "sslsplit", "content.pcap");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with pcaplog");

	conn_fd_count += 1;
	expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	opts_set_pcaplogdir(opts, "sslsplit", ".");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with pcaplog_isdir");

	opts_set_pcaplogpathspec(opts, "sslsplit", "%s-%d-%T.pcap");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with pcaplog_isspec");
}
END_TEST

START_TEST(fd_usage_08)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +2 for masterkeylog */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 2;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_masterkeylog(opts, "sslsplit", "masterkeys.log");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with masterkeylog");
}
END_TEST

#ifndef WITHOUT_MIRROR
START_TEST(fd_usage_09)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	/* +1 for mirrortarget */
	proxy_fd_count += 3 + 3 * num_thr + 2 + 1;
	size_t expected_conn_limit = (dtable_size - proxy_fd_count) / conn_fd_count;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	opts->spec = spec;

	opts_set_mirrortarget(opts, "sslsplit", "192.0.2.1");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "wrong conn_limit with mirrortarget");

	opts_set_mirrorif(opts, "sslsplit", "lo");
	opts_compute_conn_limit(opts);
	fail_unless(opts->conn_limit == expected_conn_limit, "mirrorif changes conn_limit");
}
END_TEST
#endif /* !WITHOUT_MIRROR */

Suite *
main_suite(void)
{
	Suite *s;
	TCase *tc;
	s = suite_create("main");

	tc = tcase_create("build_date");
	tcase_add_test(tc, build_date_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("fd_usage");
	tcase_add_checked_fixture(tc, fd_usage_setup, fd_usage_teardown);
	tcase_add_test(tc, fd_usage_01);
	tcase_add_test(tc, fd_usage_02);
	tcase_add_test(tc, fd_usage_03);
	tcase_add_test(tc, fd_usage_04);
	tcase_add_test(tc, fd_usage_05);
	tcase_add_test(tc, fd_usage_06);
	tcase_add_test(tc, fd_usage_07);
	tcase_add_test(tc, fd_usage_08);
#ifndef WITHOUT_MIRROR
	tcase_add_test(tc, fd_usage_09);
#endif /* !WITHOUT_MIRROR */
	suite_add_tcase(s, tc);

	return s;
}

Suite * opts_suite(void);
Suite * dynbuf_suite(void);
Suite * logbuf_suite(void);
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
Suite * defaults_suite(void);

int
main(UNUSED int argc, UNUSED char *argv[])
{
	int nfail;
	SRunner *sr;

	sr = srunner_create(blank_suite());
	srunner_add_suite(sr, main_suite());
	srunner_add_suite(sr, opts_suite());
	srunner_add_suite(sr, dynbuf_suite());
	srunner_add_suite(sr, logbuf_suite());
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
	srunner_add_suite(sr, defaults_suite());
	srunner_run_all(sr, CK_NORMAL);
	nfail = srunner_ntests_failed(sr);
	srunner_free(sr);

	return !nfail ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim: set noet ft=c: */
