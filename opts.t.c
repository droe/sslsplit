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

#include "attrib.h"
#include "opts.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

static char *argv01[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443"
};
#ifndef TRAVIS
static char *argv02[] = {
	"https", "::1", "10443", "::2", "443"
};
#endif /* !TRAVIS */
static char *argv03[] = {
	"http", "127.0.0.1", "10443", "127.0.0.2", "443"
};
static char *argv04[] = {
	"ssl", "127.0.0.1", "10443", "127.0.0.2", "443"
};
static char *argv05[] = {
	"tcp", "127.0.0.1", "10443", "127.0.0.2", "443"
};
static char *argv06[] = {
	"https", "127.0.0.1", "10443", "sni", "443"
};
#ifndef DOCKER
static char *argv07[] = {
	"http", "127.0.0.1", "10443", "sni", "443"
};
#endif /* !DOCKER */
static char *argv08[] = {
	"https", "127.0.0.1", "10443", "no_such_engine"
};
#ifndef TRAVIS
static char *argv09[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443",
	"https", "::1", "10443", "::2", "443"
};
static char *argv10[] = {
	"https", "127.0.0.1", "10443",
	"https", "::1", "10443"
};
#endif /* !TRAVIS */
static char *argv11[] = {
	"autossl", "127.0.0.1", "10025"
};
static char *argv12[] = {
	"autossl", "127.0.0.1", "10025", "127.0.0.2", "25",
	"https", "127.0.0.1", "10443", "127.0.0.2", "443"
};
#ifndef DOCKER
static char *argv13[] = {
	"autossl", "127.0.0.1", "10025", "sni", "25"
};
#endif /* !DOCKER */
static char *argv14[] = {
	"https", "127.0.0.1", "10443",
	"autossl", "127.0.0.1", "10025", "127.0.0.2", "25"
};

#ifdef __linux__
#define NATENGINE "netfilter"
#else
#define NATENGINE "pf"
#endif

START_TEST(proxyspec_parse_01)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv01;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

#ifndef TRAVIS
START_TEST(proxyspec_parse_02)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv02;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST
#endif /* !TRAVIS */

#ifndef DOCKER
START_TEST(proxyspec_parse_03)
{
	proxyspec_t *spec = NULL;
	int argc = 2;
	char **argv = argv01;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST
#endif /* !DOCKER */

#ifndef DOCKER
START_TEST(proxyspec_parse_04)
{
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv01;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST
#endif /* !DOCKER */

START_TEST(proxyspec_parse_05)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv03;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(!spec->ssl, "SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_06)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv04;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(!spec->http, "HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_07)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv05;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(!spec->ssl, "SSL");
	ck_assert_msg(!spec->http, "HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_08)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv06;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(!spec->connect_addrlen, "connect addr set");
	ck_assert_msg(spec->sni_port == 443, "SNI port is not set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

#ifndef DOCKER
START_TEST(proxyspec_parse_09)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv07;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_10)
{
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv06;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST
#endif /* !DOCKER */

START_TEST(proxyspec_parse_11)
{
	proxyspec_t *spec = NULL;
	int argc = 3;
	char **argv = argv08;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(!spec->connect_addrlen, "connect addr set");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!!spec->natengine, "natengine not set");
	ck_assert_msg(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

#ifndef DOCKER
START_TEST(proxyspec_parse_12)
{
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv08;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST
#endif /* !DOCKER */

#ifndef TRAVIS
START_TEST(proxyspec_parse_13)
{
	proxyspec_t *spec = NULL;
	int argc = 10;
	char **argv = argv09;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!!spec->next, "next is not set");
	ck_assert_msg(spec->next->ssl, "not SSL");
	ck_assert_msg(spec->next->http, "not HTTP");
	ck_assert_msg(!spec->next->upgrade, "Upgrade");
	ck_assert_msg(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->next->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->next->sni_port, "SNI port is set");
	ck_assert_msg(!spec->next->natengine, "natengine is set");
	ck_assert_msg(!spec->next->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_14)
{
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv10;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	ck_assert_msg(!spec->connect_addrlen, "connect addr set");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!!spec->natengine, "natengine not set");
	ck_assert_msg(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!!spec->next, "next is not set");
	ck_assert_msg(spec->next->ssl, "not SSL");
	ck_assert_msg(spec->next->http, "not HTTP");
	ck_assert_msg(!spec->next->upgrade, "Upgrade");
	ck_assert_msg(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(!spec->next->connect_addrlen, "connect addr set");
	ck_assert_msg(!spec->next->sni_port, "SNI port is set");
	ck_assert_msg(!!spec->next->natengine, "natengine not set");
	ck_assert_msg(!strcmp(spec->next->natengine, NATENGINE),
	            "natengine mismatch");
	ck_assert_msg(!spec->next->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST
#endif /* !TRAVIS */

START_TEST(proxyspec_parse_15)
{
	proxyspec_t *spec = NULL;
	int argc = 3;
	char **argv = argv11;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(!spec->ssl, "SSL");
	ck_assert_msg(!spec->http, "HTTP");
	ck_assert_msg(spec->upgrade, "not Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(!spec->connect_addrlen, "connect addr set");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!!spec->natengine, "natengine is not set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_16)
{
	proxyspec_t *spec = NULL;
	int argc = 10;
	char **argv = argv12;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(spec->ssl, "not SSL");
	ck_assert_msg(spec->http, "not HTTP");
	ck_assert_msg(!spec->upgrade, "Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!!spec->next, "next is not set");
	ck_assert_msg(!spec->next->ssl, "SSL");
	ck_assert_msg(!spec->next->http, "HTTP");
	ck_assert_msg(spec->next->upgrade, "not Upgrade");
	ck_assert_msg(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->next->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->next->sni_port, "SNI port is set");
	ck_assert_msg(!spec->next->natengine, "natengine is set");
	ck_assert_msg(!spec->next->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST

#ifndef DOCKER
START_TEST(proxyspec_parse_17)
{
	proxyspec_t *spec = NULL;
	int argc = 5;
	char **argv = argv13;

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	if (spec)
		proxyspec_free(spec);
}
END_TEST
#endif /* !DOCKER */

START_TEST(proxyspec_parse_18)
{
	proxyspec_t *spec = NULL;
	int argc = 8;
	char **argv = argv14;

	proxyspec_parse(&argc, &argv, NATENGINE, &spec);
	ck_assert_msg(!!spec, "failed to parse spec");
	ck_assert_msg(!spec->ssl, "SSL");
	ck_assert_msg(!spec->http, "HTTP");
	ck_assert_msg(spec->upgrade, "not Upgrade");
	ck_assert_msg(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	ck_assert_msg(!spec->sni_port, "SNI port is set");
	ck_assert_msg(!spec->natengine, "natengine is set");
	ck_assert_msg(!spec->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->natsocket, "natsocket() is set");
	ck_assert_msg(!!spec->next, "next is not set");
	ck_assert_msg(spec->next->ssl, "not SSL");
	ck_assert_msg(spec->next->http, "not HTTP");
	ck_assert_msg(!spec->next->upgrade, "Upgrade");
	ck_assert_msg(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	ck_assert_msg(!spec->next->connect_addrlen, "connect addr set");
	ck_assert_msg(!spec->next->sni_port, "SNI port is set");
	ck_assert_msg(!!spec->next->natengine, "natengine is not set");
	ck_assert_msg(!spec->next->natlookup, "natlookup() is set");
	ck_assert_msg(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(opts_debug_01)
{
	opts_t *opts;

	opts = opts_new();
	opts->debug = 0;
	ck_assert_msg(!opts->debug, "plain 0");
	ck_assert_msg(!OPTS_DEBUG(opts), "macro 0");
	opts->debug = 1;
	ck_assert_msg(!!opts->debug, "plain 1");
	ck_assert_msg(!!OPTS_DEBUG(opts), "macro 1");
	opts_free(opts);
}
END_TEST

Suite *
opts_suite(void)
{
	Suite *s;
	TCase *tc;
	s = suite_create("opts");

	tc = tcase_create("proxyspec_parse");
	tcase_add_test(tc, proxyspec_parse_01);
#ifndef TRAVIS
	tcase_add_test(tc, proxyspec_parse_02); /* IPv6 */
#endif /* !TRAVIS */
#ifndef DOCKER
	tcase_add_exit_test(tc, proxyspec_parse_03, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_04, EXIT_FAILURE);
#endif /* !DOCKER */
	tcase_add_test(tc, proxyspec_parse_05);
	tcase_add_test(tc, proxyspec_parse_06);
	tcase_add_test(tc, proxyspec_parse_07);
	tcase_add_test(tc, proxyspec_parse_08);
#ifndef DOCKER
	tcase_add_exit_test(tc, proxyspec_parse_09, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_10, EXIT_FAILURE);
#endif /* !DOCKER */
	tcase_add_test(tc, proxyspec_parse_11);
#ifndef DOCKER
	tcase_add_exit_test(tc, proxyspec_parse_12, EXIT_FAILURE);
#endif /* !DOCKER */
#ifndef TRAVIS
	tcase_add_test(tc, proxyspec_parse_13); /* IPv6 */
	tcase_add_test(tc, proxyspec_parse_14); /* IPv6 */
#endif /* !TRAVIS */
	tcase_add_test(tc, proxyspec_parse_15);
	tcase_add_test(tc, proxyspec_parse_16);
#ifndef DOCKER
	tcase_add_exit_test(tc, proxyspec_parse_17, EXIT_FAILURE);
#endif /* !DOCKER */
	tcase_add_test(tc, proxyspec_parse_18);
	suite_add_tcase(s, tc);

	tc = tcase_create("opts_debug");
	tcase_add_test(tc, opts_debug_01);
	suite_add_tcase(s, tc);

#ifdef DOCKER
	fprintf(stderr, "opts: 6 tests omitted because building in docker\n");
#endif
#ifdef TRAVIS
	fprintf(stderr, "opts: 3 tests omitted because building in travis\n");
#endif

	return s;
}

/* vim: set noet ft=c: */
