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

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

static char *argv01[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443"
};
static char *argv02[] = {
	"https", "::1", "10443", "::2", "443"
};
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
static char *argv07[] = {
	"http", "127.0.0.1", "10443", "sni", "443"
};
static char *argv08[] = {
	"https", "127.0.0.1", "10443", "no_such_engine"
};
static char *argv09[] = {
	"https", "127.0.0.1", "10443", "127.0.0.2", "443",
	"https", "::1", "10443", "::2", "443"
};
static char *argv10[] = {
	"https", "127.0.0.1", "10443",
	"https", "::1", "10443"
};

#define NATENGINE "pf"

START_TEST(proxyspec_parse_01)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv01;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_02)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv02;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_03)
{
	proxyspec_t *spec;
	int argc = 2;
	char **argv = argv01;

	close(2);
	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_04)
{
	proxyspec_t *spec;
	int argc = 4;
	char **argv = argv01;

	close(2);
	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_05)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv03;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_06)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv04;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_07)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv05;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_08)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv06;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(spec->sni_port == 443, "SNI port is not set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_09)
{
	proxyspec_t *spec;
	int argc = 5;
	char **argv = argv07;

	close(2);
	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_10)
{
	proxyspec_t *spec;
	int argc = 4;
	char **argv = argv06;

	close(2);
	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_11)
{
	proxyspec_t *spec;
	int argc = 3;
	char **argv = argv08;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!!spec->natengine, "natengine not set");
	fail_unless(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_12)
{
	proxyspec_t *spec;
	int argc = 4;
	char **argv = argv08;

	close(2);
	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	if (spec)
		proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_13)
{
	proxyspec_t *spec;
	int argc = 10;
	char **argv = argv09;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(spec->next->ssl, "not SSL");
	fail_unless(spec->next->http, "not HTTP");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->next->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!spec->next->natengine, "natengine is set");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(proxyspec_parse_14)
{
	proxyspec_t *spec;
	int argc = 6;
	char **argv = argv10;

	spec = proxyspec_parse(&argc, &argv, NATENGINE);
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!!spec->natengine, "natengine not set");
	fail_unless(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(spec->next->ssl, "not SSL");
	fail_unless(spec->next->http, "not HTTP");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->next->connect_addrlen, "connect addr set");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!!spec->next->natengine, "natengine not set");
	fail_unless(!strcmp(spec->next->natengine, NATENGINE),
	            "natengine mismatch");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	proxyspec_free(spec);
}
END_TEST

START_TEST(opts_debug_01)
{
	opts_t *opts;

	opts = opts_new();
	opts->debug = 0;
	fail_unless(!opts->debug, "plain 0");
	fail_unless(!OPTS_DEBUG(opts), "macro 0");
	opts->debug = 1;
	fail_unless(!!opts->debug, "plain 1");
	fail_unless(!!OPTS_DEBUG(opts), "macro 1");
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
	tcase_add_test(tc, proxyspec_parse_02);
	tcase_add_exit_test(tc, proxyspec_parse_03, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_04, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_05);
	tcase_add_test(tc, proxyspec_parse_06);
	tcase_add_test(tc, proxyspec_parse_07);
	tcase_add_test(tc, proxyspec_parse_08);
	tcase_add_exit_test(tc, proxyspec_parse_09, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_10, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_11);
	tcase_add_exit_test(tc, proxyspec_parse_12, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_13);
	tcase_add_test(tc, proxyspec_parse_14);
	suite_add_tcase(s, tc);

	tc = tcase_create("opts_debug");
	tcase_add_test(tc, opts_debug_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
