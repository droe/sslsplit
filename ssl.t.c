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
#include "ssl.h"

#include <stdlib.h>

#include <check.h>

#define TESTCERT "extra/pki/server.crt"
#define TESTCERT2 "extra/pki/rsa.crt"

static void
ssl_setup(void)
{
	if (ssl_init() == -1)
		exit(EXIT_FAILURE);
}

static void
ssl_teardown(void)
{
	ssl_fini();
}

static char wildcard1[] = "*.example.org";
static char wildcard2[] = "www.*.example.org";
static char wildcard3[] = "*.*.org";
static char wildcard4[] = "www*.example.org";
static char wildcard5[] = "*";
static char wildcard6[] = "*.xn--r-1ga.ch";
static char wildcard7[] = "xn--r-1ga*.xn--r-1ga.ch";
static char wildcard8[] = "xn--r-1ga.*.xn--r-1ga.ch";
static char name1[] = "www.example.org";
static char name2[] = "www.example.com";
static char name3[] = "example.org";
static char name4[] = "www.example.org.co.uk";
static char name5[] = "test.www.example.org";
static char name6[] = "www.test.example.org";
static char name7[] = "wwwtest.example.org";
static char name8[] = "ch";
static char name9[] = "www.xn--r-1ga.ch";
static char name10[] = "xn--r-1ga.xn--r-1ga.ch";
static char name11[] = "";

START_TEST(ssl_wildcardify_01)
{
	char *wc = ssl_wildcardify(name1);
	fail_unless(!strcmp(wc, wildcard1), "mismatch for 'www.example.org'");
	free(wc);
}
END_TEST

START_TEST(ssl_wildcardify_02)
{
	char *wc = ssl_wildcardify(name8);
	fail_unless(!strcmp(wc, wildcard5), "mismatch for 'ch'");
	free(wc);
}
END_TEST

START_TEST(ssl_wildcardify_03)
{
	char *wc = ssl_wildcardify(name11);
	fail_unless(!strcmp(wc, wildcard5), "mismatch for ''");
	free(wc);
}
END_TEST

START_TEST(ssl_dnsname_match_01)
{
	fail_unless(
		ssl_dnsname_match(name1, sizeof(name1) - 1,
		                  name1, sizeof(name1) - 1),
		"Hostname does not match itself");
}
END_TEST

START_TEST(ssl_dnsname_match_02)
{
	fail_unless(
		!ssl_dnsname_match(name1, sizeof(name1) - 1,
		                   name2, sizeof(name2) - 1),
		"Hostname matches hostname with different TLD");
}
END_TEST

START_TEST(ssl_dnsname_match_03)
{
	fail_unless(
		ssl_dnsname_match(wildcard1, sizeof(wildcard1) - 1,
		                  name1, sizeof(name1) - 1),
		"Regular wildcard does not match");
}
END_TEST

START_TEST(ssl_dnsname_match_04)
{
	fail_unless(
		!ssl_dnsname_match(wildcard1, sizeof(wildcard1) - 1,
		                   name2, sizeof(name2) - 1),
		"Regular wildcard matches other TLD");
}
END_TEST

START_TEST(ssl_dnsname_match_05)
{
	fail_unless(
		!ssl_dnsname_match(wildcard1, sizeof(wildcard1) - 1,
		                   name3, sizeof(name3) - 1),
		"Regular wildcard matches upper level domain");
}
END_TEST

START_TEST(ssl_dnsname_match_06)
{
	fail_unless(
		!ssl_dnsname_match(wildcard1, sizeof(wildcard1) - 1,
		                   name4, sizeof(name4) - 1),
		"Regular wildcard matches despite added suffix");
}
END_TEST

START_TEST(ssl_dnsname_match_07)
{
	fail_unless(
		!ssl_dnsname_match(wildcard1, sizeof(wildcard1) - 1,
		                   name5, sizeof(name5) - 1),
		"Regular wildcard matches two elements");
}
END_TEST

START_TEST(ssl_dnsname_match_08)
{
	fail_unless(
		!ssl_dnsname_match(wildcard2, sizeof(wildcard2) - 1,
		                   name6, sizeof(name6) - 1),
		"Wildcard matches in non-leftmost element");
}
END_TEST

START_TEST(ssl_dnsname_match_09)
{
	fail_unless(
		!ssl_dnsname_match(wildcard3, sizeof(wildcard3) - 1,
		                   name5, sizeof(name5) - 1),
		"Multiple wildcard matches");
}
END_TEST

START_TEST(ssl_dnsname_match_10)
{
	fail_unless(
		!ssl_dnsname_match(wildcard4, sizeof(wildcard4) - 1,
		                   name7, sizeof(name7) - 1),
		"Partial label wildcard matches");
}
END_TEST

START_TEST(ssl_dnsname_match_11)
{
	fail_unless(
		!ssl_dnsname_match(wildcard5, sizeof(wildcard5) - 1,
		                   name1, sizeof(name1) - 1),
		"Global wildcard * matches fqdn");
}
END_TEST

START_TEST(ssl_dnsname_match_12)
{
	fail_unless(
		ssl_dnsname_match(wildcard5, sizeof(wildcard5) - 1,
		                  name8, sizeof(name8) - 1),
		"Global wildcard * does not match TLD");
}
END_TEST

START_TEST(ssl_dnsname_match_13)
{
	fail_unless(
		ssl_dnsname_match(wildcard6, sizeof(wildcard6) - 1,
		                  name9, sizeof(name9) - 1),
		"IDN wildcard does not match");
}
END_TEST

START_TEST(ssl_dnsname_match_14)
{
	fail_unless(
		ssl_dnsname_match(wildcard6, sizeof(wildcard6) - 1,
		                  name10, sizeof(name10) - 1),
		"IDN wildcard does not match IDN element");
}
END_TEST

START_TEST(ssl_dnsname_match_15)
{
	fail_unless(
		!ssl_dnsname_match(wildcard7, sizeof(wildcard7) - 1,
		                   name10, sizeof(name10) - 1),
		"Illegal IDN wildcard matches");
}
END_TEST

START_TEST(ssl_dnsname_match_16)
{
	fail_unless(
		!ssl_dnsname_match(wildcard8, sizeof(wildcard8) - 1,
		                   name10, sizeof(name10) - 1),
		"Illegal IDN wildcard matches IDN element");
}
END_TEST

#ifndef OPENSSL_NO_TLSEXT
static unsigned char clienthello01[] =
	"\x80\x67\x01\x03\x00\x00\x4e\x00\x00\x00\x10\x01\x00\x80\x03\x00"
	"\x80\x07\x00\xc0\x06\x00\x40\x02\x00\x80\x04\x00\x80\x00\x00\x39"
	"\x00\x00\x38\x00\x00\x35\x00\x00\x33\x00\x00\x32\x00\x00\x04\x00"
	"\x00\x05\x00\x00\x2f\x00\x00\x16\x00\x00\x13\x00\xfe\xff\x00\x00"
	"\x0a\x00\x00\x15\x00\x00\x12\x00\xfe\xfe\x00\x00\x09\x00\x00\x64"
	"\x00\x00\x62\x00\x00\x03\x00\x00\x06\xa8\xb8\x93\xbb\x90\xe9\x2a"
	"\xa2\x4d\x6d\xcc\x1c\xe7\x2a\x80\x21";
	/* SSL 2.0, no TLS extensions */

static unsigned char clienthello02[] =
	"\x16\x03\x00\x00\x73\x01\x00\x00\x6f\x03\x00\x00\x34\x01\x1e\x67"
	"\x3a\xfa\xce\xd9\x51\xba\xe4\xfc\x64\x95\x03\x82\x63\x0f\xe3\x39"
	"\x6b\xc7\xbd\x2b\xe5\x51\x37\x23\x48\x5b\xfb\x20\xa3\xca\xad\x46"
	"\x95\x5d\x64\xbb\x33\xec\xb5\x12\x91\x21\xa3\x50\xd2\xc0\xc5\xf6"
	"\x67\xc3\xcc\x9e\xc0\x4a\x71\x1b\x92\xdc\x58\x55\x00\x28\x00\x39"
	"\x00\x38\x00\x35\x00\x33\x00\x32\x00\x04\x00\x05\x00\x2f\x00\x16"
	"\x00\x13\xfe\xff\x00\x0a\x00\x15\x00\x12\xfe\xfe\x00\x09\x00\x64"
	"\x00\x62\x00\x03\x00\x06\x01\x00";
	/* SSL 3.0, no TLS extensions */

static unsigned char clienthello03[] =
	"\x16\x03\x01\x00\x9b\x01\x00\x00\x97\x03\x01\x4b\x99\x46\xac\x38"
	"\x08\xbb\xa7\x1c\x9b\xea\x79\xc5\xd6\x70\x3d\xed\x20\x80\x60\xb4"
	"\x7e\xb5\x07\x13\xcf\x9a\x1c\xec\x6f\x64\xe5\x00\x00\x46\xc0\x0a"
	"\xc0\x09\xc0\x07\xc0\x08\xc0\x13\xc0\x14\xc0\x11\xc0\x12\xc0\x04"
	"\xc0\x05\xc0\x02\xc0\x03\xc0\x0e\xc0\x0f\xc0\x0c\xc0\x0d\x00\x2f"
	"\x00\x05\x00\x04\x00\x35\x00\x0a\x00\x09\x00\x03\x00\x08\x00\x06"
	"\x00\x32\x00\x33\x00\x38\x00\x39\x00\x16\x00\x15\x00\x14\x00\x13"
	"\x00\x12\x00\x11\x01\x00\x00\x28\x00\x00\x00\x12\x00\x10\x00\x00"
	"\x0d\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x30\x30\x2e\x34\x00\x0a"
	"\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00";
	/* TLS 1.0, SNI extension with hostname "192.168.100.4";
	 * Note: IP addresses are not legal values */

static unsigned char clienthello04[] =
	"\x16\x03\x01\x00\x6c\x01\x00\x00\x68\x03\x01\x4a\x9d\x49\x75\xb2"
	"\x7e\xf9\xbc\xc3\x76\xac\x19\x78\xfb\x6a\xee\x50\x55\x5e\x35\x4c"
	"\xca\xf2\x21\x15\xf3\x8a\x2a\xfc\xb5\x35\xed\x00\x00\x28\x00\x39"
	"\x00\x38\x00\x35\x00\x16\x00\x13\x00\x0a\x00\x33\x00\x32\x00\x2f"
	"\x00\x07\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11"
	"\x00\x08\x00\x06\x00\x03\x01\x00\x00\x17\x00\x00\x00\x0f\x00\x0d"
	"\x00\x00\x0a\x6b\x61\x6d\x65\x73\x68\x2e\x63\x6f\x6d\x00\x23\x00"
	"\x00";
	/* TLS 1.0, SNI extension with hostname "kamesh.com" */

static unsigned char clienthello05[] =
	"\x16\x03\x03\x01\x7d\x01\x00\x01\x79\x03\x03\x4f\x7f\x27\xd0\x76"
	"\x5f\xc1\x3b\xba\x73\xd5\x07\x8b\xd9\x79\xf9\x51\xd4\xce\x7d\x9a"
	"\xdb\xdf\xf8\x4e\x95\x86\x38\x61\xdd\x84\x2a\x00\x00\xca\xc0\x30"
	"\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\xa3"
	"\x00\x9f\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x19"
	"\xc0\x20\x00\xa7\x00\x6d\x00\x3a\x00\x89\xc0\x32\xc0\x2e\xc0\x2a"
	"\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d\x00\x35\x00\x84\xc0\x12"
	"\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x17\xc0\x1a\x00\x1b"
	"\xc0\x0d\xc0\x03\x00\x0a\xc0\x2f\xc0\x2b\xc0\x27\xc0\x23\xc0\x13"
	"\xc0\x09\xc0\x1f\xc0\x1e\x00\xa2\x00\x9e\x00\x67\x00\x40\x00\x33"
	"\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x18\xc0\x1d\x00\xa6"
	"\x00\x6c\x00\x34\x00\x9b\x00\x46\xc0\x31\xc0\x2d\xc0\x29\xc0\x25"
	"\xc0\x0e\xc0\x04\x00\x9c\x00\x3c\x00\x2f\x00\x96\x00\x41\x00\x07"
	"\xc0\x11\xc0\x07\xc0\x16\x00\x18\xc0\x0c\xc0\x02\x00\x05\x00\x04"
	"\x00\x15\x00\x12\x00\x1a\x00\x09\x00\x14\x00\x11\x00\x19\x00\x08"
	"\x00\x06\x00\x17\x00\x03\x00\xff\x02\x01\x00\x00\x85\x00\x00\x00"
	"\x12\x00\x10\x00\x00\x0d\x64\x61\x6e\x69\x65\x6c\x2e\x72\x6f\x65"
	"\x2e\x63\x68\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00"
	"\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00"
	"\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00"
	"\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00"
	"\x10\x00\x11\x00\x23\x00\x00\x00\x0d\x00\x22\x00\x20\x06\x01\x06"
	"\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03"
	"\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01\x00\x0f\x00"
	"\x01\x01";
	/* TLS 1.2, SNI extension with hostname "daniel.roe.ch" */

START_TEST(ssl_tls_clienthello_parse_sni_01)
{
	ssize_t sz;
	char *sni;

	sz = sizeof(clienthello01) - 1;
	sni = ssl_tls_clienthello_parse_sni(clienthello01, &sz);
	fail_unless(sni == NULL, "sni not null but should be");
	fail_unless(sz != -1, "size is -1 but should not");
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_02)
{
	ssize_t sz;
	char *sni;

	sz = sizeof(clienthello02) - 1;
	sni = ssl_tls_clienthello_parse_sni(clienthello02, &sz);
	fail_unless(sni == NULL, "sni not null but should be");
	fail_unless(sz != -1, "size is -1 but should not");
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_03)
{
	ssize_t sz;
	char *sni;

	sz = sizeof(clienthello03) - 1;
	sni = ssl_tls_clienthello_parse_sni(clienthello03, &sz);
	fail_unless(sni && !strcmp(sni, "192.168.100.4"),
	            "sni not '192.168.100.4' but should be");
	fail_unless(sz != -1, "size is -1 but should not");
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_04)
{
	ssize_t sz;
	char *sni;

	sz = sizeof(clienthello04) - 1;
	sni = ssl_tls_clienthello_parse_sni(clienthello04, &sz);
	fail_unless(sni && !strcmp(sni, "kamesh.com"),
	            "sni not 'kamesh.com' but should be");
	fail_unless(sz != -1, "size is -1 but should not");
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_05)
{
	for (size_t i = 0; i < sizeof(clienthello04) - 1; i++) {
		ssize_t sz;
		char *sni;

		sz = (ssize_t)i;
		sni = ssl_tls_clienthello_parse_sni(clienthello04, &sz);
		fail_unless(sni == NULL, "sni not null but should be");
		fail_unless(sz == -1, "size is not -1 but should be");
	}
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_06)
{
	ssize_t sz;
	char *sni;

	sz = sizeof(clienthello05) - 1;
	sni = ssl_tls_clienthello_parse_sni(clienthello05, &sz);
	fail_unless(sni && !strcmp(sni, "daniel.roe.ch"),
	            "sni not 'daniel.roe.ch' but should be");
	fail_unless(sz != -1, "size is -1 but should not");
}
END_TEST

START_TEST(ssl_tls_clienthello_parse_sni_07)
{
	for (size_t i = 0; i < sizeof(clienthello05) - 1; i++) {
		ssize_t sz;
		char *sni;

		sz = (ssize_t)i;
		sni = ssl_tls_clienthello_parse_sni(clienthello05, &sz);
		fail_unless(sni == NULL, "sni not null but should be");
		fail_unless(sz == -1, "size is not -1 but should be");
	}
}
END_TEST
#endif /* !OPENSSL_NO_TLSEXT */

START_TEST(ssl_x509_names_01)
{
	X509 *c;
	char **names, **p;

	c = ssl_x509_load(TESTCERT);
	fail_unless(!!c, "loading certificate failed");
	names = ssl_x509_names(c);
	fail_unless(!!names, "parsing names failed");
	fail_unless(!!names[0], "first name");
	fail_unless(!strcmp(names[0], "daniel.roe.ch"), "first name");
	fail_unless(!!names[1], "second name");
	fail_unless(!strcmp(names[1], "daniel.roe.ch"), "second name");
	fail_unless(!!names[2], "third name");
	fail_unless(!strcmp(names[2], "www.roe.ch"), "third name");
	fail_unless(!!names[3], "fourth name");
	fail_unless(!strcmp(names[3], "*.roe.ch"), "fourth name");
	fail_unless(!names[4], "too many names");
	p = names;
	while (*p)
		free(*p++);
	free(names);
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_names_to_str_01)
{
	X509 *c;
	char *names;

	c = ssl_x509_load(TESTCERT);
	fail_unless(!!c, "loading certificate failed");
	names = ssl_x509_names_to_str(c);
	fail_unless(!!names, "no string");
	fail_unless(!strcmp(names,
	            "daniel.roe.ch/daniel.roe.ch/www.roe.ch/*.roe.ch"),
	            "wrong name string");
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_names_to_str_02)
{
	X509 *c;
	char *names;

	c = ssl_x509_load(TESTCERT2);
	fail_unless(!!c, "loading certificate failed");
	names = ssl_x509_names_to_str(c);
	fail_unless(!!names, "no string");
	fail_unless(!strcmp(names, "SSLsplit Root CA"), "wrong name string");
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_subject_01)
{
	X509 *c;
	char *subject;

	c = ssl_x509_load(TESTCERT);
	fail_unless(!!c, "loading certificate failed");
	subject = ssl_x509_subject(c);
	fail_unless(!!subject, "no string");
	fail_unless(!strcmp(subject, "/C=CH/O=SSLsplit Test Certificate/"
	                             "CN=daniel.roe.ch"),
	            "wrong subject string");
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_subject_cn_01)
{
	X509 *c;
	char *cn;
	size_t sz;
	size_t expsz = strlen("daniel.roe.ch") + 1;

	c = ssl_x509_load(TESTCERT);
	fail_unless(!!c, "loading certificate failed");
	cn = ssl_x509_subject_cn(c, &sz);
	fail_unless(!!cn, "no string");
	fail_unless(sz >= expsz, "subject CN size too small");
	fail_unless(!strcmp(cn, "daniel.roe.ch"), "wrong subject CN string");
#if 0
	for (unsigned int i = expsz; i < sz; i++) {
		fail_unless(cn[i] == '\0', "extra byte != 0");
	}
#endif
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_ocsps_01)
{
	X509 *c;
	char **ocsps, **p;

	c = ssl_x509_load(TESTCERT);
	fail_unless(!!c, "loading certificate failed");
	ocsps = ssl_x509_ocsps(c);
	fail_unless(!!ocsps, "parsing OCSP extensions failed");
	fail_unless(!!ocsps[0], "first OCSP");
	fail_unless(!strcmp(ocsps[0], "http://daniel.roe.ch/test/ocsp"),
	                              "first OCSP");
	fail_unless(!ocsps[1], "too many OCSPs");
	p = ocsps;
	while (*p)
		free(*p++);
	free(ocsps);
	X509_free(c);
}
END_TEST

START_TEST(ssl_x509_ocsps_02)
{
	X509 *c;
	char **ocsps;

	c = ssl_x509_load(TESTCERT2);
	fail_unless(!!c, "loading certificate failed");
	ocsps = ssl_x509_ocsps(c);
	fail_unless(!ocsps, "unexpected OCSP extensions");
	X509_free(c);
}
END_TEST

static char ocspreq01[] =
	"MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIB"
	"ewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE=";

START_TEST(ssl_is_ocspreq_01)
{
	unsigned char *buf;
	size_t sz;

	buf = base64_dec(ocspreq01, sizeof(ocspreq01) - 1, &sz);
	fail_unless(!!buf, "failed to base64 decode");
	fail_unless(ssl_is_ocspreq(buf, sz), "is not ocsp req");
}
END_TEST

START_TEST(ssl_features_01)
{
	int have_threads = 0;
#ifdef OPENSSL_THREADS
	have_threads = 1;
#endif /* OPENSSL_THREADS */
	fail_unless(have_threads, "!OPENSSL_THREADS: no threading support");
}
END_TEST

Suite *
ssl_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("ssl");

	tc = tcase_create("ssl_wildcardify");
	tcase_add_test(tc, ssl_wildcardify_01);
	tcase_add_test(tc, ssl_wildcardify_02);
	tcase_add_test(tc, ssl_wildcardify_03);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_dnsname_match");
	tcase_add_test(tc, ssl_dnsname_match_01);
	tcase_add_test(tc, ssl_dnsname_match_02);
	tcase_add_test(tc, ssl_dnsname_match_03);
	tcase_add_test(tc, ssl_dnsname_match_04);
	tcase_add_test(tc, ssl_dnsname_match_05);
	tcase_add_test(tc, ssl_dnsname_match_06);
	tcase_add_test(tc, ssl_dnsname_match_07);
	tcase_add_test(tc, ssl_dnsname_match_08);
	tcase_add_test(tc, ssl_dnsname_match_09);
	tcase_add_test(tc, ssl_dnsname_match_10);
	tcase_add_test(tc, ssl_dnsname_match_11);
	tcase_add_test(tc, ssl_dnsname_match_12);
	tcase_add_test(tc, ssl_dnsname_match_13);
	tcase_add_test(tc, ssl_dnsname_match_14);
	tcase_add_test(tc, ssl_dnsname_match_15);
	tcase_add_test(tc, ssl_dnsname_match_16);
	suite_add_tcase(s, tc);

#ifndef OPENSSL_NO_TLSEXT
	tc = tcase_create("ssl_tls_clienthello_parse_sni");
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_01);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_02);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_03);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_04);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_05);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_06);
	tcase_add_test(tc, ssl_tls_clienthello_parse_sni_07);
	suite_add_tcase(s, tc);
#endif /* !OPENSSL_NO_TLSEXT */

	tc = tcase_create("ssl_x509_names");
	tcase_add_checked_fixture(tc, ssl_setup, ssl_teardown);
	tcase_add_test(tc, ssl_x509_names_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_x509_names_to_str");
	tcase_add_checked_fixture(tc, ssl_setup, ssl_teardown);
	tcase_add_test(tc, ssl_x509_names_to_str_01);
	tcase_add_test(tc, ssl_x509_names_to_str_02);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_x509_subject");
	tcase_add_checked_fixture(tc, ssl_setup, ssl_teardown);
	tcase_add_test(tc, ssl_x509_subject_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_x509_subject_cn");
	tcase_add_checked_fixture(tc, ssl_setup, ssl_teardown);
	tcase_add_test(tc, ssl_x509_subject_cn_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_x509_ocsps");
	tcase_add_checked_fixture(tc, ssl_setup, ssl_teardown);
	tcase_add_test(tc, ssl_x509_ocsps_01);
	tcase_add_test(tc, ssl_x509_ocsps_02);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_is_ocspreq");
	tcase_add_test(tc, ssl_is_ocspreq_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("ssl_features");
	tcase_add_test(tc, ssl_features_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
