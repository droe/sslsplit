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

#include "pxythrmgr.h"

#include <string.h>

#include <check.h>

START_TEST(pxythrmgr_libevent_01)
{
	struct event_base *evbase;

	evbase = event_base_new();
	fail_unless(!!evbase, "no event base");
	event_base_free(evbase);
}
END_TEST

START_TEST(pxythrmgr_libevent_02)
{
	struct event_base *evbase;
	struct evdns_base *dnsbase;

	evbase = event_base_new();
	fail_unless(!!evbase, "no event base");
	dnsbase = evdns_base_new(evbase, 0);
	fail_unless(!!dnsbase, "no evdns base");
	evdns_base_free(dnsbase, 0);
	event_base_free(evbase);
}
END_TEST

START_TEST(pxythrmgr_libevent_03)
{
	struct event_base *evbase;
	struct evdns_base *dnsbase;
	int rc;

	evbase = event_base_new();
	fail_unless(!!evbase, "no event base");
	dnsbase = evdns_base_new(evbase, 0);
	fail_unless(!!dnsbase, "no evdns base");
	rc = evdns_base_resolv_conf_parse(dnsbase, DNS_OPTIONS_ALL,
	                                  "/etc/resolv.conf");
	fail_unless(rc == 0, "unable to parse resolv.conf");
	evdns_base_free(dnsbase, 0);
	event_base_free(evbase);
}
END_TEST

START_TEST(pxythrmgr_libevent_04)
{
	struct event_base *evbase;
	struct evdns_base *dnsbase;

	evbase = event_base_new();
	fail_unless(!!evbase, "no event base");
	dnsbase = evdns_base_new(evbase, 1);
	fail_unless(!!dnsbase, "no evdns base");
	evdns_base_free(dnsbase, 0);
	event_base_free(evbase);
}
END_TEST

START_TEST(pxythrmgr_libevent_05)
{
	struct event_base *evbase1;
	struct event_base *evbase2;
	struct evdns_base *dnsbase;

	/* issue #17:  */
	evbase1 = event_base_new();
	fail_unless(!!evbase1, "no event base 1");
	evbase2 = event_base_new();
	fail_unless(!!evbase1, "no event base 2");
	dnsbase = evdns_base_new(evbase2, 1);
	fail_unless(!!dnsbase, "no evdns base");
	evdns_base_free(dnsbase, 0);
	event_base_free(evbase2);
	event_base_free(evbase1);
}
END_TEST

Suite *
pxythrmgr_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("pxythrmgr");

	tc = tcase_create("pxythrmgr_libevent");
	tcase_add_test(tc, pxythrmgr_libevent_01);
	tcase_add_test(tc, pxythrmgr_libevent_02);
	tcase_add_test(tc, pxythrmgr_libevent_03);
	tcase_add_test(tc, pxythrmgr_libevent_04);
	tcase_add_test(tc, pxythrmgr_libevent_05);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
