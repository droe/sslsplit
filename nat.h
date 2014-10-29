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

#ifndef NAT_H
#define NAT_H

#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/util.h>

typedef int (*nat_lookup_cb_t)(struct sockaddr *, socklen_t *,
                               pid_t *, evutil_socket_t s,
                               struct sockaddr *, socklen_t);
typedef int (*nat_socket_cb_t)(evutil_socket_t);

int nat_exist(const char *) WUNRES;
nat_lookup_cb_t nat_getlookupcb(const char *) WUNRES;
nat_socket_cb_t nat_getsocketcb(const char *) WUNRES;
int nat_ipv6ready(const char *) WUNRES;

const char *nat_getdefaultname(void) WUNRES;
void nat_list_engines(void);
int nat_preinit(void) WUNRES;
int nat_init(void) WUNRES;
void nat_fini(void);
void nat_version(void);

#endif /* !NAT_H */

/* vim: set noet ft=c: */
