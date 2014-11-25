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

#ifndef PROC_H
#define PROC_H

#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/util.h>

#if defined(HAVE_DARWIN_LIBPROC) || defined(__FreeBSD__)
#define HAVE_LOCAL_PROCINFO
#endif

#ifdef HAVE_DARWIN_LIBPROC
#ifndef LOCAL_PROCINFO_STR
#define LOCAL_PROCINFO_STR "Darwin libproc"
#define proc_pid_for_addr(a,b,c)	proc_darwin_pid_for_addr(a,b,c)
#define proc_get_info(a,b,c,d)		proc_darwin_get_info(a,b,c,d)
#endif /* LOCAL_PROCINFO_STR */
int proc_darwin_pid_for_addr(pid_t *, struct sockaddr *, socklen_t) WUNRES NONNULL(1,2);
int proc_darwin_get_info(pid_t, char **, uid_t *, gid_t *) WUNRES NONNULL(2,3,4);
#endif /* HAVE_DARWIN_LIBPROC */

#ifdef __FreeBSD__
#ifndef LOCAL_PROCINFO_STR
#define LOCAL_PROCINFO_STR "FreeBSD sysctl"
#define proc_pid_for_addr(a,b,c)	proc_freebsd_pid_for_addr(a,b,c)
#define proc_get_info(a,b,c,d)		proc_freebsd_get_info(a,b,c,d)
#endif /* LOCAL_PROCINFO_STR */
int proc_freebsd_pid_for_addr(pid_t *, struct sockaddr *, socklen_t) WUNRES NONNULL(1,2);
int proc_freebsd_get_info(pid_t, char **, uid_t *, gid_t *) WUNRES NONNULL(2,3,4);
#endif /* __FreeBSD__ */

#endif /* !PROC_H */

/* vim: set noet ft=c: */
