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

#ifndef SYS_H
#define SYS_H

#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

int sys_privdrop(const char *, const char *, const char *) WUNRES;

int sys_pidf_open(const char *) NONNULL(1) WUNRES;
int sys_pidf_write(int) WUNRES;
void sys_pidf_close(int, const char *) NONNULL(2);

char * sys_user_str(uid_t) MALLOC;
char * sys_group_str(gid_t) MALLOC;

int sys_sockaddr_parse(struct sockaddr_storage *, socklen_t *,
                       char *, char *, int, int) NONNULL(1,2,3,4) WUNRES;
char * sys_sockaddr_str(struct sockaddr *, socklen_t) NONNULL(1) MALLOC;

int sys_isdir(const char *) NONNULL(1) WUNRES;
int sys_mkpath(const char *, mode_t) NONNULL(1) WUNRES;

typedef void (*sys_dir_eachfile_cb_t)(const char *, void *) NONNULL(1);
int sys_dir_eachfile(const char *, sys_dir_eachfile_cb_t, void *) NONNULL(1,2);

uint32_t sys_get_cpu_cores(void) WUNRES;

#endif /* !SYS_H */

/* vim: set noet ft=c: */
