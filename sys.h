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

int sys_uid(const char *, uid_t *) NONNULL(1) WUNRES;
int sys_gid(const char *, gid_t *) NONNULL(1) WUNRES;
int sys_isuser(const char *) NONNULL(1) WUNRES;
int sys_isgroup(const char *) NONNULL(1) WUNRES;
int sys_isgeteuid(const char *) NONNULL(1) WUNRES;
char * sys_user_str(uid_t) MALLOC;
char * sys_group_str(gid_t) MALLOC;

int sys_get_af(const char *);
int sys_sockaddr_parse(struct sockaddr_storage *, socklen_t *,
                       char *, char *, int, int) NONNULL(1,2,3,4) WUNRES;
int sys_sockaddr_str(struct sockaddr *, socklen_t,
                     char **, char **) NONNULL(1,3,4);
char * sys_ip46str_sanitize(const char *) NONNULL(1) MALLOC;
size_t sys_get_mtu(const char *);

int sys_isdir(const char *) NONNULL(1) WUNRES;
int sys_mkpath(const char *, mode_t) NONNULL(1) WUNRES;
char * sys_realdir(const char *) NONNULL(1) MALLOC;

typedef int (*sys_dir_eachfile_cb_t)(const char *, void *) NONNULL(1) WUNRES;
int sys_dir_eachfile(const char *, sys_dir_eachfile_cb_t, void *) NONNULL(1,2) WUNRES;

uint32_t sys_get_cpu_cores(void) WUNRES;

ssize_t sys_sendmsgfd(int, void *, size_t, int) NONNULL(2) WUNRES;
ssize_t sys_recvmsgfd(int, void *, size_t, int *) NONNULL(2) WUNRES;

void sys_dump_fds(void);

uint16_t sys_rand16(void);
uint32_t sys_rand32(void);

#endif /* !SYS_H */

/* vim: set noet ft=c: */
