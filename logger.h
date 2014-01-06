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

#ifndef LOGGER_H
#define LOGGER_H

#include "logbuf.h"
#include "attrib.h"

#include <unistd.h>
#include <pthread.h>

typedef ssize_t (*logger_write_func_t)(int, const void *, size_t);
typedef struct logger logger_t;

logger_t * logger_new(logger_write_func_t) NONNULL(1) MALLOC;
void logger_free(logger_t *) NONNULL(1);
int logger_start(logger_t *) NONNULL(1);
void logger_leave(logger_t *) NONNULL(1);
int logger_join(logger_t *) NONNULL(1);
int logger_stop(logger_t *) NONNULL(1);
int logger_submit(logger_t *, logbuf_t *) NONNULL(1);
int logger_printf(logger_t *, int, const char *, ...) PRINTF(3,4) NONNULL(1,3);
int logger_print(logger_t *, int, const char *) NONNULL(1);
int logger_write(logger_t *, int, const void *, size_t) NONNULL(1);
int logger_print_freebuf(logger_t *, int, char *) NONNULL(1);
int logger_write_freebuf(logger_t *, int, void *, size_t) NONNULL(1);

#endif /* !LOGGER_H */

/* vim: set noet ft=c: */
