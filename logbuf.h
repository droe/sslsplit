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

#ifndef LOGBUF_H
#define LOGBUF_H

#include "attrib.h"

#include <stdlib.h>
#include <unistd.h>

typedef struct logbuf {
	unsigned char *buf;
	ssize_t sz;
	void *fh;
	unsigned long ctl;
	struct logbuf *next;
} logbuf_t;

typedef ssize_t (*writefunc_t)(void *, const void *, size_t);

logbuf_t * logbuf_new(void *, size_t, void *, logbuf_t *) MALLOC;
logbuf_t * logbuf_new_alloc(size_t, void *, logbuf_t *) MALLOC;
logbuf_t * logbuf_new_copy(const void *, size_t, void *, logbuf_t *) MALLOC;
logbuf_t * logbuf_new_printf(void *, logbuf_t *, const char *, ...)
           MALLOC PRINTF(3,4);
ssize_t logbuf_size(logbuf_t *) NONNULL(1) WUNRES;
ssize_t logbuf_write_free(logbuf_t *, writefunc_t) NONNULL(1);
void logbuf_free(logbuf_t *) NONNULL(1);

#define logbuf_ctl_clear(x) (x)->ctl = 0
#define logbuf_ctl_set(x, y) (x)->ctl |= (y)
#define logbuf_ctl_unset(x, y) (x)->ctl &= ~(y)
#define logbuf_ctl_isset(x, y) (!!((x)->ctl & (y)))

#endif /* !LOGBUF_H */

/* vim: set noet ft=c: */
