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

#include "logbuf.h"

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/*
 * Dynamic log buffer with zero-copy chaining, generic void * file handle
 * and ctl for status control flags.
 * Logbuf always owns the internal allocated buffer.
 */

/*
 * Create new logbuf from provided, pre-allocated buffer, set fd and next.
 * The provided buffer will be freed by logbuf_free() if non-NULL.
 */
logbuf_t *
logbuf_new(void *buf, size_t sz, void *fh, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = malloc(sizeof(logbuf_t))))
		return NULL;
	lb->buf = buf;
	lb->sz = sz;
	lb->fh = fh;
	lb->ctl = 0;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf, allocating sz bytes into the internal buffer.
 */
logbuf_t *
logbuf_new_alloc(size_t sz, void *fh, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = malloc(sizeof(logbuf_t))))
		return NULL;
	if (!(lb->buf = malloc(sz))) {
		free(lb);
		return NULL;
	}
	lb->sz = sz;
	lb->fh = fh;
	lb->ctl = 0;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf, copying buf into a newly allocated internal buffer.
 */
logbuf_t *
logbuf_new_copy(const void *buf, size_t sz, void *fh, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = malloc(sizeof(logbuf_t))))
		return NULL;
	if (!(lb->buf = malloc(sz))) {
		free(lb);
		return NULL;
	}
	memcpy(lb->buf, buf, sz);
	lb->sz = sz;
	lb->fh = fh;
	lb->ctl = 0;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf using printf, setting fh and next.
 */
logbuf_t *
logbuf_new_printf(void *fh, logbuf_t *next, const char *fmt, ...)
{
	va_list ap;
	logbuf_t *lb;

	if (!(lb = malloc(sizeof(logbuf_t))))
		return NULL;
	va_start(ap, fmt);
	lb->sz = vasprintf((char**)&lb->buf, fmt, ap);
	va_end(ap);
	if (lb->sz < 0) {
		free(lb);
		return NULL;
	}
	lb->fh = fh;
	lb->ctl = 0;
	lb->next = next;
	return lb;
}

/*
 * Calculate the total size of the logbuf and all chained buffers.
 */
ssize_t
logbuf_size(logbuf_t *lb)
{
	ssize_t sz;

	sz = lb->sz;
	if (lb->next) {
		sz += logbuf_size(lb->next);
	}
	return sz;
}

/*
 * Write content of logbuf using writefunc and free all buffers.
 * Returns -1 on errors and sets errno according to write().
 * Returns total of bytes written by 1 .. n write() calls on success.
 */
ssize_t
logbuf_write_free(logbuf_t *lb, writefunc_t writefunc)
{
	ssize_t rv1, rv2 = 0;

	rv1 = writefunc(lb->fh, lb->buf, lb->sz);
	if (lb->buf) {
		free(lb->buf);
	}
	if (lb->next) {
		if (rv1 == -1) {
			logbuf_free(lb->next);
		} else {
			lb->next->fh = lb->fh;
			rv2 = logbuf_write_free(lb->next, writefunc);
		}
	}
	free(lb);
	if (rv1 == -1 || rv2 == -1)
		return -1;
	else
		return rv1 + rv2;
}

/*
 * Free dynbuf including internal and chained buffers.
 */
void
logbuf_free(logbuf_t *lb)
{
	if (lb->buf) {
		free(lb->buf);
	}
	if (lb->next) {
		logbuf_free(lb->next);
	}
	free(lb);
}

/* vim: set noet ft=c: */
