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

#include "dynbuf.h"

#include <string.h>
#include <stdio.h>

/*
 * Simple dynamic buffer, consisting of internal buffer ptr plus length.
 * Dynbuf always owns the internal allocated buffer.
 */

/*
 * Allocate new dynbuf; will allocate sz bytes of memory in ->buf.
 */
dynbuf_t *
dynbuf_new_alloc(size_t sz)
{
	dynbuf_t *db;

	if (!(db = malloc(sizeof(dynbuf_t))))
		return NULL;
	if (!(db->buf = malloc(sz))) {
		free(db);
		return NULL;
	}
	db->sz = sz;
	return db;
}

/*
 * Create new dynbuf from provided buffer, which is copied.
 */
dynbuf_t *
dynbuf_new_copy(const unsigned char *buf, const size_t sz)
{
	dynbuf_t *db;

	if (!(db = malloc(sizeof(dynbuf_t))))
		return NULL;
	if (!(db->buf = malloc(sz))) {
		free(db);
		return NULL;
	}
	memcpy(db->buf, buf, sz);
	db->sz = sz;
	return db;
}

/*
 * Create new dynbuf by loading a file into a newly allocated internal buffer.
 * The provided buffer will be freed by dynbuf_free().
 */
dynbuf_t *
dynbuf_new_file(const char *filename)
{
	dynbuf_t *db;
	FILE *f;

	if (!(db = malloc(sizeof(dynbuf_t))))
		return NULL;

	f = fopen(filename, "rb");
	if (!f) {
		free(db);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	db->sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(db->buf = malloc(db->sz))) {
		free(db);
		fclose(f);
		return NULL;
	}
	if (fread(db->buf, db->sz, 1, f) != 1) {
		free(db->buf);
		free(db);
		fclose(f);
		return NULL;
	}
	fclose(f);
	return db;
}

/*
 * Create new dynbuf from provided, pre-allocated buffer.
 * The provided buffer will be freed by dynbuf_free().
 */
dynbuf_t *
dynbuf_new(unsigned char *buf, size_t sz)
{
	dynbuf_t *db;

	if (!(db = malloc(sizeof(dynbuf_t))))
		return NULL;
	db->buf = buf;
	db->sz = sz;
	return db;
}

/*
 * Free dynbuf including internal buffer.
 */
void
dynbuf_free(dynbuf_t *db)
{
	free(db->buf);
	free(db);
}

/* vim: set noet ft=c: */
