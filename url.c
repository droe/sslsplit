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

#include <stdlib.h>
#include <string.h>

/*
 * URL encoding functions.
 */

/*
 * URL decode insz bytes from in.
 * Returns allocated buffer containing outsz bytes plus a '\0' terminator.
 * If in does not contain valid URL encoded data, returns NULL.
 */
char *
url_dec(const char *in, size_t insz, size_t *outsz)
{
	static const int hex2dec[] = {
		-1, -1, -1, -1, -1, -1, -1, -1,   /*   0 ..   7 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*   8 ..  15 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  16 ..  23 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  24 ..  31 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  32 ..  39 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  40 ..  47 */
		 0,  1,  2,  3,  4,  5,  6,  7,   /*  48  .. 55 */
		 8,  9, -1, -1, -1, -1, -1, -1,   /*  56 ..  63 */
		-1, 10, 11, 12, 13, 14, 15, -1,   /*  64 ..  71 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  72 ..  79 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  80 ..  87 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  88 ..  95 */
		-1, 10, 11, 12, 13, 14, 15, -1,   /*  96 .. 103 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 104 .. 111 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 112 .. 119 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 120 .. 127 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 128 .. 135 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 136 .. 143 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 144 .. 151 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 152 .. 159 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 160 .. 167 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 168 .. 175 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 176 .. 183 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 184 .. 191 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 192 .. 199 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 200 .. 207 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 208 .. 215 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 216 .. 223 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 224 .. 231 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 232 .. 239 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /* 240 .. 247 */
		-1, -1, -1, -1, -1, -1, -1, -1 }; /* 248 .. 255 */
	size_t i, o;
	int hi, lo;
	char *out;

	if (insz == 0) {
		*outsz = 0;
		return strdup("");
	}

	for (i = 0, o = 0; i < insz; i++)
		if (in[i] == '%')
			o++;
	if (2 * o > insz) {
		*outsz = 0;
		return NULL;
	}
	*outsz = insz - (2 * o);

	if (!(out = malloc((*outsz) + 1))) {
		*outsz = 0;
		return NULL;
	}

	for (i = 0, o = 0; i < insz; i++, o++) {
		if (in[i] != '%') {
			out[o] = in[i];
			continue;
		}
		if (i + 2 >= insz)
			goto leave;
		if ((hi = hex2dec[(unsigned char)in[i + 1]]) == -1)
			goto leave;
		if ((lo = hex2dec[(unsigned char)in[i + 2]]) == -1)
			goto leave;
		out[o] = ((hi & 0xF) << 4) | (lo & 0xF);
		i += 2;
	}
	out[*outsz] = '\0';
	return out;

leave:
	free(out);
	return NULL;
}

/* vim: set noet ft=c: */
