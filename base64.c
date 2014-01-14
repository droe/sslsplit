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
 * Base64 encoding functions.
 */

/*
 * Base64 decode insz bytes from in.
 * Returns allocated buffer containing outsz bytes.
 * The buffer is null-terminated, but the terminator is not included in outsz.
 * If in does not contain valid Base64 encoded data, returns NULL.
 * This is a very strict implementation.  Any characters not within the
 * Base64 alphabet are considered invalid, including newline and whitespace.
 */
unsigned char *
base64_dec(const char *in, size_t insz, size_t *outsz)
{
	static const int revalphabet[] = {
		-1, -1, -1, -1, -1, -1, -1, -1,   /*   0 ..   7 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*   8 ..  15 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  16 ..  23 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  24 ..  31 */
		-1, -1, -1, -1, -1, -1, -1, -1,   /*  32 ..  39 */
		-1, -1, -1, 62, -1, -1, -1, 63,   /*  40 ..  47 */
		52, 53, 54, 55, 56, 57, 58, 59,   /*  48  .. 55 */
		60, 61, -1, -1, -1, -1, -1, -1,   /*  56 ..  63 */
		-1,  0,  1,  2,  3,  4,  5,  6,   /*  64 ..  71 */
		 7,  8,  9, 10, 11, 12, 13, 14,   /*  72 ..  79 */
		15, 16, 17, 18, 19, 20, 21, 22,   /*  80 ..  87 */
		23, 24, 25, -1, -1, -1, -1, -1,   /*  88 ..  95 */
		-1, 26, 27, 28, 29, 30, 31, 32,   /*  96 .. 103 */
		33, 34, 35, 36, 37, 38, 39, 40,   /* 104 .. 111 */
		41, 42, 43, 44, 45, 46, 47, 48,   /* 112 .. 119 */
		49, 50, 51, -1, -1, -1, -1, -1,   /* 120 .. 127 */
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
	int tmp, digit;
	unsigned char *out;

	if (insz % 4)
		return NULL;

	if (insz == 0) {
		*outsz = 0;
		return (unsigned char *)strdup("");
	}

	if (in[insz - 2] == '=')
		*outsz = ((insz / 4) * 3) - 2;
	else if (in[insz - 1] == '=')
		*outsz = ((insz / 4) * 3) - 1;
	else
		*outsz = (insz / 4) * 3;
	if (!(out = malloc((*outsz) + 1))) {
		*outsz = 0;
		return NULL;
	}

	for (i = 0, o = 0; i < insz; i += 4, o += 3) {
		if ((digit = revalphabet[(unsigned char)in[i    ]]) == -1)
			goto leave;
		tmp  = digit << 18;
		if ((digit = revalphabet[(unsigned char)in[i + 1]]) == -1)
			goto leave;
		tmp += digit << 12;
		if ((digit = revalphabet[(unsigned char)in[i + 2]]) == -1) {
			if ((i == insz - 4) && (in[i + 2] == '='))
				digit = 0;
			else
				goto leave;
		}
		tmp += digit <<  6;
		if ((digit = revalphabet[(unsigned char)in[i + 3]]) == -1) {
			if ((i == insz - 4) && (in[i + 3] == '='))
				digit = 0;
			else
				goto leave;
		}
		tmp += digit;
			out[o    ] = (tmp >> 16) & 0xff;
		if (o + 1 < *outsz)
			out[o + 1] = (tmp >>  8) & 0xff;
		if (o + 2 < *outsz)
			out[o + 2] =  tmp        & 0xff;
	}
	out[*outsz] = '\0';
	return out;

leave:
	free(out);
	return NULL;
}

/*
 * Base64 encode insz bytes from in.
 * Returns allocated buffer containing outsz bytes.
 * The buffer is null-terminated, but the terminator is not included in outsz.
 */
char *
base64_enc(const unsigned char *in, size_t insz, size_t *outsz)
{
	static const int alphabet[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/' };
	size_t i, o;
	char *out;

	if (insz == 0) {
		*outsz = 0;
		return strdup("");
	}

	*outsz = ((insz + 2) / 3) * 4;
	if (!(out = malloc((*outsz) + 1))) {
		*outsz = 0;
		return NULL;
	}

	for (i = 0, o = 0; i < insz; i += 3, o += 4) {
		int tmp;
			tmp  = in[i    ] << 16;
		if (i + 1 < insz)
			tmp += in[i + 1] <<  8;
		if (i + 2 < insz)
			tmp += in[i + 2];
		out[o    ] = alphabet[(tmp >> 18) & 0x3f];
		out[o + 1] = alphabet[(tmp >> 12) & 0x3f];
		out[o + 2] = alphabet[(tmp >>  6) & 0x3f];
		out[o + 3] = alphabet[ tmp        & 0x3f];
		if (i + 2 > insz)
			out[o + 2] = '=';
		if (i + 3 > insz)
			out[o + 3] = '=';
	}
	out[*outsz] = '\0';
	return out;
}

/* vim: set noet ft=c: */
