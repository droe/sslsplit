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

#ifndef CACHEMGR_H
#define CACHEMGR_H

#include "cache.h"
#include "cachefkcrt.h"
#include "cachetgcrt.h"
#include "cachessess.h"
#include "cachedsess.h"

extern cache_t *cachemgr_fkcrt;
extern cache_t *cachemgr_tgcrt;
extern cache_t *cachemgr_ssess;
extern cache_t *cachemgr_dsess;

int cachemgr_preinit(void) WUNRES;
int cachemgr_init(void) WUNRES;
void cachemgr_fini(void);
void cachemgr_gc(void);

#define cachemgr_fkcrt_get(key) \
        cache_get(cachemgr_fkcrt, cachefkcrt_mkkey(key))
#define cachemgr_fkcrt_set(key, val) \
        cache_set(cachemgr_fkcrt, cachefkcrt_mkkey(key), cachefkcrt_mkval(val))
#define cachemgr_fkcrt_del(key) \
        cache_del(cachemgr_fkcrt, cachefkcrt_mkkey(key))

#define cachemgr_tgcrt_get(key) \
        cache_get(cachemgr_tgcrt, cachetgcrt_mkkey(key))
#define cachemgr_tgcrt_set(key, val) \
        cache_set(cachemgr_tgcrt, cachetgcrt_mkkey(key), cachetgcrt_mkval(val))
#define cachemgr_tgcrt_del(key) \
        cache_del(cachemgr_tgcrt, cachetgcrt_mkkey(key))

#define cachemgr_ssess_get(key, keysz) \
        cache_get(cachemgr_ssess, cachessess_mkkey((key), (keysz)))
#define cachemgr_ssess_set(val) \
        cache_set(cachemgr_ssess, \
                  cachessess_mkkey((val)->session_id, \
                                   (val)->session_id_length), \
                  cachessess_mkval(val))
#define cachemgr_ssess_del(val) \
        cache_del(cachemgr_ssess, \
                  cachessess_mkkey((val)->session_id, \
                                   (val)->session_id_length))

#define cachemgr_dsess_get(addr, addrlen, sni) \
        cache_get(cachemgr_dsess, cachedsess_mkkey((addr), (addrlen), (sni)))
#define cachemgr_dsess_set(addr, addrlen, sni, val) \
        cache_set(cachemgr_dsess, cachedsess_mkkey((addr), (addrlen), (sni)), \
                                  cachedsess_mkval(val))
#define cachemgr_dsess_del(addr, addrlen, sni) \
        cache_del(cachemgr_dsess, cachedsess_mkkey((addr), (addrlen), (sni)))

#endif /* !CACHEMGR_H */

/* vim: set noet ft=c: */
