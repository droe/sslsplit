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

/*
 * LD_PRELOAD library overlay to print calls to NSS CERT_PKIXVerifyCert() and
 * their error code.  This function is used by Chrome and other browsers using
 * NSS to verify server certificates.  This overlay is intended to help finding
 * the root cause for certificate verification failures in Chrome, that are
 * mapped to Chrome error codes in MapSecurityError():
 * https://chromium.googlesource.com/chromium/src/+/master/net/cert/cert_verify_proc_nss.cc
 *
 * Usage on Linux:
 * gcc -shared -fPIC -o snoop-nss-verify.so snoop-nss-verify.c -ldl
 * LD_PRELOAD=./snoop-nss-verify.so /usr/bin/google-chrome
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

#define CERTCertificate void
#define SECCertificateUsage int64_t
#define CERTValInParam  void
#define CERTValOutParam void
#define SECStatus int /* actually enum */

SECStatus
CERT_PKIXVerifyCert(CERTCertificate *cert,
                    SECCertificateUsage usages,
                    CERTValInParam *paramsIn,
                    CERTValOutParam *paramsOut,
                    void *wincx)
{
	typeof(CERT_PKIXVerifyCert) *original;
	SECStatus rv;

	original = dlsym(RTLD_NEXT, "CERT_PKIXVerifyCert");
	rv = original(cert, usages, paramsIn, paramsOut, wincx);
	fprintf(stderr,
	        "CERT_PKIXVerifyCert(%p, %"PRId64", %p, %p, %p) => %i\n",
	        cert, usages, paramsIn, paramsOut, wincx, rv);
	return rv;
}

