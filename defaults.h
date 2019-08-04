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

#ifndef DEFAULTS_H
#define DEFAULTS_H

/*
 * Defaults for convenient tweaking or patching.
 */

/*
 * User to drop privileges to by default.  This user needs to be allowed to
 * create outbound TCP connections, and in some configurations, perform DNS
 * resolution.
 *
 * Packagers may want to use a specific service user account instead of
 * overloading nobody with yet another use case.  Using nobody for source
 * builds makes sense because chances are high that it exists.  Good practice
 * is to create a dedicated user for sslsplit.
 *
 * Make sure to also patch the manual page if you patch this.
 */
#define DFLT_DROPUSER "nobody"

/*
 * Default file and directory modes for newly created files and directories
 * created as part of e.g. logging.  The default is to use full permissions
 * subject to the system's umask, as is the default for system utilities.
 * Use a more restrictive mode for the PID file.
 */
#define DFLT_DIRMODE  0777
#define DFLT_FILEMODE 0666
#define DFLT_PIDFMODE 0644

/*
 * Default cipher suite spec.
 * Use 'openssl ciphers -v spec' to see what ciphers are effectively enabled
 * by a cipher suite spec with a given version of OpenSSL.
 */
#define DFLT_CIPHERS "ALL:-aNULL"

/*
 * Default elliptic curve for EC cipher suites.
 */
#define DFLT_CURVE "prime256v1"

/*
 * Default leaf key RSA keysize in bits.
 *
 * While implementations still generally accepted leaf keys of 1024 bits in
 * size, we used 1024 for leaf keys.  As implementations are starting to sunset
 * 1024 bit RSA not only for CA keys, but also for leaf keys, we now use a 2048
 * bit key size for the leaf cert key in order to maximize interoperability in
 * default config.
 *
 * Users who want a different size, for example 1024 bit RSA for performance,
 * can always use their own pre-generated leaf key using the -K option instead
 * of generating one automatically.
 *
 * Refer to the following resources on key sizes accepted by different
 * implementations.  Note that OpenSSL security level restrictions potentially
 * apply to both sslsplit and all of the clients and servers using OpenSSL.
 *
 * OpenSSL:
 * https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_get_security_level.html
 * https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_get_security_level.html
 */
#define DFLT_LEAFKEY_RSABITS 2048

#endif /* !DEFAULTS_H */

/* vim: set noet ft=c: */
