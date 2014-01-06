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

#ifndef ATTRIB_H
#define ATTRIB_H

/*
 * GCC attributes and built-ins for improved compile-time error checking
 * and performance optimization.
 *
 * All of these are fully optional and are automatically disabled on non-GCC
 * and non-LLVM/clang compilers.
 */

/*
 * Attributes.
 * These serve to improve the compiler warnings or optimizations.
 */

#if !defined(__GNUC__) && !defined(__clang__)
#define __attribute__(x) 
#endif

#define UNUSED          __attribute__((unused))
#define NORET           __attribute__((noreturn))
#define PRINTF(f,a)     __attribute__((format(printf,(f),(a))))
#define SCANF(f,a)      __attribute__((format(scanf,(f),(a))))
#define WUNRES          __attribute__((warn_unused_result))
#define MALLOC          __attribute__((malloc)) WUNRES
#define NONNULL(...)    __attribute__((nonnull(__VA_ARGS__)))
#define PURE            __attribute__((pure))


/*
 * Branch prediction macros.
 * These serve to tell the compiler which of the branches is more likely.
 */

#if !defined(__GNUC__) && !defined(__clang__)
#define likely(expr)    (expr)
#define unlikely(expr)  (expr)
#else
#define likely(expr)    __builtin_expect((expr), 1)
#define unlikely(expr)  __builtin_expect((expr), 0)
#endif

#endif /* !ATTRIB_H */

/* vim: set noet ft=c: */
