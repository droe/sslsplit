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

#include "opts.h"

#include "sys.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif /* !OPENSSL_NO_DH */
#include <openssl/x509.h>

opts_t *
opts_new(void)
{
	opts_t *opts;

	opts = malloc(sizeof(opts_t));
	memset(opts, 0, sizeof(opts_t));

	opts->sslcomp = 1;
	opts->chain = sk_X509_new_null();

	return opts;
}

void
opts_free(opts_t *opts)
{
	sk_X509_pop_free(opts->chain, X509_free);
	if (opts->cacrt) {
		X509_free(opts->cacrt);
	}
	if (opts->cakey) {
		EVP_PKEY_free(opts->cakey);
	}
	if (opts->key) {
		EVP_PKEY_free(opts->key);
	}
#ifndef OPENSSL_NO_DH
	if (opts->dh) {
		DH_free(opts->dh);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (opts->ecdhcurve) {
		free(opts->ecdhcurve);
	}
#endif /* !OPENSSL_NO_ECDH */
	if (opts->spec) {
		proxyspec_free(opts->spec);
	}
	if (opts->ciphers) {
		free(opts->ciphers);
	}
	if (opts->tgcrtdir) {
		free(opts->tgcrtdir);
	}
	if (opts->dropuser) {
		free(opts->dropuser);
	}
	if (opts->jaildir) {
		free(opts->jaildir);
	}
	if (opts->pidfile) {
		free(opts->pidfile);
	}
	if (opts->connectlog) {
		free(opts->connectlog);
	}
	if (opts->contentlog) {
		free(opts->contentlog);
	}
	memset(opts, 0, sizeof(opts_t));
	free(opts);
}

/*
 * Return 1 if opts_t contains a proxyspec with ssl, 0 otherwise.
 */
int
opts_has_ssl_spec(opts_t *opts)
{
	proxyspec_t *p = opts->spec;

	while (p) {
		if (p->ssl)
			return 1;
		p = p->next;
	}

	return 0;
}

/*
 * Parse proxyspecs using a simple state machine.
 * Returns NULL if parsing failed.
 */
proxyspec_t *
proxyspec_parse(int *argc, char **argv[], const char *natengine)
{
	proxyspec_t *curspec, *spec = NULL;
	char *addr;
	int af;
	int state = 0;

	while ((*argc)--) {
		switch (state) {
			default:
			case 0:
				/* tcp | ssl | http | https */
				curspec = malloc(sizeof(proxyspec_t));
				memset(curspec, 0, sizeof(proxyspec_t));
				curspec->next = spec;
				spec = curspec;
				if (!strcmp(**argv, "tcp")) {
					spec->ssl = 0;
					spec->http = 0;
				} else
				if (!strcmp(**argv, "ssl")) {
					spec->ssl = 1;
					spec->http = 0;
				} else
				if (!strcmp(**argv, "http")) {
					spec->ssl = 0;
					spec->http = 1;
				} else
				if (!strcmp(**argv, "https")) {
					spec->ssl = 1;
					spec->http = 1;
				} else {
					fprintf(stderr, "Unknown connection "
					                "type '%s'\n", **argv);
					exit(EXIT_FAILURE);
				}
				state++;
				break;
			case 1:
				/* listenaddr */
				addr = **argv;
				state++;
				break;
			case 2:
				/* listenport */
				if (strstr(addr, ":"))
					af = AF_INET6;
				else if (!strpbrk(addr, "abcdefghijklmnopqrstu"
				                        "vwxyzABCDEFGHIJKLMNOP"
				                        "QRSTUVWXYZ-"))
					af = AF_INET;
				else
					af = AF_UNSPEC;
				af = sys_sockaddr_parse(&spec->listen_addr,
				                        &spec->listen_addrlen,
				                        addr, **argv, af,
				                        EVUTIL_AI_PASSIVE);
				if (af == -1) {
					exit(EXIT_FAILURE);
				}
				spec->natengine = strdup(natengine);
				state++;
				break;
			case 3:
				/* [ natengine | dstaddr ] */
				if (!strcmp(**argv, "tcp") ||
				    !strcmp(**argv, "ssl") ||
				    !strcmp(**argv, "http") ||
				    !strcmp(**argv, "https")) {
					/* implicit default natengine */
					(*argv)--; (*argc)++; /* rewind */
					state = 0;
				} else
				if (!strcmp(**argv, "sni")) {
					free(spec->natengine);
					spec->natengine = NULL;
					if (!spec->ssl) {
						fprintf(stderr,
						        "SNI hostname lookup "
						        "only works for ssl "
						        "and https proxyspecs"
						        "\n");
						exit(EXIT_FAILURE);
					}
					state = 5;
				} else
				if (nat_exist(**argv)) {
					/* natengine */
					free(spec->natengine);
					spec->natengine = strdup(**argv);
					state = 0;
				} else {
					/* explicit target address */
					free(spec->natengine);
					spec->natengine = NULL;
					addr = **argv;
					state++;
				}
				break;
			case 4:
				/* dstport */
				af = sys_sockaddr_parse(&spec->connect_addr,
				                        &spec->connect_addrlen,
				                        addr, **argv, af, 0);
				if (af == -1) {
					exit(EXIT_FAILURE);
				}
				state = 0;
				break;
			case 5:
				/* SNI dstport */
				spec->sni_port = atoi(**argv);
				if (!spec->sni_port) {
					fprintf(stderr, "Invalid port '%s'\n",
					                **argv);
					exit(EXIT_FAILURE);
				}
				state = 0;
				break;
		}
		(*argv)++;
	}
	if (state != 0 && state != 3) {
		fprintf(stderr, "Incomplete proxyspec!\n");
		exit(EXIT_FAILURE);
	}

	return spec;
}

/*
 * Clear and free a proxy spec.
 */
void
proxyspec_free(proxyspec_t *spec)
{
	while (spec) {
		proxyspec_t *next = spec->next;
		if (spec->natengine)
			free(spec->natengine);
		memset(spec, 0, sizeof(proxyspec_t));
		free(spec);
		spec = next;
	}
}

/* vim: set noet ft=c: */
