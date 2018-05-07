/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "opts.h"

#include "sys.h"
#include "log.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif /* !OPENSSL_NO_DH */
#include <openssl/x509.h>

/*
 * Handle out of memory conditions in early stages of main().
 * Print error message and exit with failure status code.
 * Does not return.
 */
void NORET
oom_die(const char *argv0)
{
	fprintf(stderr, "%s: out of memory\n", argv0);
	exit(EXIT_FAILURE);
}

opts_t *
opts_new(void)
{
	opts_t *opts;

	opts = malloc(sizeof(opts_t));
	memset(opts, 0, sizeof(opts_t));

	opts->sslcomp = 1;
	opts->chain = sk_X509_new_null();
	opts->sslmethod = SSLv23_method;

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
	if (opts->crlurl) {
		free(opts->crlurl);
	}
	if (opts->dropuser) {
		free(opts->dropuser);
	}
	if (opts->dropgroup) {
		free(opts->dropgroup);
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
	if (opts->certgendir) {
		free(opts->certgendir);
	}
	if (opts->contentlog_basedir) {
		free(opts->contentlog_basedir);
	}
	if (opts->masterkeylog) {
		free(opts->masterkeylog);
	}
	memset(opts, 0, sizeof(opts_t));
	free(opts);
}

/*
 * Return 1 if opts_t contains a proxyspec that (eventually) uses SSL/TLS,
 * 0 otherwise.  When 0, it is safe to assume that no SSL/TLS operations
 * will take place with this configuration.
 */
int
opts_has_ssl_spec(opts_t *opts)
{
	proxyspec_t *p = opts->spec;

	while (p) {
		if (p->ssl || p->upgrade)
			return 1;
		p = p->next;
	}

	return 0;
}

/*
 * Return 1 if opts_t contains a proxyspec with dns, 0 otherwise.
 */
int
opts_has_dns_spec(opts_t *opts)
{
	proxyspec_t *p = opts->spec;

	while (p) {
		if (p->dns)
			return 1;
		p = p->next;
	}

	return 0;
}

/*
 * Dump the SSL/TLS protocol related configuration to the debug log.
 */
void
opts_proto_dbg_dump(opts_t *opts)
{
	log_dbg_printf("SSL/TLS protocol: %s%s%s%s%s%s\n",
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef HAVE_SSLV2
	               (opts->sslmethod == SSLv2_method) ? "ssl2" :
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	               (opts->sslmethod == SSLv3_method) ? "ssl3" :
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	               (opts->sslmethod == TLSv1_method) ? "tls10" :
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	               (opts->sslmethod == TLSv1_1_method) ? "tls11" :
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	               (opts->sslmethod == TLSv1_2_method) ? "tls12" :
#endif /* HAVE_TLSV12 */
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
#ifdef HAVE_SSLV3
	               (opts->sslversion == SSL3_VERSION) ? "ssl3" :
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	               (opts->sslversion == TLS1_VERSION) ? "tls10" :
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	               (opts->sslversion == TLS1_1_VERSION) ? "tls11" :
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	               (opts->sslversion == TLS1_2_VERSION) ? "tls12" :
#endif /* HAVE_TLSV12 */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	               "negotiate",
#ifdef HAVE_SSLV2
	               opts->no_ssl2 ? " -ssl2" :
#endif /* HAVE_SSLV2 */
	               "",
#ifdef HAVE_SSLV3
	               opts->no_ssl3 ? " -ssl3" :
#endif /* HAVE_SSLV3 */
	               "",
#ifdef HAVE_TLSV10
	               opts->no_tls10 ? " -tls10" :
#endif /* HAVE_TLSV10 */
	               "",
#ifdef HAVE_TLSV11
	               opts->no_tls11 ? " -tls11" :
#endif /* HAVE_TLSV11 */
	               "",
#ifdef HAVE_TLSV12
	               opts->no_tls12 ? " -tls12" :
#endif /* HAVE_TLSV12 */
	               "");
}


/*
 * Parse proxyspecs using a simple state machine.
 */
void
proxyspec_parse(int *argc, char **argv[], const char *natengine, opts_t *opts)
{
	proxyspec_t *spec = NULL;
	char *addr = NULL;
	int af = AF_UNSPEC;
	int state = 0;

	while ((*argc)--) {
		switch (state) {
			default:
			case 0:
				/* tcp | ssl | http | https | autossl */
				spec = malloc(sizeof(proxyspec_t));
				memset(spec, 0, sizeof(proxyspec_t));
				spec->next = opts->spec;
				opts->spec = spec;

				// Defaults
				spec->ssl = 0;
				spec->http = 0;
				spec->upgrade = 0;
				if (!strcmp(**argv, "tcp")) {
					// use defaults
				} else
				if (!strcmp(**argv, "ssl")) {
					spec->ssl = 1;
				} else
				if (!strcmp(**argv, "http")) {
					spec->http = 1;
				} else
				if (!strcmp(**argv, "https")) {
					spec->ssl = 1;
					spec->http = 1;
				} else
				if (!strcmp(**argv, "autossl")) {
					spec->upgrade = 1;
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
				if (natengine) {
					spec->natengine = strdup(natengine);
					if (!spec->natengine) {
						fprintf(stderr,
						        "Out of memory"
						        "\n");
						exit(EXIT_FAILURE);
					}
				} else {
					spec->natengine = NULL;
				}
				state++;
				break;
			case 3:
				/* [ natengine | dstaddr ] */
				if (!strcmp(**argv, "tcp") ||
				    !strcmp(**argv, "ssl") ||
				    !strcmp(**argv, "http") ||
				    !strcmp(**argv, "https") ||
				    !strcmp(**argv, "autossl")) {
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
					if (!spec->natengine) {
						fprintf(stderr,
						        "Out of memory"
						        "\n");
						exit(EXIT_FAILURE);
					}
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
				spec->dns = 1;
				state = 0;
				break;
		}
		(*argv)++;
	}
	if (state != 0 && state != 3) {
		fprintf(stderr, "Incomplete proxyspec!\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Clear and free a proxy spec.
 */
void
proxyspec_free(proxyspec_t *spec)
{
	do {
		proxyspec_t *next = spec->next;
		if (spec->natengine)
			free(spec->natengine);
		memset(spec, 0, sizeof(proxyspec_t));
		free(spec);
		spec = next;
	} while (spec);
}

/*
 * Return text representation of proxy spec for display to the user.
 * Returned string must be freed by caller.
 */
char *
proxyspec_str(proxyspec_t *spec)
{
	char *s;
	char *lhbuf, *lpbuf;
	char *cbuf = NULL;
	if (sys_sockaddr_str((struct sockaddr *)&spec->listen_addr,
	                     spec->listen_addrlen, &lhbuf, &lpbuf) != 0) {
		return NULL;
	}
	if (spec->connect_addrlen) {
		char *chbuf, *cpbuf;
		if (sys_sockaddr_str((struct sockaddr *)&spec->connect_addr,
		                     spec->connect_addrlen,
		                     &chbuf, &cpbuf) != 0) {
			return NULL;
		}
		if (asprintf(&cbuf, "[%s]:%s", chbuf, cpbuf) < 0) {
			return NULL;
		}
		free(chbuf);
		free(cpbuf);
	}
	if (spec->sni_port) {
		if (asprintf(&cbuf, "sni %i", spec->sni_port) < 0) {
			return NULL;
		}
	}
	if (asprintf(&s, "[%s]:%s %s%s%s %s", lhbuf, lpbuf,
	             (spec->ssl ? "ssl" : "tcp"),
	             (spec->upgrade ? "|upgrade" : ""),
	             (spec->http ? "|http" : ""),
	             (spec->natengine ? spec->natengine : cbuf)) < 0) {
		s = NULL;
	}
	free(lhbuf);
	free(lpbuf);
	if (cbuf)
		free(cbuf);
	return s;
}

void
opts_set_cacrt(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->cacrt)
		X509_free(opts->cacrt);
	opts->cacrt = ssl_x509_load(optarg);
	if (!opts->cacrt) {
		fprintf(stderr, "%s: error loading CA "
						"cert from '%s':\n",
						argv0, optarg);
		if (errno) {
			fprintf(stderr, "%s\n",
					strerror(errno));
		} else {
			ERR_print_errors_fp(stderr);
		}
		exit(EXIT_FAILURE);
	}
	ssl_x509_refcount_inc(opts->cacrt);
	sk_X509_insert(opts->chain, opts->cacrt, 0);
	if (!opts->cakey) {
		opts->cakey = ssl_key_load(optarg);
	}
#ifndef OPENSSL_NO_DH
	if (!opts->dh) {
		opts->dh = ssl_dh_load(optarg);
	}
#endif /* !OPENSSL_NO_DH */
	fprintf(stderr, "CACrt: %s\n", optarg);
}

void
opts_set_cakey(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->cakey)
		EVP_PKEY_free(opts->cakey);
	opts->cakey = ssl_key_load(optarg);
	if (!opts->cakey) {
		fprintf(stderr, "%s: error loading CA "
						"key from '%s':\n",
						argv0, optarg);
		if (errno) {
			fprintf(stderr, "%s\n",
					strerror(errno));
		} else {
			ERR_print_errors_fp(stderr);
		}
		exit(EXIT_FAILURE);
	}
	if (!opts->cacrt) {
		opts->cacrt = ssl_x509_load(optarg);
		if (opts->cacrt) {
			ssl_x509_refcount_inc(
						   opts->cacrt);
			sk_X509_insert(opts->chain,
						   opts->cacrt, 0);
		}
	}
#ifndef OPENSSL_NO_DH
	if (!opts->dh) {
		opts->dh = ssl_dh_load(optarg);
	}
#endif /* !OPENSSL_NO_DH */
	fprintf(stderr, "CAKey: %s\n", optarg);
}

void
opts_set_chain(opts_t *opts, const char *argv0, const char *optarg)
{
	if (ssl_x509chain_load(NULL, &opts->chain,
						   optarg) == -1) {
		fprintf(stderr, "%s: error loading "
						"chain from '%s':\n",
						argv0, optarg);
		if (errno) {
			fprintf(stderr, "%s\n",
					strerror(errno));
		} else {
			ERR_print_errors_fp(stderr);
		}
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "CAChain: %s\n", optarg);
}

void
opts_set_key(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->key)
		EVP_PKEY_free(opts->key);
	opts->key = ssl_key_load(optarg);
	if (!opts->key) {
		fprintf(stderr, "%s: error loading lea"
						"f key from '%s':\n",
						argv0, optarg);
		if (errno) {
			fprintf(stderr, "%s\n",
					strerror(errno));
		} else {
			ERR_print_errors_fp(stderr);
		}
		exit(EXIT_FAILURE);
	}
#ifndef OPENSSL_NO_DH
	if (!opts->dh) {
		opts->dh = ssl_dh_load(optarg);
	}
#endif /* !OPENSSL_NO_DH */
	fprintf(stderr, "LeafCerts: %s\n", optarg);
}

void
opts_set_crl(opts_t *opts, const char *optarg)
{
	if (opts->crlurl)
		free(opts->crlurl);
	opts->crlurl = strdup(optarg);
	fprintf(stderr, "CRL: %s\n", opts->crlurl);
}

void
opts_set_tgcrtdir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isdir(optarg)) {
		fprintf(stderr, "%s: '%s' is not a "
						"directory\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->tgcrtdir)
		free(opts->tgcrtdir);
	opts->tgcrtdir = strdup(optarg);
	if (!opts->tgcrtdir)
		oom_die(argv0);
	fprintf(stderr, "TargetCertDir: %s\n", opts->tgcrtdir);
}

static void
set_certgendir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->certgendir)
		free(opts->certgendir);
	opts->certgendir = strdup(optarg);
	if (!opts->certgendir)
		oom_die(argv0);
}

void
opts_set_certgendir_writegencerts(opts_t *opts, const char *argv0, const char *optarg)
{
	opts->certgen_writeall = 0;
	set_certgendir(opts, argv0, optarg);
	fprintf(stderr, "WriteGenCertsDir: certgendir=%s, writeall=%u\n", opts->certgendir, opts->certgen_writeall);
}

void
opts_set_certgendir_writeall(opts_t *opts, const char *argv0, const char *optarg)
{
	opts->certgen_writeall = 1;
	set_certgendir(opts, argv0, optarg);
	fprintf(stderr, "WriteAllCertsDir: certgendir=%s, writeall=%u\n", opts->certgendir, opts->certgen_writeall);
}

void
opts_set_deny_ocsp(opts_t *opts)
{
	opts->deny_ocsp = 1;
}

void
opts_unset_deny_ocsp(opts_t *opts)
{
	opts->deny_ocsp = 0;
}

void
opts_set_passthrough(opts_t *opts)
{
	opts->passthrough = 1;
}

void
opts_unset_passthrough(opts_t *opts)
{
	opts->passthrough = 0;
}

#ifndef OPENSSL_NO_DH
void
opts_set_dh(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->dh)
		DH_free(opts->dh);
	opts->dh = ssl_dh_load(optarg);
	if (!opts->dh) {
		fprintf(stderr, "%s: error loading DH "
						"params from '%s':\n",
						argv0, optarg);
		if (errno) {
			fprintf(stderr, "%s\n",
					strerror(errno));
		} else {
			ERR_print_errors_fp(stderr);
		}
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "DHGroupParams: %s\n", optarg);
}
#endif /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_ECDH
void
opts_set_ecdhcurve(opts_t *opts, const char *argv0, const char *optarg)
{
	EC_KEY *ec;
	if (opts->ecdhcurve)
		free(opts->ecdhcurve);
	if (!(ec = ssl_ec_by_name(optarg))) {
		fprintf(stderr, "%s: unknown curve "
						"'%s'\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	EC_KEY_free(ec);
	opts->ecdhcurve = strdup(optarg);
	if (!opts->ecdhcurve)
		oom_die(argv0);
	fprintf(stderr, "ECDHCurve: %s\n", opts->ecdhcurve);
}
#endif /* !OPENSSL_NO_ECDH */

void
opts_set_sslcomp(opts_t *opts)
{
	opts->sslcomp = 1;
}

void
opts_unset_sslcomp(opts_t *opts)
{
	opts->sslcomp = 0;
}

void
opts_set_ciphers(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->ciphers)
		free(opts->ciphers);
	opts->ciphers = strdup(optarg);
	if (!opts->ciphers)
		oom_die(argv0);
	fprintf(stderr, "Ciphers: %s\n", opts->ciphers);
}

/*
 * Parse SSL proto string in optarg and look up the corresponding SSL method.
 * Calls exit() on failure.
 */
void
opts_proto_force(opts_t *opts, const char *optarg, const char *argv0)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (opts->sslmethod != SSLv23_method) {
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	if (opts->sslversion) {
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
		fprintf(stderr, "%s: cannot use -r multiple times\n", argv0);
		exit(EXIT_FAILURE);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef HAVE_SSLV2
	if (!strcmp(optarg, "ssl2")) {
		opts->sslmethod = SSLv2_method;
	} else
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	if (!strcmp(optarg, "ssl3")) {
		opts->sslmethod = SSLv3_method;
	} else
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (!strcmp(optarg, "tls10") || !strcmp(optarg, "tls1")) {
		opts->sslmethod = TLSv1_method;
	} else
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (!strcmp(optarg, "tls11")) {
		opts->sslmethod = TLSv1_1_method;
	} else
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (!strcmp(optarg, "tls12")) {
		opts->sslmethod = TLSv1_2_method;
	} else
#endif /* HAVE_TLSV12 */
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
/*
 * Support for SSLv2 and the corresponding SSLv2_method(),
 * SSLv2_server_method() and SSLv2_client_method() functions were
 * removed in OpenSSL 1.1.0.
 */
#ifdef HAVE_SSLV3
	if (!strcmp(optarg, "ssl3")) {
		opts->sslversion = SSL3_VERSION;
	} else
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (!strcmp(optarg, "tls10") || !strcmp(optarg, "tls1")) {
		opts->sslversion = TLS1_VERSION;
	} else
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (!strcmp(optarg, "tls11")) {
		opts->sslversion = TLS1_1_VERSION;
	} else
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (!strcmp(optarg, "tls12")) {
		opts->sslversion = TLS1_2_VERSION;
	} else
#endif /* HAVE_TLSV12 */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	{
		fprintf(stderr, "%s: Unsupported SSL/TLS protocol '%s'\n",
		                argv0, optarg);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "ForceSSLProto: %s\n", optarg);
}

/*
 * Parse SSL proto string in optarg and set the corresponding no_foo bit.
 * Calls exit() on failure.
 */
void
opts_proto_disable(opts_t *opts, const char *optarg, const char *argv0)
{
#ifdef HAVE_SSLV2
	if (!strcmp(optarg, "ssl2")) {
		opts->no_ssl2 = 1;
	} else
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	if (!strcmp(optarg, "ssl3")) {
		opts->no_ssl3 = 1;
	} else
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (!strcmp(optarg, "tls10") || !strcmp(optarg, "tls1")) {
		opts->no_tls10 = 1;
	} else
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (!strcmp(optarg, "tls11")) {
		opts->no_tls11 = 1;
	} else
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (!strcmp(optarg, "tls12")) {
		opts->no_tls12 = 1;
	} else
#endif /* HAVE_TLSV12 */
	{
		fprintf(stderr, "%s: Unsupported SSL/TLS protocol '%s'\n",
		                argv0, optarg);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "DisableSSLProto: %s\n", optarg);
}

void
opts_set_user(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isuser(optarg)) {
		fprintf(stderr, "%s: '%s' is not an "
						"existing user\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->dropuser)
		free(opts->dropuser);
	opts->dropuser = strdup(optarg);
	if (!opts->dropuser)
		oom_die(argv0);
	fprintf(stderr, "User: %s\n", opts->dropuser);
}

void
opts_set_group(opts_t *opts, const char *argv0, const char *optarg)
{

	if (!sys_isgroup(optarg)) {
		fprintf(stderr, "%s: '%s' is not an "
						"existing group\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->dropgroup)
		free(opts->dropgroup);
	opts->dropgroup = strdup(optarg);
	if (!opts->dropgroup)
		oom_die(argv0);
	fprintf(stderr, "Group: %s\n", opts->dropgroup);
}

void
opts_set_jaildir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isdir(optarg)) {
		fprintf(stderr, "%s: '%s' is not a "
						"directory\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->jaildir)
		free(opts->jaildir);
	opts->jaildir = realpath(optarg, NULL);
	if (!opts->jaildir) {
		fprintf(stderr, "%s: Failed to "
						"canonicalize '%s': "
						"%s (%i)\n",
						argv0, optarg,
						strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Chroot: %s\n", opts->jaildir);
}

void
opts_set_pidfile(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->pidfile)
		free(opts->pidfile);
	opts->pidfile = strdup(optarg);
	if (!opts->pidfile)
		oom_die(argv0);
	fprintf(stderr, "PidFile: %s\n", opts->pidfile);
}

void
opts_set_connectlog(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->connectlog)
		free(opts->connectlog);
	opts->connectlog = strdup(optarg);
	if (!opts->connectlog)
		oom_die(argv0);
	fprintf(stderr, "ConnectLog: %s\n", opts->connectlog);
}

void
opts_set_contentlog(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->contentlog)
		free(opts->contentlog);
	opts->contentlog = strdup(optarg);
	if (!opts->contentlog)
		oom_die(argv0);
	opts->contentlog_isdir = 0;
	opts->contentlog_isspec = 0;
	fprintf(stderr, "ContentLog: %s\n", opts->contentlog);
}

void
opts_set_contentlogdir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isdir(optarg)) {
		fprintf(stderr, "%s: '%s' is not a "
						"directory\n",
						argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->contentlog)
		free(opts->contentlog);
	opts->contentlog = realpath(optarg, NULL);
	if (!opts->contentlog) {
		fprintf(stderr, "%s: Failed to "
						"canonicalize '%s': "
						"%s (%i)\n",
						argv0, optarg,
						strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	opts->contentlog_isdir = 1;
	opts->contentlog_isspec = 0;
	fprintf(stderr, "ContentLogDir: %s\n", opts->contentlog);
}

void
opts_set_contentlogpathspec(opts_t *opts, const char *argv0, const char *optarg)
{
	char *lhs, *rhs, *p, *q;
	size_t n;
	if (opts->contentlog_basedir)
		free(opts->contentlog_basedir);
	if (opts->contentlog)
		free(opts->contentlog);
	if (log_content_split_pathspec(optarg, &lhs,
								   &rhs) == -1) {
		fprintf(stderr, "%s: Failed to split "
						"'%s' in lhs/rhs: "
						"%s (%i)\n",
						argv0, optarg,
						strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	/* eliminate %% from lhs */
	for (p = q = lhs; *p; p++, q++) {
		if (q < p)
			*q = *p;
		if (*p == '%' && *(p+1) == '%')
			p++;
	}
	*q = '\0';
	/* all %% in lhs resolved to % */
	if (sys_mkpath(lhs, 0777) == -1) {
		fprintf(stderr, "%s: Failed to create "
						"'%s': %s (%i)\n",
						argv0, lhs,
						strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	opts->contentlog_basedir = realpath(lhs, NULL);
	if (!opts->contentlog_basedir) {
		fprintf(stderr, "%s: Failed to "
						"canonicalize '%s': "
						"%s (%i)\n",
						argv0, lhs,
						strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	/* count '%' in opts->contentlog_basedir */
	for (n = 0, p = opts->contentlog_basedir;
		 *p;
		 p++) {
		if (*p == '%')
			n++;
	}
	free(lhs);
	n += strlen(opts->contentlog_basedir);
	if (!(lhs = malloc(n + 1)))
		oom_die(argv0);
	/* re-encoding % to %%, copying basedir to lhs */
	for (p = opts->contentlog_basedir, q = lhs;
		 *p;
		 p++, q++) {
		*q = *p;
		if (*q == '%')
			*(++q) = '%';
	}
	*q = '\0';
	/* lhs contains encoded realpathed basedir */
	if (asprintf(&opts->contentlog,
				 "%s/%s", lhs, rhs) < 0)
		oom_die(argv0);
	opts->contentlog_isdir = 0;
	opts->contentlog_isspec = 1;
	free(lhs);
	free(rhs);
	fprintf(stderr, "ContentLogPathSpec: basedir=%s, %s\n", opts->contentlog_basedir, opts->contentlog);
}

#ifdef HAVE_LOCAL_PROCINFO
void
opts_set_lprocinfo(opts_t *opts)
{
	opts->lprocinfo = 1;
}

void
opts_unset_lprocinfo(opts_t *opts)
{
	opts->lprocinfo = 0;
}
#endif /* HAVE_LOCAL_PROCINFO */

void
opts_set_masterkeylog(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->masterkeylog)
		free(opts->masterkeylog);
	opts->masterkeylog = strdup(optarg);
	if (!opts->masterkeylog)
		oom_die(argv0);
	fprintf(stderr, "MasterKeyLog: %s\n", opts->masterkeylog);
}

void
opts_set_daemon(opts_t *opts)
{
	opts->detach = 1;
}

void
opts_unset_daemon(opts_t *opts)
{
	opts->detach = 0;
}

void
opts_set_debug(opts_t *opts)
{
	log_dbg_mode(LOG_DBG_MODE_ERRLOG);
	opts->debug = 1;
}

void
opts_unset_debug(opts_t *opts)
{
	log_dbg_mode(LOG_DBG_MODE_NONE);
	opts->debug = 0;
}

static int
check_value_yesno(char *value, char *name, int line_num)
{
	// Compare strlen(s2)+1 chars to match exactly
	if (!strncmp(value, "yes", 4)) {
		return 1;
	} else if (!strncmp(value, "no", 3)) {
		return 0;
	}
	fprintf(stderr, "Invalid %s %s at line %d, use yes|no\n", name, value, line_num);
	return -1;
}

int
load_conffile(opts_t *opts, const char *argv0, const char *prev_natengine)
{
	FILE *f;
	int rv, line_num, yes;
	size_t line_len;
	char *n, *value, *v, *value_end;
	char *line, *name;
	char natengine[NATENGINE_SIZE];
	
	strncpy(natengine, prev_natengine, NATENGINE_SIZE);

	f = fopen(opts->conffile, "r");
	if (!f) {
		fprintf(stderr, "Error opening conf file %s: %s\n", opts->conffile, strerror(errno));
		return -1;
	}

	line = NULL;
	line_num = 0;
	while (!feof(f)) {
		rv = getline(&line, &line_len, f);
		if (rv == -1) {
			break;
		}
		if (line == NULL) {
			fprintf(stderr, "getline() buf=NULL");
			return -1;
		}
		line_num++;

		// skip white space
		for (name = line; *name == ' ' || *name == '\t'; name++); 

		// skip comments and empty lines
		if ((name[0] == '\0') || (name[0] == '#') || (name[0] == ';') ||
			(name[0] == '\r') || (name[0] == '\n')) {
			continue;
		}

		// skip to the end of option name and terminate it with '\0'
		for (n = name;; n++) {
			if (*n == ' ' || *n == '\t') {
				*n = '\0';
				n++;
				break;
			}
			if (*n == '\0') {
				n = NULL;
				break;
			}
		}

		// no value
		if (n == NULL) {
			fprintf(stderr, "Conf error at line %d\n", line_num);
			fclose(f);
			if (line) {
				free(line);
			}
			return -1;
		}
		
		// skip white space before value
		while (*n == ' ' || *n == '\t') {
			n++;
		}

		value = n;

		// find end of value and terminate it with '\0'
		// find first occurrence of trailing white space
		value_end = NULL;
		for (v = value;; v++) {
			if (*v == '\0') {
				break;
			}
			if (*v == '\r' || *v == '\n') {
				*v = '\0';
				break;
			}
			if (*v == ' ' || *v == '\t') {
				if (!value_end) {
					value_end = v;
				}
			} else {
				value_end = NULL;
			}
		}

		if (value_end) {
			*value_end = '\0';
		}

		// Compare strlen(s2)+1 chars to match exactly
		if (!strncmp(name, "CACert", 7)) {
			opts_set_cacrt(opts, argv0, value);
		} else if (!strncmp(name, "CAKey", 6)) {
			opts_set_cakey(opts, argv0, value);
		} else if (!strncmp(name, "CAChain", 8)) {
			opts_set_chain(opts, argv0, value);
		} else if (!strncmp(name, "LeafCerts", 10)) {
			opts_set_key(opts, argv0, value);
		} else if (!strncmp(name, "CRL", 4)) {
			opts_set_crl(opts, value);
		} else if (!strncmp(name, "TargetCertDir", 14)) {
			opts_set_tgcrtdir(opts, argv0, value);
		} else if (!strncmp(name, "WriteGenCertsDir", 17)) {
			opts_set_certgendir_writegencerts(opts, argv0, value);
		} else if (!strncmp(name, "WriteAllCertsDir", 17)) {
			opts_set_certgendir_writeall(opts, argv0, value);
		} else if (!strncmp(name, "DenyOCSP", 9)) {
			yes = check_value_yesno(value, "DenyOCSP", line_num);
			if (yes >= 0) {
				yes ? opts_set_deny_ocsp(opts) : opts_unset_deny_ocsp(opts);
			}
			fprintf(stderr, "DenyOCSP: %u\n", opts->deny_ocsp);
		} else if (!strncmp(name, "Passthrough", 12)) {
			yes = check_value_yesno(value, "Passthrough", line_num);
			if (yes >= 0) {
				yes ? opts_set_passthrough(opts) : opts_unset_passthrough(opts);
			}
			fprintf(stderr, "Passthrough: %u\n", opts->passthrough);
#ifndef OPENSSL_NO_DH
		} else if (!strncmp(name, "DHGroupParams", 14)) {
			opts_set_dh(opts, argv0, value);
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
		} else if (!strncmp(name, "ECDHCurve", 10)) {
			opts_set_ecdhcurve(opts, argv0, value);
#endif /* !OPENSSL_NO_ECDH */
#ifdef SSL_OP_NO_COMPRESSION
		} else if (!strncmp(name, "SSLCompression", 15)) {
			yes = check_value_yesno(value, "SSLCompression", line_num);
			if (yes >= 0) {
				yes ? opts_set_sslcomp(opts) : opts_unset_sslcomp(opts);
			}
			fprintf(stderr, "SSLCompression: %u\n", opts->sslcomp);
#endif /* SSL_OP_NO_COMPRESSION */
		} else if (!strncmp(name, "ForceSSLProto", 14)) {
			opts_proto_force(opts, value, argv0);
		} else if (!strncmp(name, "DisableSSLProto", 16)) {
			opts_proto_disable(opts, value, argv0);
		} else if (!strncmp(name, "Ciphers", 8)) {
			opts_set_ciphers(opts, argv0, value);
		} else if (!strncmp(name, "NATEngine", 10)) {
			strncpy(natengine, value, NATENGINE_SIZE);
			fprintf(stderr, "NATEngine: %s\n", natengine);
		} else if (!strncmp(name, "User", 5)) {
			opts_set_user(opts, argv0, value);
		} else if (!strncmp(name, "Group", 6)) {
			opts_set_group(opts, argv0, value);
		} else if (!strncmp(name, "Chroot", 7)) {
			opts_set_jaildir(opts, argv0, value);
		} else if (!strncmp(name, "PidFile", 8)) {
			opts_set_pidfile(opts, argv0, value);
		} else if (!strncmp(name, "ConnectLog", 11)) {
			opts_set_connectlog(opts, argv0, value);
		} else if (!strncmp(name, "ContentLog", 11)) {
			opts_set_contentlog(opts, argv0, value);
		} else if (!strncmp(name, "ContentLogDir", 14)) {
			opts_set_contentlogdir(opts, argv0, value);
		} else if (!strncmp(name, "ContentLogPathSpec", 19)) {
			opts_set_contentlogpathspec(opts, argv0, value);
#ifdef HAVE_LOCAL_PROCINFO
		} else if (!strncmp(name, "LogProcInfo", 11)) {
			yes = check_value_yesno(value, "LogProcInfo", line_num);
			if (yes >= 0) {
				yes ? opts_set_lprocinfo(opts) : opts_unset_lprocinfo(opts);
			}
			fprintf(stderr, "LogProcInfo: %u\n", opts->lprocinfo);
#endif /* HAVE_LOCAL_PROCINFO */
		} else if (!strncmp(name, "MasterKeyLog", 13)) {
			opts_set_masterkeylog(opts, argv0, value);
		} else if (!strncmp(name, "Daemon", 7)) {
			yes = check_value_yesno(value, "Daemon", line_num);
			if (yes >= 0) {
				yes ? opts_set_daemon(opts) : opts_unset_daemon(opts);
			}
			fprintf(stderr, "Daemon: %u\n", opts->detach);
		} else if (!strncmp(name, "Debug", 6)) {
			yes = check_value_yesno(value, "Debug", line_num);
			if (yes >= 0) {
				yes ? opts_set_debug(opts) : opts_unset_debug(opts);
			}
			fprintf(stderr, "Debug: %u\n", opts->debug);
		} else if (!strncmp(name, "ProxySpec", 10)) {
			char **argv = malloc(strlen(value) + 1);
			char **save_argv = argv;
			int argc = 0;
			char *p, *last = NULL;

			for ((p = strtok_r(value, " ", &last)); p; (p = strtok_r(NULL, " ", &last))) {
				// Limit max # token
				if (argc < 10) {
					argv[argc++] = p;
				}
			}
			
			proxyspec_parse(&argc, &argv, natengine, opts);
			free(save_argv);
		} else {
			fprintf(stderr, "Unknown option '%s' at %s line %d\n", name, opts->conffile, line_num);
			fclose(f);
			if (line) {
				free(line);
			}
			return -1;
		}

		continue;
	}

	fclose(f);
	if (line) {
		free(line);
	}
	return 0;
}

/* vim: set noet ft=c: */
