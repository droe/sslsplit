/*
 * SSLsplit - transparent SSL/TLS interception
 * Copyright (c) 2009-2016, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
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

/* silence daemon(3) deprecation warning on Mac OS X */
#if __APPLE__
#define daemon xdaemon
#endif /* __APPLE__ */

#include "opts.h"
#include "proxy.h"
#include "privsep.h"
#include "ssl.h"
#include "nat.h"
#include "proc.h"
#include "cachemgr.h"
#include "sys.h"
#include "log.h"
#include "version.h"
#include "defaults.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

#include <event2/event.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#if __APPLE__
#undef daemon
extern int daemon(int, int);
#endif /* __APPLE__ */


/*
 * Print version information to stderr.
 */
static void
main_version(void)
{
	fprintf(stderr, "%s %s (built %s)\n", PNAME, version, build_date);
	if (strlen(version) < 5) {
		/*
		 * Note to package maintainers:  If you break the version
		 * string in your build, it will be impossible to provide
		 * proper upstream support to the users of the package,
		 * because it will be difficult or impossible to identify
		 * the exact codebase that is being used by the user
		 * reporting a bug.  The version string is provided through
		 * different means depending on whether the code is a git
		 * checkout, a tarball downloaded from GitHub or a release.
		 * See GNUmakefile for the gory details.
		 */
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
		fprintf(stderr, "WARNING: Something is wrong with the "
		                "version compiled into sslsplit!\n");
		fprintf(stderr, "The version should contain a release "
		                "number and/or a git commit reference.\n");
		fprintf(stderr, "If using a package, please report a bug "
		                "to the distro package maintainer.\n");
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
	}
	fprintf(stderr, "Copyright (c) 2009-2016, "
	                "Daniel Roethlisberger <daniel@roe.ch>\n");
	fprintf(stderr, "http://www.roe.ch/SSLsplit\n");
	if (build_info[0]) {
		fprintf(stderr, "Build info: %s\n", build_info);
	}
	if (features[0]) {
		fprintf(stderr, "Features: %s\n", features);
	}
	nat_version();
	fprintf(stderr, "Local process info support: ");
#ifdef HAVE_LOCAL_PROCINFO
	fprintf(stderr, "yes (" LOCAL_PROCINFO_STR ")\n");
#else /* !HAVE_LOCAL_PROCINFO */
	fprintf(stderr, "no\n");
#endif /* !HAVE_LOCAL_PROCINFO */
	ssl_openssl_version();
	fprintf(stderr, "compiled against libevent %s\n", LIBEVENT_VERSION);
	fprintf(stderr, "rtlinked against libevent %s\n", event_get_version());
	fprintf(stderr, "%d CPU cores detected\n", sys_get_cpu_cores());
}

/*
 * Print usage to stderr.
 */
static void
main_usage(void)
{
	const char *dflt, *warn;

	if (!(dflt = nat_getdefaultname())) {
		dflt = "n/a";
		warn = "\nWarning: no supported NAT engine on this platform!\n"
		       "Only static and SNI proxyspecs are supported.\n";
	} else {
		warn = "";
	}

	fprintf(stderr,
"Usage: %s [options...] [proxyspecs...]\n"
"  -c pemfile  use CA cert (and key) from pemfile to sign forged certs\n"
"  -k pemfile  use CA key (and cert) from pemfile to sign forged certs\n"
"  -C pemfile  use CA chain from pemfile (intermediate and root CA certs)\n"
"  -K pemfile  use key from pemfile for leaf certs (default: generate)\n"
"  -t certdir  use cert+chain+key PEM files from certdir to target all sites\n"
"              matching the common names (non-matching: generate if CA)\n"
"  -q crlurl   use this URL as CRL distrib point for all forged certs\n"
"  -w gendir   write leaf key and only generated certificates to gendir\n"
"  -W gendir   write leaf key and all certificates to gendir\n"
"  -O          deny all OCSP requests on all proxyspecs\n"
"  -P          passthrough SSL connections if they cannot be split because of\n"
"              client cert auth or no matching cert and no CA (default: drop)\n"
#ifndef OPENSSL_NO_DH
"  -g pemfile  use DH group params from pemfile (default: keyfiles or auto)\n"
#define OPT_g "g:"
#else /* OPENSSL_NO_DH */
#define OPT_g 
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
"  -G curve    use ECDH named curve (default: " DFLT_CURVE ")\n"
#define OPT_G "G:"
#else /* OPENSSL_NO_ECDH */
#define OPT_G 
#endif /* OPENSSL_NO_ECDH */
#ifdef SSL_OP_NO_COMPRESSION
"  -Z          disable SSL/TLS compression on all connections\n"
#define OPT_Z "Z"
#else /* !SSL_OP_NO_COMPRESSION */
#define OPT_Z 
#endif /* !SSL_OP_NO_COMPRESSION */
"  -r proto    only support one of " SSL_PROTO_SUPPORT_S "(default: all)\n"
"  -R proto    disable one of " SSL_PROTO_SUPPORT_S "(default: none)\n"
"  -s ciphers  use the given OpenSSL cipher suite spec (default: " DFLT_CIPHERS ")\n"
"  -e engine   specify default NAT engine to use (default: %s)\n"
"  -E          list available NAT engines and exit\n"
"  -u user     drop privileges to user (default if run as root: " DFLT_DROPUSER ")\n"
"  -m group    when using -u, override group (default: primary group of user)\n"
"  -j jaildir  chroot() to jaildir (impacts sni proxyspecs, see manual page)\n"
"  -p pidfile  write pid to pidfile (default: no pid file)\n"
"  -l logfile  connect log: log one line summary per connection to logfile\n"
"  -L logfile  content log: full data to file or named pipe (excludes -S/-F)\n"
"  -S logdir   content log: full data to separate files in dir (excludes -L/-F)\n"
"  -F pathspec content log: full data to sep files with %% subst (excl. -L/-S):\n"
"              %%T - initial connection time as an ISO 8601 UTC timestamp\n"
"              %%d - destination host and port\n"
"              %%D - destination host\n"
"              %%p - destination port\n"
"              %%s - source host and port\n"
"              %%S - source host\n"
"              %%q - source port\n"
#ifdef HAVE_LOCAL_PROCINFO
"              %%x - base name of local process        (requires -i)\n"
"              %%X - full path to local process        (requires -i)\n"
"              %%u - user name or id of local process  (requires -i)\n"
"              %%g - group name or id of local process (requires -i)\n"
#endif /* HAVE_LOCAL_PROCINFO */
"              %%%% - literal '%%'\n"
#ifdef HAVE_LOCAL_PROCINFO
"      e.g.    \"/var/log/sslsplit/%%X/%%u-%%s-%%d-%%T.log\"\n"
"  -i          look up local process owning each connection for logging\n"
#define OPT_i "i"
#else /* !HAVE_LOCAL_PROCINFO */
"      e.g.    \"/var/log/sslsplit/%%T-%%s-%%d.log\"\n"
#define OPT_i 
#endif /* HAVE_LOCAL_PROCINFO */
"  -d          daemon mode: run in background, log error messages to syslog\n"
"  -D          debug mode: run in foreground, log debug messages on stderr\n"
"  -V          print version information and exit\n"
"  -h          print usage information and exit\n"
"  proxyspec = type listenaddr+port [natengine|targetaddr+port|\"sni\"+port]\n"
"      e.g.    http 0.0.0.0 8080 www.roe.ch 80  # http/4; static hostname dst\n"
"              https ::1 8443 2001:db8::1 443   # https/6; static address dst\n"
"              https 127.0.0.1 9443 sni 443     # https/4; SNI DNS lookups\n"
"              tcp 127.0.0.1 10025              # tcp/4; default NAT engine\n"
"              ssl 2001:db8::2 9999 pf          # ssl/6; NAT engine 'pf'\n"
"              autossl ::1 10025                # autossl/6; STARTTLS et al\n"
"Example:\n"
"  %s -k ca.key -c ca.pem -P  https 127.0.0.1 8443  https ::1 8443\n"
	"%s", BNAME, dflt, BNAME, warn);
}

/*
 * Callback to load a cert/chain/key combo from a single PEM file.
 */
static void
main_loadtgcrt(const char *filename, void *arg)
{
	opts_t *opts = arg;
	cert_t *cert;
	char **names;

	cert = cert_new_load(filename);
	if (!cert) {
		log_err_printf("Failed to load cert and key from PEM file "
		                "'%s'\n", filename);
		log_fini();
		exit(EXIT_FAILURE);
	}
	if (X509_check_private_key(cert->crt, cert->key) != 1) {
		log_err_printf("Cert does not match key in PEM file "
		                "'%s':\n", filename);
		ERR_print_errors_fp(stderr);
		log_fini();
		exit(EXIT_FAILURE);
	}

#ifdef DEBUG_CERTIFICATE
	log_dbg_printf("Loaded '%s':\n", filename);
	log_dbg_print_free(ssl_x509_to_str(cert->crt));
	log_dbg_print_free(ssl_x509_to_pem(cert->crt));
#endif /* DEBUG_CERTIFICATE */

	if (OPTS_DEBUG(opts)) {
		log_dbg_printf("Targets for '%s':", filename);
	}
	names = ssl_x509_names(cert->crt);
	for (char **p = names; *p; p++) {
		/* be deliberately vulnerable to NULL prefix attacks */
		char *sep;
		if ((sep = strchr(*p, '!'))) {
			*sep = '\0';
		}
		if (OPTS_DEBUG(opts)) {
			log_dbg_printf(" '%s'", *p);
		}
		cachemgr_tgcrt_set(*p, cert);
		free(*p);
	}
	if (OPTS_DEBUG(opts)) {
		log_dbg_printf("\n");
	}
	free(names);
	cert_free(cert);
}

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

/*
 * Main entry point.
 */
int
main(int argc, char *argv[])
{
	const char *argv0;
	int ch;
	opts_t *opts;
	char *natengine;
	int pidfd = -1;
	int rv = EXIT_FAILURE;

	argv0 = argv[0];
	opts = opts_new();
	if (nat_getdefaultname()) {
		natengine = strdup(nat_getdefaultname());
		if (!natengine)
			oom_die(argv0);
	} else {
		natengine = NULL;
	}

	while ((ch = getopt(argc, argv, OPT_g OPT_G OPT_Z OPT_i "k:c:C:K:t:"
	                    "OPs:r:R:e:Eu:m:j:p:l:L:S:F:dDVhW:w:q:")) != -1) {
		switch (ch) {
			case 'c':
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
				break;
			case 'k':
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
				break;
			case 'C':
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
				break;
			case 'K':
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
				break;
			case 't':
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
				break;
			case 'q':
				if (opts->crlurl)
					free(opts->crlurl);
				opts->crlurl = strdup(optarg);
				break;
			case 'O':
				opts->deny_ocsp = 1;
				break;
			case 'P':
				opts->passthrough = 1;
				break;
#ifndef OPENSSL_NO_DH
			case 'g':
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
				break;
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
			case 'G':
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
				break;
			}
#endif /* !OPENSSL_NO_ECDH */
#ifdef SSL_OP_NO_COMPRESSION
			case 'Z':
				opts->sslcomp = 0;
				break;
#endif /* SSL_OP_NO_COMPRESSION */
			case 's':
				if (opts->ciphers)
					free(opts->ciphers);
				opts->ciphers = strdup(optarg);
				if (!opts->ciphers)
					oom_die(argv0);
				break;
			case 'r':
				opts_proto_force(opts, optarg, argv0);
				break;
			case 'R':
				opts_proto_disable(opts, optarg, argv0);
				break;
			case 'e':
				free(natengine);
				natengine = strdup(optarg);
				if (!natengine)
					oom_die(argv0);
				break;
			case 'E':
				nat_list_engines();
				exit(EXIT_SUCCESS);
				break;
			case 'u':
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
				break;
			case 'm':
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
				break;
			case 'p':
				if (opts->pidfile)
					free(opts->pidfile);
				opts->pidfile = strdup(optarg);
				if (!opts->pidfile)
					oom_die(argv0);
				break;
			case 'j':
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
				break;
			case 'l':
				if (opts->connectlog)
					free(opts->connectlog);
				opts->connectlog = strdup(optarg);
				if (!opts->connectlog)
					oom_die(argv0);
				break;
			case 'L':
				if (opts->contentlog)
					free(opts->contentlog);
				opts->contentlog = strdup(optarg);
				if (!opts->contentlog)
					oom_die(argv0);
				opts->contentlog_isdir = 0;
				opts->contentlog_isspec = 0;
				break;
			case 'S':
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
				break;
			case 'F': {
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
				break;
			case 'W':
				opts->certgen_writeall = 1;
				if (opts->certgendir)
					free(opts->certgendir);
				opts->certgendir = strdup(optarg);
				if (!opts->certgendir)
					oom_die(argv0);
				break;
			case 'w':
				opts->certgen_writeall = 0;
				if (opts->certgendir)
					free(opts->certgendir);
				opts->certgendir = strdup(optarg);
				if (!opts->certgendir)
					oom_die(argv0);
				break;
			}
#ifdef HAVE_LOCAL_PROCINFO
			case 'i':
				opts->lprocinfo = 1;
				break;
#endif /* HAVE_LOCAL_PROCINFO */
			case 'd':
				opts->detach = 1;
				break;
			case 'D':
				log_dbg_mode(LOG_DBG_MODE_ERRLOG);
				opts->debug = 1;
				break;
			case 'V':
				main_version();
				exit(EXIT_SUCCESS);
			case 'h':
				main_usage();
				exit(EXIT_SUCCESS);
			case '?':
				exit(EXIT_FAILURE);
			default:
				main_usage();
				exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;
	opts->spec = proxyspec_parse(&argc, &argv, natengine);

	/* usage checks before defaults */
	if (opts->detach && OPTS_DEBUG(opts)) {
		fprintf(stderr, "%s: -d and -D are mutually exclusive.\n",
		                argv0);
		exit(EXIT_FAILURE);
	}
	if (!opts->spec) {
		fprintf(stderr, "%s: no proxyspec specified.\n", argv0);
		exit(EXIT_FAILURE);
	}
	for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
		if (spec->connect_addrlen || spec->sni_port)
			continue;
		if (!spec->natengine) {
			fprintf(stderr, "%s: no supported NAT engines "
			                "on this platform.\n"
			                "Only static addr and SNI proxyspecs "
			                "supported.\n", argv0);
			exit(EXIT_FAILURE);
		}
		if (spec->listen_addr.ss_family == AF_INET6 &&
		    !nat_ipv6ready(spec->natengine)) {
			fprintf(stderr, "%s: IPv6 not supported by '%s'\n",
			                argv0, spec->natengine);
			exit(EXIT_FAILURE);
		}
		spec->natlookup = nat_getlookupcb(spec->natengine);
		spec->natsocket = nat_getsocketcb(spec->natengine);
	}
	if (opts_has_ssl_spec(opts)) {
		if (ssl_init() == -1) {
			fprintf(stderr, "%s: failed to initialize OpenSSL.\n",
			                argv0);
			exit(EXIT_FAILURE);
		}
		if ((opts->cacrt || !opts->tgcrtdir) && !opts->cakey) {
			fprintf(stderr, "%s: no CA key specified (-k).\n",
			                argv0);
			exit(EXIT_FAILURE);
		}
		if (opts->cakey && !opts->cacrt) {
			fprintf(stderr, "%s: no CA cert specified (-c).\n",
			                argv0);
			exit(EXIT_FAILURE);
		}
		if (opts->cakey && opts->cacrt &&
		    (X509_check_private_key(opts->cacrt, opts->cakey) != 1)) {
			fprintf(stderr, "%s: CA cert does not match key.\n",
			                argv0);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
	}
#ifdef __APPLE__
	if (opts->dropuser && !!strcmp(opts->dropuser, "root") &&
	    nat_used("pf")) {
		fprintf(stderr, "%s: cannot use 'pf' proxyspec with -u due "
		                "to Apple bug\n", argv0);
		exit(EXIT_FAILURE);
	}
#endif /* __APPLE__ */

	/* prevent multiple instances running */
	if (opts->pidfile) {
		pidfd = sys_pidf_open(opts->pidfile);
		if (pidfd == -1) {
			fprintf(stderr, "%s: cannot open PID file '%s' "
			                "- process already running?\n",
			                argv0, opts->pidfile);
			exit(EXIT_FAILURE);
		}
	}

	/* dynamic defaults */
	if (!opts->ciphers) {
		opts->ciphers = strdup(DFLT_CIPHERS);
		if (!opts->ciphers)
			oom_die(argv0);
	}
	if (!opts->dropuser && !geteuid() && !getuid() &&
	    sys_isuser(DFLT_DROPUSER)) {
#ifdef __APPLE__
		/* Apple broke ioctl(/dev/pf) for EUID != 0 so we do not
		 * want to automatically drop privileges to nobody there
		 * if pf has been used in any proxyspec */
		if (!nat_used("pf")) {
#endif /* __APPLE__ */
		opts->dropuser = strdup(DFLT_DROPUSER);
		if (!opts->dropuser)
			oom_die(argv0);
#ifdef __APPLE__
		}
#endif /* __APPLE__ */
	}
	if (opts_has_ssl_spec(opts) && opts->cakey && !opts->key) {
		/*
		 * While browsers still generally accept it, use a leaf key
		 * size of 1024 bit for leaf keys.  When browsers start to
		 * sunset 1024 bit RSA in leaf keys, we will need to make this
		 * value bigger, and/or configurable.  Until then, users who
		 * want a different size can always use their own pre-generated
		 * leaf key instead of generating one.
		 */
		opts->key = ssl_key_genrsa(1024);
		if (!opts->key) {
			fprintf(stderr, "%s: error generating RSA key:\n",
			                argv0);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (OPTS_DEBUG(opts)) {
			log_dbg_printf("Generated RSA key for leaf certs.\n");
		}
	}

	if (opts->certgendir) {
		char *keyid, *keyfn;
		int prv;
		FILE *keyf;

		keyid = ssl_key_identifier(opts->key, 0);
		if (!keyid) {
			fprintf(stderr, "%s: error generating key id\n", argv0);
			exit(EXIT_FAILURE);
		}

		prv = asprintf(&keyfn, "%s/%s.key", opts->certgendir, keyid);
		if (prv == -1) {
			fprintf(stderr, "%s: %s (%i)\n", argv0,
			                strerror(errno), errno);
			exit(EXIT_FAILURE);
		}

		if (!(keyf = fopen(keyfn, "w"))) {
			fprintf(stderr, "%s: Failed to open '%s' for writing: "
			                "%s (%i)\n", argv0, keyfn,
			                strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
		if (!PEM_write_PrivateKey(keyf, opts->key, NULL, 0, 0,
		                                           NULL, NULL)) {
			fprintf(stderr, "%s: Failed to write key to '%s': "
			                "%s (%i)\n", argv0, keyfn,
			                strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
		fclose(keyf);
	}

	/* usage checks after defaults */
	if (opts->dropgroup && !opts->dropuser) {
		fprintf(stderr, "%s: -m depends on -u.\n", argv0);
		exit(EXIT_FAILURE);
	}

	/* debugging */
	if (OPTS_DEBUG(opts)) {
		main_version();
		opts_proto_dbg_dump(opts);
		log_dbg_printf("proxyspecs:\n");
		for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
			char *specstr = proxyspec_str(spec);
			if (!specstr) {
				fprintf(stderr, "%s: out of memory\n", argv0);
				exit(EXIT_FAILURE);
			}
			log_dbg_printf("- %s\n", specstr);
			free(specstr);
		}
		if (opts->cacrt) {
			char *subj = ssl_x509_subject(opts->cacrt);
			log_dbg_printf("Loaded CA: '%s'\n", subj);
			free(subj);
#ifdef DEBUG_CERTIFICATE
			log_dbg_print_free(ssl_x509_to_str(opts->cacrt));
			log_dbg_print_free(ssl_x509_to_pem(opts->cacrt));
#endif /* DEBUG_CERTIFICATE */
		} else {
			log_dbg_printf("No CA loaded.\n");
		}
	}

	/*
	 * Initialize as much as possible before daemon() in order to be
	 * able to provide direct feedback to the user when failing.
	 */
	if (cachemgr_preinit() == -1) {
		fprintf(stderr, "%s: failed to preinit cachemgr.\n", argv0);
		exit(EXIT_FAILURE);
	}
	if (log_preinit(opts) == -1) {
		fprintf(stderr, "%s: failed to preinit logging.\n", argv0);
		exit(EXIT_FAILURE);
	}
	if (nat_preinit() == -1) {
		fprintf(stderr, "%s: failed to preinit NAT lookup.\n", argv0);
		exit(EXIT_FAILURE);
	}

	/* Load certs before dropping privs but after cachemgr_preinit() */
	if (opts->tgcrtdir) {
		sys_dir_eachfile(opts->tgcrtdir, main_loadtgcrt, opts);
	}

	/* Detach from tty; from this point on, only canonicalized absolute
	 * paths should be used (-j, -F, -S). */
	if (opts->detach) {
		if (OPTS_DEBUG(opts)) {
			log_dbg_printf("Detaching from TTY, see syslog for "
			               "errors after this point\n");
		}
		if (daemon(0, 0) == -1) {
			fprintf(stderr, "%s: failed to detach from TTY: %s\n",
			                argv0, strerror(errno));
			exit(EXIT_FAILURE);
		}
		log_err_mode(LOG_ERR_MODE_SYSLOG);
	}

	if (opts->pidfile && (sys_pidf_write(pidfd) == -1)) {
		log_err_printf("Failed to write PID to PID file '%s': %s (%i)"
		               "\n", opts->pidfile, strerror(errno), errno);
		return -1;
	}

	/* Fork into parent monitor process and (potentially unprivileged)
	 * child process doing the actual work.  We request 3 privsep client
	 * sockets: content logger thread, cert writer thread, and the child
	 * process main thread (main proxy thread) */
	int clisock[3];
	if (privsep_fork(opts, clisock, 3) != 0) {
		/* parent has exited the monitor loop after waiting for child,
		 * or an error occured */
		if (opts->pidfile) {
			sys_pidf_close(pidfd, opts->pidfile);
		}
		goto out_parent;
	}
	/* child */

	/* close pidfile in child */
	if (opts->pidfile)
		close(pidfd);

	/* Initialize proxy before dropping privs */
	proxy_ctx_t *proxy = proxy_new(opts, clisock[0]);
	if (!proxy) {
		log_err_printf("Failed to initialize proxy.\n");
		exit(EXIT_FAILURE);
	}

	/* Drop privs, chroot */
	if (sys_privdrop(opts->dropuser, opts->dropgroup,
	                 opts->jaildir) == -1) {
		log_err_printf("Failed to drop privileges: %s (%i)\n",
		               strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	ssl_reinit();

	/* Post-privdrop/chroot/detach initialization, thread spawning */
	if (log_init(opts, proxy, clisock[1], clisock[2]) == -1) {
		fprintf(stderr, "%s: failed to init log facility: %s\n",
		                argv0, strerror(errno));
		goto out_log_failed;
	}
	if (cachemgr_init() == -1) {
		log_err_printf("Failed to init cache manager.\n");
		goto out_cachemgr_failed;
	}
	if (nat_init() == -1) {
		log_err_printf("Failed to init NAT state table lookup.\n");
		goto out_nat_failed;
	}
	rv = EXIT_SUCCESS;

	proxy_run(proxy);
	proxy_free(proxy);
	nat_fini();
out_nat_failed:
	cachemgr_fini();
out_cachemgr_failed:
	log_fini();
out_log_failed:
out_parent:
	opts_free(opts);
	ssl_fini();
	return rv;
}

/* vim: set noet ft=c: */
