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

#include "log.h"

#include "logger.h"
#include "sys.h"
#include "attrib.h"
#include "privsep.h"
#include "defaults.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <assert.h>
#include <sys/stat.h>
#include <netinet/in.h>

/*
 * Centralized logging code multiplexing thread access to the logger based
 * logging in separate threads.  Some log types are switchable to different
 * backends, such as syslog and stderr.
 */


/*
 * Common code for all logs.
 */
static proxy_ctx_t *proxy_ctx = NULL;

static void
log_exceptcb(void)
{
	if (proxy_ctx) {
		proxy_loopbreak(proxy_ctx);
	}
}

/*
 * Error log.
 * Switchable between stderr and syslog.
 * Uses logger thread.
 */

static logger_t *err_log = NULL;
static int err_shortcut_logger = 0;
static int err_mode = LOG_ERR_MODE_STDERR;

static ssize_t
log_err_writecb(UNUSED void *fh, const void *buf, size_t sz)
{
	switch (err_mode) {
		case LOG_ERR_MODE_STDERR:
			return fwrite(buf, sz - 1, 1, stderr);
		case LOG_ERR_MODE_SYSLOG:
			syslog(LOG_ERR, "%s", (const char *)buf);
			return sz;
	}
	return -1;
}

int
log_err_printf(const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int rv;

	va_start(ap, fmt);
	rv = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (rv < 0)
		return -1;
	if (err_shortcut_logger) {
		return logger_write_freebuf(err_log, NULL, 0,
		                            buf, strlen(buf) + 1);
	} else {
		log_err_writecb(NULL, (unsigned char*)buf, strlen(buf) + 1);
		free(buf);
	}
	return 0;
}

void
log_err_mode(int mode)
{
	err_mode = mode;
}


/*
 * Debug log.  Redirects logging to error log.
 * Switchable between error log or no logging.
 * Uses the error log logger thread.
 */

static int dbg_mode = LOG_DBG_MODE_NONE;

int
log_dbg_write_free(void *buf, size_t sz)
{
	if (dbg_mode == LOG_DBG_MODE_NONE)
		return 0;

	if (err_shortcut_logger) {
		return logger_write_freebuf(err_log, NULL, 0, buf, sz);
	} else {
		log_err_writecb(NULL, buf, sz);
		free(buf);
	}
	return 0;
}

int
log_dbg_print_free(char *s)
{
	return log_dbg_write_free(s, strlen(s) + 1);
}

int
log_dbg_printf(const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int rv;

	if (dbg_mode == LOG_DBG_MODE_NONE)
		return 0;

	va_start(ap, fmt);
	rv = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (rv < 0)
		return -1;
	return log_dbg_print_free(buf);
}

void
log_dbg_mode(int mode)
{
	dbg_mode = mode;
}


/*
 * Connection log.  Logs a one-liner to a file-based connection log.
 * Uses a logger thread.
 */

logger_t *connect_log = NULL;
static int connect_fd = -1;
static char *connect_fn = NULL;

static int
log_connect_preinit(const char *logfile)
{
	connect_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, DFLT_FILEMODE);
	if (connect_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s (%i)\n",
		               logfile, strerror(errno), errno);
		return -1;
	}
	if (!(connect_fn = realpath(logfile, NULL))) {
		log_err_printf("Failed to realpath '%s': %s (%i)\n",
		              logfile, strerror(errno), errno);
		close(connect_fd);
		connect_fd = -1;
		return -1;
	}
	return 0;
}

static int
log_connect_reopencb(void)
{
	close(connect_fd);
	connect_fd = open(connect_fn, O_WRONLY|O_APPEND|O_CREAT, DFLT_FILEMODE);
	if (connect_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s\n",
		               connect_fn, strerror(errno));
		free(connect_fn);
		connect_fn = NULL;
		return -1;
	}
	return 0;
}

/*
 * Do the actual write to the open connection log file descriptor.
 * We prepend a timestamp here, which means that timestamps are slightly
 * delayed from the time of actual logging.  Since we only have second
 * resolution that should not make any difference.
 */
static ssize_t
log_connect_writecb(UNUSED void *fh, const void *buf, size_t sz)
{
	char timebuf[32];
	time_t epoch;
	struct tm *utc;
	size_t n;

	time(&epoch);
	utc = gmtime(&epoch);
	n = strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC ", utc);
	if (n == 0) {
		log_err_printf("Error from strftime(): buffer too small\n");
		return -1;
	}
	if ((write(connect_fd, timebuf, n) == -1) ||
	    (write(connect_fd, buf, sz) == -1)) {
		log_err_printf("Warning: Failed to write to connect log: %s\n",
		               strerror(errno));
		return -1;
	}
	return sz;
}

static void
log_connect_fini(void)
{
	close(connect_fd);
}


/*
 * Content log.
 * Logs connection content to either a single file or a directory containing
 * per-connection logs.
 * Uses a logger thread; the actual logging happens in a separate thread.
 * To ensure ordering of requests (open, write, ..., close), logging for a
 * single connection must happen from a single thread.
 * This is guaranteed by the current pxythr architecture.
 */

#define PREPFLAG_REQUEST 1

struct log_content_ctx {
	unsigned int open : 1;
	unsigned int is_request;
	union {
		struct {
			char *header_req;
			char *header_resp;
		} file;
		struct {
			int fd;
			char *filename;
		} dir;
		struct {
			int fd;
			char *filename;
		} spec;
		struct {
			pcap_log_t * request;
			pcap_log_t * response;
		}pcap;
	} u;
};

static logger_t *content_log = NULL;
static int content_clisock = -1; /* privsep client socket for content logger */

/*
 * Split a pathname into static LHS (including final slashes) and dynamic RHS.
 * Returns -1 on error, 0 on success.
 * On success, fills in lhs and rhs with newly allocated buffers that must
 * be freed by the caller.
 */
int
log_content_split_pathspec(const char *path, char **lhs, char **rhs)
{
	const char *p, *q, *r;

	p = strchr(path, '%');
	/* at first % or EOS */

	/* skip % if next char is % (and implicitly not \0) */
	while (p && p[1] == '%') {
		p = strchr(p + 2, '%');
	}
	/* at first % that is not %%, or at EOS */

	if (!p || !p[1]) {
		/* EOS: no % that is not %% in path */
		p = path + strlen(path);
	}
	/* at first hot % or at '\0' */

	/* find last / before % */
	for (r = q = strchr(path, '/'); q && (q < p); q = strchr(q + 1, '/')) {
		r = q;
	}
	if (!(p = r)) {
		/* no / found, use dummy ./ as LHS */
		*lhs = strdup("./");
		if (!*lhs)
			return -1;
		*rhs = strdup(path);
		if (!*rhs) {
			free(*lhs);
			return -1;
		}
		return 0;
	}
	/* at last / terminating the static part of path */

	p++; /* skip / */
	*lhs = malloc(p - path + 1 /* for terminating null */);
	if (!*lhs)
		return -1;
	memcpy(*lhs, path, p - path);
	(*lhs)[p - path] = '\0';
	*rhs = strdup(p);
	if (!*rhs) {
		free(*lhs);
		return -1;
	}

	return 0;
}

/*
 * Generate a log path based on the given log spec.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
#define PATH_BUF_INC	1024
static char * MALLOC NONNULL(1,2,3)
log_content_format_pathspec(const char *logspec,
                            char *srchost, char *srcport,
                            char *dsthost, char *dstport,
                            char *exec_path, char *user, char *group)
{
	/* set up buffer to hold our generated file path */
	size_t path_buflen = PATH_BUF_INC;
	char *path_buf = malloc(path_buflen);
	if (path_buf == NULL) {
		log_err_printf("failed to allocate path buffer\n");
		return NULL;
	}

	/* initialize the buffer as an empty C string */
	path_buf[0] = '\0';

	/* iterate over format specifiers */
	size_t path_len = 0;
	for (const char *p = logspec; *p != '\0'; p++) {
		const char *elem = NULL;
		size_t elem_len = 0;

		const char iso8601[] =  "%Y%m%dT%H%M%SZ";
		char timebuf[24]; /* sized for ISO 8601 format */
		char addrbuf[INET6_ADDRSTRLEN + 8]; /* [host]:port */

		/* parse the format string and generate the next path element */
		switch (*p) {
		case '%':
			p++;
			/* handle format specifiers. */
			switch (*p) {
			case '\0':
				/* unexpected eof; backtrack and discard
				 * invalid format spec */
				p--;
				elem_len = 0;
				break;
			case '%':
				elem = p;
				elem_len = 1;
				break;
			case 'd':
				if (snprintf(addrbuf, sizeof(addrbuf),
				             "%s,%s", dsthost, dstport) < 0) {
					addrbuf[0] = '?';
					addrbuf[1] = '\0';
				}
				elem = addrbuf;
				elem_len = strlen(addrbuf);
				break;
			case 'D':
				elem = dsthost;
				elem_len = strlen(dsthost);
				break;
			case 'p':
				elem = dstport;
				elem_len = strlen(dstport);
				break;
			case 's':
				if (snprintf(addrbuf, sizeof(addrbuf),
				             "%s,%s", srchost, srcport) < 0) {
					addrbuf[0] = '?';
					addrbuf[1] = '\0';
				}
				elem = addrbuf;
				elem_len = strlen(addrbuf);
				break;
			case 'S':
				elem = srchost;
				elem_len = strlen(srchost);
				break;
			case 'q':
				elem = srcport;
				elem_len = strlen(srcport);
				break;
			case 'x':
				if (exec_path) {
					char *match = exec_path;
					while ((match = strchr(match, '/')) != NULL) {
						match++;
						elem = match;
					}
					elem_len = elem ? strlen(elem) : 0;
				} else {
					elem_len = 0;
				}
				break;
			case 'X':
				elem = exec_path;
				elem_len = exec_path ? strlen(exec_path) : 0;
				break;
			case 'u':
				elem = user;
				elem_len = user ? strlen(user) : 0;
				break;
			case 'g':
				elem = group;
				elem_len = group ? strlen(group) : 0;
				break;
			case 'T': {
				time_t epoch;
				struct tm *utc;

				time(&epoch);
				utc = gmtime(&epoch);
				strftime(timebuf, sizeof(timebuf), iso8601, utc);

				elem = timebuf;
				elem_len = sizeof(timebuf);
				break;
			}}
			break;
		default:
			elem = p;
			elem_len = 1;
			break;
		}

		if (elem_len > 0) {
			/* growing the buffer to fit elem_len + terminating \0 */
			if (path_buflen - path_len < elem_len + 1) {
				/* Grow in PATH_BUF_INC chunks.
				 * Note that the use of `PATH_BUF_INC' provides
				 * our guaranteed space for a trailing '\0' */
				path_buflen += elem_len + PATH_BUF_INC;
				char *newbuf = realloc(path_buf, path_buflen);
				if (newbuf == NULL) {
					log_err_printf("failed to reallocate"
					               " path buffer\n");
					free(path_buf);
					return NULL;
				}
				path_buf = newbuf;
			}

			strncat(path_buf, elem, elem_len);
			path_len += elem_len;
		}
	}

	/* apply terminating NUL */
	assert(path_buflen > path_len);
	path_buf[path_len] = '\0';
	return path_buf;
}
#undef PATH_BUF_INC

int
log_content_open(log_content_ctx_t **pctx, opts_t *opts,
                 char *srchost, char *srcport,
                 char *dsthost, char *dstport,
                 char *exec_path, char *user, char *group)
{
	log_content_ctx_t *ctx;
	char enet_dst[MAC_LEN] = {0x2B, 0xDE, 0x7C, 0x01, 0x7C, 0xA9};

	if (*pctx)
		return 0;
	*pctx = malloc(sizeof(log_content_ctx_t));
	if (!*pctx)
		return -1;
	ctx = *pctx;

	if(!opts->contentlog_pcap){
		if (opts->contentlog_isdir) {
			/* per-connection-file content log (-S) */
			char timebuf[24];
			time_t epoch;
			struct tm *utc;
			char *dsthost_clean, *srchost_clean;

			if (time(&epoch) == -1) {
				log_err_printf("Failed to get time\n");
				goto errout;
			}
			if ((utc = gmtime(&epoch)) == NULL) {
				log_err_printf("Failed to convert time: %s (%i)\n",
							   strerror(errno), errno);
				goto errout;
			}
			if (!strftime(timebuf, sizeof(timebuf),
						  "%Y%m%dT%H%M%SZ", utc)) {
				log_err_printf("Failed to format time: %s (%i)\n",
							   strerror(errno), errno);
				goto errout;
			}
			srchost_clean = sys_ip46str_sanitize(srchost);
			if (!srchost_clean) {
				log_err_printf("Failed to sanitize srchost\n");
				goto errout;
			}
			dsthost_clean = sys_ip46str_sanitize(dsthost);
			if (!dsthost_clean) {
				log_err_printf("Failed to sanitize dsthost\n");
				free(srchost_clean);
				goto errout;
			}
			if (asprintf(&ctx->u.dir.filename, "%s/%s-%s,%s-%s,%s.log",
						 opts->contentlog, timebuf,
						 srchost_clean, srcport,
						 dsthost_clean, dstport) < 0) {
				log_err_printf("Failed to format filename: %s (%i)\n",
							   strerror(errno), errno);
				free(srchost_clean);
				free(dsthost_clean);
				goto errout;
			}
			free(srchost_clean);
			free(dsthost_clean);
		} else if (opts->contentlog_isspec) {
			/* per-connection-file content log with logspec (-F) */
			char *dsthost_clean, *srchost_clean;
			srchost_clean = sys_ip46str_sanitize(srchost);
			if (!srchost_clean) {
				log_err_printf("Failed to sanitize srchost\n");
				goto errout;
			}
			dsthost_clean = sys_ip46str_sanitize(dsthost);
			if (!dsthost_clean) {
				log_err_printf("Failed to sanitize dsthost\n");
				free(srchost_clean);
				goto errout;
			}
			ctx->u.spec.filename = log_content_format_pathspec(
												   opts->contentlog,
												   srchost_clean, srcport,
												   dsthost_clean, dstport,
												   exec_path, user, group);
			free(srchost_clean);
			free(dsthost_clean);
			if (!ctx->u.spec.filename) {
				goto errout;
			}
		} else {
			/* single-file content log (-L) */
			if (asprintf(&ctx->u.file.header_req, "[%s]:%s -> [%s]:%s",
						 srchost, srcport, dsthost, dstport) < 0) {
				goto errout;
			}
			if (asprintf(&ctx->u.file.header_resp, "[%s]:%s -> [%s]:%s",
						 dsthost, dstport, srchost, srcport) < 0) {
				free(ctx->u.file.header_req);
				goto errout;
			}
		}
	}
	else{
		ctx->u.pcap.request = malloc(sizeof(pcap_log_t));
		ctx->u.pcap.response = malloc(sizeof(pcap_log_t));

		if(opts->mirrortarget != NULL && opts->contentlog_mirror != 0){
			memcpy(ctx->u.pcap.request->target_mac, opts->target_mac, sizeof(opts->target_mac));
			memcpy(ctx->u.pcap.response->target_mac, opts->target_mac, sizeof(opts->target_mac));
		}
		else{
			memcpy(ctx->u.pcap.request->target_mac, enet_dst, sizeof(enet_dst));
			memcpy(ctx->u.pcap.response->target_mac, enet_dst, sizeof(enet_dst));
		}

		if(!ctx->u.pcap.request || !ctx->u.pcap.response){
			free(ctx->u.pcap.request);
			free(ctx->u.pcap.response);
			goto errout;
		}
		store_ip_port(ctx->u.pcap.request, srchost, srcport, dsthost, dstport, opts->contentlog_mirror);
		store_ip_port(ctx->u.pcap.response, dsthost, dstport, srchost, srcport, opts->contentlog_mirror);
	}

	/* submit an open event */
	if (logger_open(content_log, ctx) == -1)
		goto errout;
	ctx->open = 1;
	return 0;
errout:
	free(ctx);
	*pctx = NULL;
	return -1;
}

int
log_content_submit(log_content_ctx_t *ctx, logbuf_t *lb, int is_request)
{
	unsigned long prepflags = 0;

	if (!ctx->open) {
		log_err_printf("log_content_submit called on closed ctx\n");
		return -1;
	}

	if (is_request)
		prepflags |= PREPFLAG_REQUEST;
	return logger_submit(content_log, ctx, prepflags, lb);
}

int
log_content_close(log_content_ctx_t **pctx)
{
	int rv = 0;

	if (!(*pctx) || !(*pctx)->open)
		return -1;
	if (logger_close(content_log, *pctx) == -1) {
		rv = -1;
	}
	*pctx = NULL;
	return rv;
}

/*
 * Log-type specific code.
 *
 * The init/fini functions are executed globally in the main thread.
 * Callback functions are executed in the logger thread.
 */

static int
log_content_dir_opencb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	if ((ctx->u.dir.fd = privsep_client_openfile(content_clisock,
	                                             ctx->u.dir.filename,
	                                             0)) == -1) {
		log_err_printf("Opening logdir file '%s' failed: %s (%i)\n",
		               ctx->u.dir.filename, strerror(errno), errno);
		return -1;
	}
	return 0;
}

static void
log_content_dir_closecb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	if (ctx->u.dir.filename)
		free(ctx->u.dir.filename);
	if (ctx->u.dir.fd != 1)
		close(ctx->u.dir.fd);
	free(ctx);
}

static ssize_t
log_content_dir_writecb(void *fh, const void *buf, size_t sz)
{
	log_content_ctx_t *ctx = fh;

	if (write(ctx->u.dir.fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to content log: %s\n",
		               strerror(errno));
		return -1;
	}
	return sz;
}

static int
log_content_spec_opencb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	if ((ctx->u.spec.fd = privsep_client_openfile(content_clisock,
	                                              ctx->u.spec.filename,
	                                              1)) == -1) {
		log_err_printf("Opening logspec file '%s' failed: %s (%i)\n",
		               ctx->u.spec.filename, strerror(errno), errno);
		return -1;
	}
	return 0;
}

static void
log_content_spec_closecb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	if (ctx->u.spec.filename)
		free(ctx->u.spec.filename);
	if (ctx->u.spec.fd != -1)
		close(ctx->u.spec.fd);
	free(ctx);
}

static ssize_t
log_content_spec_writecb(void *fh, const void *buf, size_t sz)
{
	log_content_ctx_t *ctx = fh;

	if (write(ctx->u.spec.fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to content log: %s\n",
		               strerror(errno));
		return -1;
	}
	return sz;
}

static int content_file_fd = -1;
static char *content_file_fn = NULL;

static int
log_content_file_preinit(const char *logfile)
{
	content_file_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
	                       DFLT_FILEMODE);
	if (content_file_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s (%i)\n",
		               logfile, strerror(errno), errno);
		return -1;
	}
	if (!(content_file_fn = realpath(logfile, NULL))) {
		log_err_printf("Failed to realpath '%s': %s (%i)\n",
		              logfile, strerror(errno), errno);
		close(content_file_fd);
		connect_fd = -1;
		return -1;
	}
	return 0;
}

static void
log_content_file_fini(void)
{
	if (content_file_fn) {
		free(content_file_fn);
		content_file_fn = NULL;
	}
	if (content_file_fd != -1) {
		close(content_file_fd);
		content_file_fd = -1;
	}
}

static int
log_content_file_reopencb(void)
{
	close(content_file_fd);
	content_file_fd = open(content_file_fn,
	                       O_WRONLY|O_APPEND|O_CREAT, DFLT_FILEMODE);
	if (content_file_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s (%i)\n",
		               content_file_fn, strerror(errno), errno);
		return -1;
	}
	return 0;
}

/*
static int
log_content_file_opencb(void *fh)
{
	return 0;
}
*/

static void
log_content_file_closecb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	if (ctx->u.file.header_req) {
		free(ctx->u.file.header_req);
	}
	if (ctx->u.file.header_resp) {
		free(ctx->u.file.header_resp);
	}

	free(ctx);
}

static ssize_t
log_content_file_writecb(void *fh, const void *buf, size_t sz)
{
	UNUSED log_content_ctx_t *ctx = fh;

	if (write(content_file_fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to content log: %s\n",
		               strerror(errno));
		return -1;
	}
	return sz;
}

static logbuf_t *
log_content_file_prepcb(void *fh, unsigned long prepflags, logbuf_t *lb)
{
	log_content_ctx_t *ctx = fh;
	int is_request = !!(prepflags & PREPFLAG_REQUEST);
	logbuf_t *head;
	time_t epoch;
	struct tm *utc;
	char *header;

	if (!(header = is_request ? ctx->u.file.header_req
	                          : ctx->u.file.header_resp))
		goto out;

	/* prepend size tag and newline */
	head = logbuf_new_printf(lb->fh, lb, " (%zu):\n", logbuf_size(lb));
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return NULL;
	}
	lb = head;

	/* prepend header */
	head = logbuf_new_copy(header, strlen(header), lb->fh, lb);
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return NULL;
	}
	lb = head;

	/* prepend timestamp */
	head = logbuf_new_alloc(32, lb->fh, lb);
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return NULL;
	}
	lb = head;
	time(&epoch);
	utc = gmtime(&epoch);
	lb->sz = strftime((char*)lb->buf, lb->sz, "%Y-%m-%d %H:%M:%S UTC ",
	                  utc);

out:
	return lb;
}

static int
pcap_dump_file_preinit(const char *logfile, int mirror)
{
	if(mirror == 0){
		unlink(logfile);
		content_file_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
							   DFLT_FILEMODE);
		if (content_file_fd == -1) {
			log_err_printf("Failed to open '%s' for writing: %s (%i)\n",
						   logfile, strerror(errno), errno);
			return -1;
		}

		if(write_pcap_global_hdr(content_file_fd) == -1){
			close(content_file_fd);
			connect_fd = -1;
			return -1;
		}

		if (!(content_file_fn = realpath(logfile, NULL))) {
			log_err_printf("Failed to realpath '%s': %s (%i)\n",
			              logfile, strerror(errno), errno);
			close(content_file_fd);
			connect_fd = -1;
			return -1;
		}
	}
	else{
		asprintf(&content_file_fn, "%s", logfile);
	}





	return 0;
}

static int
pcap_dump_file_reopencb(void)
{
	close(content_file_fd);
	content_file_fd = open(content_file_fn,
	                       O_WRONLY|O_APPEND|O_CREAT, DFLT_FILEMODE);
	if (content_file_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s (%i)\n",
		               content_file_fn, strerror(errno), errno);
		return -1;
	}
	return 0;
}

static void
pcap_dump_file_closecb(void *fh)
{
	log_content_ctx_t *ctx = fh;
	void *iohandle = ctx->u.pcap.request->mirror ? content_file_fn : content_file_fd;

	if(ctx->u.pcap.request->seq > 0 && ctx->u.pcap.request->ack > 0){

		if(build_ip_packet(iohandle, ctx->u.pcap.request, TH_FIN | TH_ACK, NULL, 0) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
		}
		ctx->u.pcap.response->ack += 1;
		if(build_ip_packet(iohandle, ctx->u.pcap.response, TH_ACK, NULL, 0) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
		}
		if(build_ip_packet(iohandle, ctx->u.pcap.response, TH_FIN | TH_ACK, NULL, 0) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
		}
		ctx->u.pcap.request->ack += 1;
		ctx->u.pcap.request->seq += 1;

		if(build_ip_packet(iohandle, ctx->u.pcap.request, TH_ACK, NULL, 0) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
		}
	}
	else{
/*		if(build_ip_packet(content_file_fd, ctx->u.pcap.response, TH_FIN | TH_ACK, NULL, 0) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
			return -1;
		}
	*/
	}

	if (ctx->u.pcap.request) {
		free(ctx->u.pcap.request);
	}
	if (ctx->u.pcap.response) {
		free(ctx->u.pcap.response);
	}

	free(ctx);
}

static ssize_t
pcap_dump_file_writecb(void *fh, const void *buf, size_t sz)
{
	log_content_ctx_t *ctx = fh;
	char flags = TH_PUSH | TH_ACK;
	void *iohandle = ctx->u.pcap.request->mirror ? content_file_fn : content_file_fd;
	int sendsize = 0;

	if(ctx->is_request){
		if(ctx->u.pcap.request->seq == 0){
			if(ctx->is_request){
				if(build_ip_packet(iohandle, ctx->u.pcap.request, TH_SYN, NULL, 0) == -1){
					log_err_printf("Warning: Failed to write to content log: %s\n",
					               strerror(errno));
					return -1;
				}

				ctx->u.pcap.response->ack = ctx->u.pcap.request->seq + 1;

				if(build_ip_packet(iohandle, ctx->u.pcap.response, TH_SYN | TH_ACK, NULL, 0) == -1){
					log_err_printf("Warning: Failed to write to content log: %s\n",
					               strerror(errno));
					return -1;
				}

				ctx->u.pcap.request->ack = ctx->u.pcap.response->seq + 1;
				ctx->u.pcap.request->seq += 1;
				if(build_ip_packet(iohandle, ctx->u.pcap.request, TH_ACK, NULL, 0) == -1){
						log_err_printf("Warning: Failed to write to content log: %s\n",
								               strerror(errno));
						return -1;
				}

				ctx->u.pcap.response->seq += 1;
			}
		}

		if(write_payload(iohandle, ctx->u.pcap.request, ctx->u.pcap.response, flags, buf, sz) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
			return -1;
		}
	}
	else{
		if(write_payload(iohandle, ctx->u.pcap.response, ctx->u.pcap.request, flags, buf, sz) == -1){
			log_err_printf("Warning: Failed to write to content log: %s\n",
			               strerror(errno));
			return -1;
		}
	}

	return sz;
}

static logbuf_t *
pcap_dump_file_prepcb(void *fh, unsigned long prepflags, logbuf_t *lb)
{
	log_content_ctx_t *ctx = fh;
	int is_request = !!(prepflags & PREPFLAG_REQUEST);
	time_t epoch;
	struct tm *utc;
	pcap_log_t *pcap = NULL;
	logbuf_t *head = NULL;

	ctx->is_request = is_request;

/*	head = logbuf_new_alloc(sizeof(pcap_log_t), lb->fh, lb);
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return NULL;
	}

	memcpy(head->buf, pcap, sizeof(pcap_log_t));

	lb = head;
*/
out:

	return lb;
}

/*
 * Certificate writer for -w/-W options.
 */
static logger_t *cert_log = NULL;
static int cert_clisock = -1; /* privsep client socket for cert logger */

int
log_cert_submit(const char *fn, X509 *crt)
{
	void *fh;
	logbuf_t *lb;
	char *pem;

	if (!(fh = strdup(fn)))
		goto errout1;
	if (!(pem = ssl_x509_to_pem(crt)))
		goto errout2;
	if (!(lb = logbuf_new(pem, strlen(pem), NULL, NULL)))
		goto errout3;
	return logger_submit(cert_log, fh, 0, lb);
errout3:
	free(pem);
errout2:
	free(fh);
errout1:
	return -1;
}

static ssize_t
log_cert_writecb(void *fh, const void *buf, size_t sz)
{
	char *fn = fh;
	int fd;

	if ((fd = privsep_client_certfile(cert_clisock, fn)) == -1) {
		if (errno != EEXIST) {
			log_err_printf("Failed to open '%s': %s (%i)\n",
			               fn, strerror(errno), errno);
			return -1;
		}
		return sz;
	}
	if (write(fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to '%s': %s (%i)\n",
		               fn, strerror(errno), errno);
		close(fd);
		return -1;
	}
	close(fd);
	return sz;
}


/*
 * Initialization and destruction.
 */

/*
 * Log pre-init: open all log files but don't start any threads, since we may
 * fork() after pre-initialization.
 * Return -1 on errors, 0 otherwise.
 */
int
log_preinit(opts_t *opts)
{
	logger_reopen_func_t reopencb;
	logger_open_func_t opencb;
	logger_close_func_t closecb;
	logger_write_func_t writecb;
	logger_prep_func_t prepcb;

	if (opts->contentlog) {
		if(!opts->contentlog_pcap){
			if (opts->contentlog_isdir) {
				reopencb = NULL;
				opencb = log_content_dir_opencb;
				closecb = log_content_dir_closecb;
				writecb = log_content_dir_writecb;
				prepcb = NULL;
			} else if (opts->contentlog_isspec) {
				reopencb = NULL;
				opencb = log_content_spec_opencb;
				closecb = log_content_spec_closecb;
				writecb = log_content_spec_writecb;
				prepcb = NULL;
			} else {
				if (log_content_file_preinit(opts->contentlog) == -1)
					goto out;
				reopencb = log_content_file_reopencb;
				opencb = NULL;
				closecb = log_content_file_closecb;
				writecb = log_content_file_writecb;
				prepcb = log_content_file_prepcb;
			}
		}
		else{

			if (pcap_dump_file_preinit(opts->contentlog, opts->contentlog_mirror) == -1)
				goto out;
			reopencb = opts->contentlog_mirror == 0 ? pcap_dump_file_reopencb : NULL;
			opencb = NULL;
			closecb = pcap_dump_file_closecb;
			writecb = pcap_dump_file_writecb;
			prepcb = pcap_dump_file_prepcb;
		}
		if (!(content_log = logger_new(reopencb, opencb, closecb,
		                               writecb, prepcb,
		                               log_exceptcb))) {
			log_content_file_fini();
			goto out;
		}
	}
	if (opts->connectlog) {
		if (log_connect_preinit(opts->connectlog) == -1)
			goto out;
		if (!(connect_log = logger_new(log_connect_reopencb,
		                               NULL, NULL,
		                               log_connect_writecb, NULL,
		                               log_exceptcb))) {
			log_connect_fini();
			goto out;
		}
	}
	if (opts->certgendir) {
		if (!(cert_log = logger_new(NULL, NULL, NULL, log_cert_writecb,
		                            NULL, log_exceptcb)))
			goto out;
	}
	if (!(err_log = logger_new(NULL, NULL, NULL, log_err_writecb, NULL,
	                           log_exceptcb)))
		goto out;
	return 0;

out:
	if (content_log) {
		log_content_file_fini();
		logger_free(content_log);
	}
	if (connect_log) {
		log_connect_fini();
		logger_free(connect_log);
	}
	if (cert_log) {
		logger_free(cert_log);
	}
	return -1;
}

/*
 * Close all file descriptors opened by log_preinit; used in privsep parent.
 * Only undo content and connect log, leave error and debug log functional.
 */
void
log_preinit_undo(void)
{
	if (content_log) {
		log_content_file_fini();
		logger_free(content_log);
	}
	if (connect_log) {
		log_connect_fini();
		logger_free(connect_log);
	}
}

/*
 * Log post-init: start logging threads.
 * Return -1 on errors, 0 otherwise.
 */
int
log_init(opts_t *opts, proxy_ctx_t *ctx, int clisock1, int clisock2)
{
	proxy_ctx = ctx;
	if (err_log)
		if (logger_start(err_log) == -1)
			return -1;
	if (!opts->debug) {
		err_shortcut_logger = 1;
	}
	if (connect_log)
		if (logger_start(connect_log) == -1)
			return -1;
	if (content_log) {
		content_clisock = clisock1;
		if (logger_start(content_log) == -1)
			return -1;
	} else {
		privsep_client_close(clisock1);
	}
	if (cert_log) {
		cert_clisock = clisock2;
		if (logger_start(cert_log) == -1)
			return -1;
	} else {
		privsep_client_close(clisock2);
	}
	return 0;
}

/*
 * Drain and cleanup.  Tell all loggers to leave, then join all logger threads,
 * and finally free resources and close log files.
 */
void
log_fini(void)
{
	/* switch back to direct logging so we can still log errors while
	 * tearing down the logging infrastructure */
	err_shortcut_logger = 1;

	if (cert_log)
		logger_leave(cert_log);
	if (content_log)
		logger_leave(content_log);
	if (connect_log)
		logger_leave(connect_log);
	if (err_log)
		logger_leave(err_log);

	if (cert_log)
		logger_join(cert_log);
	if (content_log)
		logger_join(content_log);
	if (connect_log)
		logger_join(connect_log);
	if (err_log)
		logger_join(err_log);

	if (cert_log)
		logger_free(cert_log);
	if (content_log)
		logger_free(content_log);
	if (connect_log)
		logger_free(connect_log);
	if (err_log)
		logger_free(err_log);

	if (content_log)
		log_content_file_fini();
	if (connect_log)
		log_connect_fini();

	if (cert_clisock != -1)
		privsep_client_close(cert_clisock);
	if (content_clisock != -1)
		privsep_client_close(content_clisock);
}

int
log_reopen(void)
{
	int rv = 0;

	if (content_log)
		if (logger_reopen(content_log) == -1)
			rv = -1;
	if (connect_log)
		if (logger_reopen(connect_log) == -1)
			rv = -1;

	return rv;
}

/* vim: set noet ft=c: */
