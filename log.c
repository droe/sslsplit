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

#include "log.h"

#include "logger.h"
#include "sys.h"
#include "attrib.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <libgen.h>
#include <assert.h>
#include <sys/stat.h>

/*
 * Centralized logging code multiplexing thread access to the logger based
 * logging in separate threads.  Some log types are switchable to different
 * backends, such as syslog and stderr.
 */


/*
 * Error log.
 * Switchable between stderr and syslog.
 * Uses logger thread.
 */

static logger_t *err_log = NULL;
static int err_started = 0; /* while 0, shortcut the thrqueue */
static int err_mode = LOG_ERR_MODE_STDERR;

static ssize_t
log_err_writecb(UNUSED void *fh, const void *buf, size_t sz)
{
	switch (err_mode) {
		case LOG_ERR_MODE_STDERR:
			return fwrite(buf, sz - 1, 1, stderr);
		case LOG_ERR_MODE_SYSLOG:
			syslog(LOG_ERR, "%s", (const char *)buf);
			return 0;
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
	if (err_started) {
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

	if (err_started) {
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

static int
log_connect_open(const char *logfile)
{
	connect_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0660);
	if (connect_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s\n",
		               logfile, strerror(errno));
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
	}
	return 0;
}

static void
log_connect_close(void)
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
	int fd;
	union {
		struct {
			char *header_req;
			char *header_resp;
		} file;
		struct {
			char *filename;
		} dir;
		struct {
			char *filename;
		} spec;
	} u;
};

logger_t *content_log = NULL;
static int content_fd = -1; /* if set, we are in single file mode */

static int
log_content_file_preinit(const char *logfile)
{
	content_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0660);
	if (content_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s\n",
		               logfile, strerror(errno));
		return -1;
	}
	return 0;
}

static void
log_content_file_fini(void)
{
	if (content_fd != -1) {
		close(content_fd);
		content_fd = -1;
	}
}

/*
 * Generate a log path based on the given log spec.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
#define PATH_BUF_INC	1024
static char *
log_content_format_pathspec(const char *logspec, char *srcaddr, char *dstaddr,
                            char *exec_path, char *user, char *group)
WUNRES MALLOC NONNULL(1,2,3);
static char *
log_content_format_pathspec(const char *logspec, char *srcaddr, char *dstaddr,
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
				elem = dstaddr;
				elem_len = strlen(dstaddr);
				break;
			case 's':
				elem = srcaddr;
				elem_len = strlen(srcaddr);
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
                 char *srcaddr, char *dstaddr,
                 char *exec_path, char *user, char *group)
{
	log_content_ctx_t *ctx;

	if (*pctx)
		return 0;
	*pctx = malloc(sizeof(log_content_ctx_t));
	if (!*pctx)
		return -1;
	ctx = *pctx;

	if (opts->contentlog_isdir) {
		/* per-connection-file content log (-S) */
		char timebuf[24];
		time_t epoch;
		struct tm *utc;

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
		if (asprintf(&ctx->u.dir.filename, "%s/%s-%s-%s.log",
		             opts->contentlog, timebuf, srcaddr, dstaddr) < 0) {
			log_err_printf("Failed to format filename: %s (%i)\n",
			               strerror(errno), errno);
			goto errout;
		}
	} else if (opts->contentlog_isspec) {
		/* per-connection-file content log with logspec (-F) */
		ctx->u.spec.filename = log_content_format_pathspec(
		                                       opts->contentlog,
		                                       srcaddr, dstaddr,
		                                       exec_path, user, group);
		if (!ctx->u.spec.filename) {
			goto errout;
		}
	} else {
		/* single-file content log (-L) */
		ctx->fd = content_fd;
		if (asprintf(&ctx->u.file.header_req, "%s -> %s",
		             srcaddr, dstaddr) < 0) {
			goto errout;
		}
		if (asprintf(&ctx->u.file.header_resp, "%s -> %s",
		             dstaddr, srcaddr) < 0) {
			free(ctx->u.file.header_req);
			goto errout;
		}
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
 * Callback functions that are executed in the logger thread.
 */

static ssize_t
log_content_common_writecb(void *fh, const void *buf, size_t sz)
{
	log_content_ctx_t *ctx = fh;

	if (write(ctx->fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to content log: %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
}

static int
log_content_dir_opencb(void *fh)
{
	log_content_ctx_t *ctx = fh;

	ctx->fd = open(ctx->u.dir.filename, O_WRONLY|O_APPEND|O_CREAT, 0660);
	if (ctx->fd == -1) {
		log_err_printf("Failed to open '%s': %s (%i)\n",
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
	if (ctx->fd != 1)
		close(ctx->fd);
	free(ctx);
}

static int
log_content_spec_opencb(UNUSED void *fh)
{
	log_content_ctx_t *ctx = fh;
	char *filedir, *filename2;

	filename2 = strdup(ctx->u.spec.filename);
	if (!filename2) {
		log_err_printf("Could not duplicate filname: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	filedir = dirname(filename2);
	if (!filedir) {
		log_err_printf("Could not get dirname: %s (%i)\n",
		               strerror(errno), errno);
		free(filename2);
		return -1;
	}
	if (sys_mkpath(filedir, 0755) == -1) {
		log_err_printf("Could not create directory '%s': %s (%i)\n",
		               filedir, strerror(errno), errno);
		free(filename2);
		return -1;
	}
	free(filename2);

	ctx->fd = open(ctx->u.spec.filename, O_WRONLY|O_APPEND|O_CREAT, 0660);
	if (ctx->fd == -1) {
		log_err_printf("Failed to open '%s': %s\n",
		               ctx->u.spec.filename, strerror(errno));
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
	if (ctx->fd != -1)
		close(ctx->fd);
	free(ctx);
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
	logger_open_func_t opencb;
	logger_close_func_t closecb;
	logger_write_func_t writecb;
	logger_prep_func_t prepcb;

	if (opts->contentlog) {
		if (opts->contentlog_isdir) {
			opencb = log_content_dir_opencb;
			closecb = log_content_dir_closecb;
			writecb = log_content_common_writecb;
			prepcb = NULL;
		} else if (opts->contentlog_isspec) {
			opencb = log_content_spec_opencb;
			closecb = log_content_spec_closecb;
			writecb = log_content_common_writecb;
			prepcb = NULL;
		} else {
			if (log_content_file_preinit(opts->contentlog) == -1)
				goto out;
			opencb = NULL;
			closecb = log_content_file_closecb;
			writecb = log_content_common_writecb;
			prepcb = log_content_file_prepcb;
		}
		if (!(content_log = logger_new(opencb, closecb, writecb,
		                               prepcb))) {
			log_content_file_fini();
			goto out;
		}
	}
	if (opts->connectlog) {
		if (log_connect_open(opts->connectlog) == -1)
			goto out;
		if (!(connect_log = logger_new(NULL, NULL,
		                               log_connect_writecb, NULL))) {
			log_connect_close();
			goto out;
		}
	}
	if (!(err_log = logger_new(NULL, NULL, log_err_writecb, NULL)))
		goto out;
	return 0;

out:
	if (content_log) {
		log_content_file_fini();
		logger_free(content_log);
	}
	if (connect_log) {
		log_connect_close();
		logger_free(connect_log);
	}
	return -1;
}

/*
 * Log post-init: start logging threads.
 * Return -1 on errors, 0 otherwise.
 */
int
log_init(opts_t *opts)
{
	if (err_log)
		if (logger_start(err_log) == -1)
			return -1;
	if (!opts->debug) {
		err_started = 1;
	}
	if (connect_log)
		if (logger_start(connect_log) == -1)
			return -1;
	if (content_log)
		if (logger_start(content_log) == -1)
			return -1;
	return 0;
}

/*
 * Drain and cleanup.  Tell all loggers to leave, then join all logger threads,
 * and finally free resources and close log files.
 */
void
log_fini(void)
{
	if (content_log)
		logger_leave(content_log);
	if (connect_log)
		logger_leave(connect_log);
	logger_leave(err_log);

	if (content_log)
		logger_join(content_log);
	if (connect_log)
		logger_join(connect_log);
	logger_join(err_log);

	if (content_log)
		logger_free(content_log);
	if (connect_log)
		logger_free(connect_log);
	logger_free(err_log);

	if (content_log)
		log_content_file_fini();
	if (connect_log)
		log_connect_close();
}

/* vim: set noet ft=c: */
