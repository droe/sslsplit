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
log_err_writecb(UNUSED int fd, const void *buf, size_t sz)
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
	if (rv == -1)
		return -1;
	if (err_started) {
		return logger_write_freebuf(err_log, 0, buf, strlen(buf) + 1);
	} else {
		log_err_writecb(0, (unsigned char*)buf, strlen(buf) + 1);
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
		return logger_write_freebuf(err_log, 0, buf, sz);
	} else {
		log_err_writecb(0, buf, sz);
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
	if (rv == -1)
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
log_connect_writecb(UNUSED int fd, const void *buf, size_t sz)
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
 * Uses a logger thread.
 */

logger_t *content_log = NULL;
static int content_fd = -1; /* if set, we are in single file mode */
static const char *content_basedir = NULL;

static int
log_content_open_singlefile(const char *logfile)
{
	content_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0660);
	if (content_fd == -1) {
		log_err_printf("Failed to open '%s' for writing: %s\n",
		               logfile, strerror(errno));
		return -1;
	}
	return 0;
}

static int
log_content_open_logdir(const char *basedir)
{
	content_basedir = basedir;
	return 0;
}

static void
log_content_close_singlefile(void)
{
	if (content_fd != -1) {
		close(content_fd);
		content_fd = -1;
	}
}

void
log_content_open(log_content_ctx_t *ctx, char *srcaddr, char *dstaddr)
{
	if (ctx->open)
		return;

	if (content_fd != -1) {
		ctx->fd = content_fd;
		asprintf(&ctx->header_in, "%s -> %s", srcaddr, dstaddr);
		asprintf(&ctx->header_out, "%s -> %s", dstaddr, srcaddr);
	} else {
		char filename[1024];
		char timebuf[24];
		time_t epoch;
		struct tm *utc;

		time(&epoch);
		utc = gmtime(&epoch);
		strftime(timebuf, sizeof(timebuf), "%Y%m%dT%H%M%SZ", utc);
		snprintf(filename, sizeof(filename), "%s/%s-%s-%s.log",
		         content_basedir, timebuf, srcaddr, dstaddr);
		ctx->fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, 0660);
		if (ctx->fd == -1) {
			log_err_printf("Failed to open '%s': %s\n",
			               filename, strerror(errno));
		}
	}
	ctx->open = 1;
}

void
log_content_submit(log_content_ctx_t *ctx, logbuf_t *lb, int direction)
{
	logbuf_t *head;
	time_t epoch;
	struct tm *utc;
	char *header;

	if (!ctx->open) {
		log_err_printf("log_content_submit called on closed ctx\n");
		return;
	}

	if (!(header = direction ? ctx->header_out : ctx->header_in))
		goto out;

	/* prepend size tag and newline */
	head = logbuf_new_printf(lb->fd, lb, " (%zu):\n", logbuf_size(lb));
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return;
	}
	lb = head;

	/* prepend header */
	head = logbuf_new_copy(header, strlen(header), lb->fd, lb);
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return;
	}
	lb = head;

	/* prepend timestamp */
	head = logbuf_new_alloc(32, lb->fd, lb);
	if (!head) {
		log_err_printf("Failed to allocate memory\n");
		logbuf_free(lb);
		return;
	}
	lb = head;
	time(&epoch);
	utc = gmtime(&epoch);
	lb->sz = strftime((char*)lb->buf, lb->sz, "%Y-%m-%d %H:%M:%S UTC ",
	                  utc);

out:
	lb->fd = ctx->fd;
	logger_submit(content_log, lb);
}

void
log_content_close(log_content_ctx_t *ctx)
{
	if (!ctx->open)
		return;
	if (content_fd == -1) {
		logger_write_freebuf(content_log, ctx->fd, NULL, 0);
	}
	if (ctx->header_in) {
		free(ctx->header_in);
	}
	if (ctx->header_out) {
		free(ctx->header_out);
	}
	ctx->open = 0;
}

/*
 * Do the actual write to the open connection log file descriptor.
 * We prepend a timestamp here, which means that timestamps are slightly
 * delayed from the time of actual logging.  Since we only have second
 * resolution that should not make any difference.
 */
static ssize_t
log_content_writecb(int fd, const void *buf, size_t sz)
{
	if (!buf) {
		close(fd);
		return 0;
	}

	if (write(fd, buf, sz) == -1) {
		log_err_printf("Warning: Failed to write to content log: %s\n",
		               strerror(errno));
		return -1;
	}
	return 0;
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
	if (opts->contentlog) {
		if (!opts->contentlogdir) {
			if (log_content_open_singlefile(opts->contentlog)
			    == -1)
				goto out;
		} else {
			if (log_content_open_logdir(opts->contentlog) == -1)
				goto out;
		}
		if (!(content_log = logger_new(log_content_writecb))) {
			log_content_close_singlefile();
			goto out;
		}
	}
	if (opts->connectlog) {
		if (log_connect_open(opts->connectlog) == -1)
			goto out;
		if (!(connect_log = logger_new(log_connect_writecb))) {
			log_connect_close();
			goto out;
		}
	}
	if (!(err_log = logger_new(log_err_writecb)))
		goto out;
	return 0;

out:
	if (content_log) {
		log_content_close_singlefile();
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
		log_content_close_singlefile();
	if (connect_log)
		log_connect_close();
}

/* vim: set noet ft=c: */
