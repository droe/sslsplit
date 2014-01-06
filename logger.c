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

#include "logger.h"

#include "thrqueue.h"
#include "logbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/*
 * Logger for multithreaded environments.  Disk writes are executed in a
 * writer thread.  Logging threads submit buffers to be logged by adding
 * them to the thrqueue.  Logging threads may block on the pthread mutex
 * of the thrqueue, but not on disk writes.
 */

struct logger {
	pthread_t thr;
	logger_write_func_t write;
	thrqueue_t *queue;
};

static void
logger_clear(logger_t *logger)
{
	memset(logger, 0, sizeof(logger_t));
}

/*
 * Create new logger with a specific write function callback.
 * The callback will be executed in the logger's writer thread,
 * not in the thread calling logger_submit().
 */
logger_t *
logger_new(logger_write_func_t writefunc)
{
	logger_t *logger;

	logger = malloc(sizeof(logger_t));
	if (!logger)
		return NULL;
	logger_clear(logger);
	logger->write = writefunc;
	logger->queue = NULL;
	return logger;
}

/*
 * Free the logger data structures.  Caller must call logger_stop()
 * or logger_leave() and logger_join() prior to freeing.
 */
void
logger_free(logger_t *logger) {
	if (logger->queue) {
		thrqueue_free(logger->queue);
	}
	free(logger);
}

/*
 * Submit a buffer to be logged by the logger thread.
 * Buffer will be freed after logging completes.
 * Returns -1 on error, 0 on success.
 */
int
logger_submit(logger_t *logger, logbuf_t *lb)
{
	return thrqueue_enqueue(logger->queue, lb) ? 0 : -1;
}

/*
 * Logger thread main function.
 */
static void *
logger_thread(void *arg)
{
	logger_t *logger = arg;
	logbuf_t *lb;

	while ((lb = thrqueue_dequeue(logger->queue))) {
		logbuf_write_free(lb, logger->write);
	}

	return NULL;
}

/*
 * Start the logger's write thread.
 */
int
logger_start(logger_t *logger) {
	int rv;

	if (logger->queue) {
		thrqueue_free(logger->queue);
	}
	logger->queue = thrqueue_new(1024);

	rv = pthread_create(&logger->thr, NULL, logger_thread, logger);
	if (rv)
		return -1;
	sched_yield();
	return 0;
}

/*
 * Tell the logger's write thread to write all pending write requests
 * and then exit.  Don't wait for the logger to exit.
 */
void
logger_leave(logger_t *logger) {
	thrqueue_unblock_dequeue(logger->queue);
	sched_yield();
}

/*
 * Wait for the logger to exit.
 */
int
logger_join(logger_t *logger) {
	int rv;

	rv = pthread_join(logger->thr, NULL);
	if (rv)
		return -1;
	return 0;
}

/*
 * Tell the logger's write thread to write all pending write requests
 * and then exit; wait for the logger to exit.
 */
int
logger_stop(logger_t *logger) {
	logger_leave(logger);
	return logger_join(logger);
}

/*
 * Generic print to a logger.  These functions should be called by the
 * actual worker thread(s) doing network I/O.
 *
 * _printf(), _print() and _write() copy the input buffers.
 * _ncprint() and _ncwrite() will free() the input buffers.
 *
 * The file descriptor argument is a virtual or real system file descriptor
 * used for multiplexing write requests to several files over the same
 * logger.  This argument is passed to the write handler as-is and is not
 * interpreted or used by the logger itself in any way.
 *
 * All of the functions return 0 on succes, -1 on failure.
 */
int
logger_printf(logger_t *logger, int fd, const char *fmt, ...)
{
	va_list ap;
	logbuf_t *lb;

	lb = logbuf_new(NULL, 0, fd, NULL);
	if (!lb)
		return -1;
	va_start(ap, fmt);
	lb->sz = vasprintf((char**)&lb->buf, fmt, ap);
	va_end(ap);
	if (lb->sz == -1) {
		logbuf_free(lb);
		return -1;
	}
	return logger_submit(logger, lb);
}
int
logger_write(logger_t *logger, int fd, const void *buf, size_t sz)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new_copy(buf, sz, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_print(logger_t *logger, int fd, const char *s)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new_copy(s, s ? strlen(s) : 0, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_write_freebuf(logger_t *logger, int fd, void *buf, size_t sz)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new(buf, sz, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_print_freebuf(logger_t *logger, int fd, char *s)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new(s, s ? strlen(s) : 0, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}

/* vim: set noet ft=c: */
