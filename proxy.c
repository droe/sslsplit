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

#include "proxy.h"

#include "pxythrmgr.h"
#include "pxyconn.h"
#include "cachemgr.h"
#include "opts.h"
#include "log.h"
#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/thread.h>


/*
 * Proxy engine, built around libevent 2.x.
 */

static int signals[] = { SIGQUIT, SIGHUP, SIGINT, SIGPIPE };

struct proxy_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	struct event_base *evbase;
	struct event *sev[sizeof(signals)/sizeof(int)];
	struct event *gcev;
	struct proxy_listener_ctx *lctx;
	opts_t *opts;
};


/*
 * Listener context.
 */
typedef struct proxy_listener_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;
	struct evconnlistener *evcl;
	struct proxy_listener_ctx *next;
} proxy_listener_ctx_t;

static proxy_listener_ctx_t *
proxy_listener_ctx_new(pxy_thrmgr_ctx_t *thrmgr, proxyspec_t *spec,
                       opts_t *opts) MALLOC;
static proxy_listener_ctx_t *
proxy_listener_ctx_new(pxy_thrmgr_ctx_t *thrmgr, proxyspec_t *spec,
                       opts_t *opts)
{
	proxy_listener_ctx_t *ctx = malloc(sizeof(proxy_listener_ctx_t));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(proxy_listener_ctx_t));
	ctx->thrmgr = thrmgr;
	ctx->spec = spec;
	ctx->opts = opts;
	return ctx;
}

static void
proxy_listener_ctx_free(proxy_listener_ctx_t *ctx) NONNULL(1);
static void
proxy_listener_ctx_free(proxy_listener_ctx_t *ctx)
{
	if (ctx->evcl) {
		evconnlistener_free(ctx->evcl);
	}
	if (ctx->next) {
		proxy_listener_ctx_free(ctx->next);
	}
	free(ctx);
}

/*
 * Callback for accept events on the socket listener bufferevent.
 */
static void
proxy_listener_acceptcb(UNUSED struct evconnlistener *listener,
                        evutil_socket_t fd,
                        struct sockaddr *peeraddr, int peeraddrlen,
                        void *arg)
{
	proxy_listener_ctx_t *cfg = arg;

	pxy_conn_setup(fd, peeraddr, peeraddrlen, cfg->thrmgr,
	               cfg->spec, cfg->opts);
}

/*
 * Callback for error events on the socket listener bufferevent.
 */
static void
proxy_listener_errorcb(struct evconnlistener *listener, UNUSED void *ctx)
{
	struct event_base *evbase = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();
	log_err_printf("Error %d on listener: %s\n", err,
	               evutil_socket_error_to_string(err));
	event_base_loopbreak(evbase);
}

/*
 * Dump a description of an evbase to debugging code.
 */
static void
proxy_debug_base(const struct event_base *ev_base)
{
	log_dbg_printf("Using libevent backend '%s'\n",
	               event_base_get_method(ev_base));

	enum event_method_feature f;
	f = event_base_get_features(ev_base);
	log_dbg_printf("Event base supports: edge %s, O(1) %s, anyfd %s\n",
	               ((f & EV_FEATURE_ET) ? "yes" : "no"),
	               ((f & EV_FEATURE_O1) ? "yes" : "no"),
	               ((f & EV_FEATURE_FDS) ? "yes" : "no"));
}

/*
 * Set up the listener for a single proxyspec and add it to evbase.
 * Returns the proxy_listener_ctx_t pointer if successful, NULL otherwise.
 */
static proxy_listener_ctx_t *
proxy_listener_setup(struct event_base *evbase, pxy_thrmgr_ctx_t *thrmgr,
                     proxyspec_t *spec, opts_t *opts)
{
	proxy_listener_ctx_t *plc;

	evutil_socket_t fd;
	int on = 1;
	int rv;

	fd = socket(spec->listen_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		log_err_printf("Error from socket(): %s\n",
		               strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	rv = evutil_make_socket_nonblocking(fd);
	if (rv == -1) {
		log_err_printf("Error making socket nonblocking: %s\n",
		               strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	rv = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on));
	if (rv == -1) {
		log_err_printf("Error from setsockopt(SO_KEEPALIVE): %s\n",
		               strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	rv = evutil_make_listen_socket_reuseable(fd);
	if (rv == -1) {
		log_err_printf("Error from setsockopt(SO_REUSABLE): %s\n",
		               strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	if (spec->natsocket && (spec->natsocket(fd) == -1)) {
		log_err_printf("Error from spec->natsocket()\n");
		evutil_closesocket(fd);
		return NULL;
	}

	rv = bind(fd, (struct sockaddr *)&spec->listen_addr,
	          spec->listen_addrlen);
	if (rv == -1) {
		log_err_printf("Error from bind(): %s\n", strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	plc = proxy_listener_ctx_new(thrmgr, spec, opts);
	if (!plc) {
		log_err_printf("Error creating listener context\n");
		evutil_closesocket(fd);
		return NULL;
	}

	plc->evcl = evconnlistener_new(evbase, proxy_listener_acceptcb,
	                               plc, LEV_OPT_CLOSE_ON_FREE, 1024, fd);
	if (!plc->evcl) {
		log_err_printf("Error creating evconnlistener: %s\n",
		               strerror(errno));
		proxy_listener_ctx_free(plc);
		evutil_closesocket(fd);
		return NULL;
	}
	evconnlistener_set_error_cb(plc->evcl, proxy_listener_errorcb);
	return plc;
}

/*
 * Signal handler for SIGQUIT, SIGINT, SIGHUP and SIGPIPE.
 */
static void
proxy_signal_cb(evutil_socket_t fd, UNUSED short what, void *arg)
{
	proxy_ctx_t *ctx = arg;

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Received signal %i\n", fd);
	}

	if (fd == SIGPIPE) {
		log_err_printf("Warning: Received SIGPIPE; ignoring.\n");
	} else {
		event_base_loopbreak(ctx->evbase);
	}
}

/*
 * Garbage collection handler.
 */
static void
proxy_gc_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	proxy_ctx_t *ctx = arg;

	if (OPTS_DEBUG(ctx->opts))
		log_dbg_printf("Garbage collecting caches started.\n");

	cachemgr_gc();

	if (OPTS_DEBUG(ctx->opts))
		log_dbg_printf("Garbage collecting caches done.\n");
}

/*
 * Set up the core event loop.
 * Returns ctx on success, or NULL on error.
 */
proxy_ctx_t *
proxy_new(opts_t *opts)
{
	proxy_listener_ctx_t *head;
	proxy_ctx_t *ctx;
	struct evdns_base *dnsbase;
	int rc;

	/* adds locking, only required if accessed from separate threads */
	evthread_use_pthreads();

#ifndef PURIFY
	if (OPTS_DEBUG(opts)) {
		event_enable_debug_mode();
	}
#endif /* PURIFY */

	ctx = malloc(sizeof(proxy_ctx_t));
	if (!ctx) {
		log_err_printf("Error allocating memory\n");
		goto leave0;
	}
	memset(ctx, 0, sizeof(proxy_ctx_t));

	ctx->opts = opts;
	ctx->evbase = event_base_new();
	if (!ctx->evbase) {
		log_err_printf("Error getting event base\n");
		goto leave1;
	}

	/* create a dnsbase here purely for being able to test parsing
	 * resolv.conf while we can still alert the user about it. */
	dnsbase = evdns_base_new(ctx->evbase, 0);
	if (!dnsbase) {
		log_err_printf("Error creating dns event base\n");
		goto leave1b;
	}
	rc = evdns_base_resolv_conf_parse(dnsbase, DNS_OPTIONS_ALL,
	                                  "/etc/resolv.conf");
	evdns_base_free(dnsbase, 0);
	if (rc != 0) {
		log_err_printf("evdns cannot parse resolv.conf: %s (%d)\n",
		               rc == 1 ? "failed to open file" :
		               rc == 2 ? "failed to stat file" :
		               rc == 3 ? "file too large" :
		               rc == 4 ? "out of memory" :
		               rc == 5 ? "short read from file" :
		               rc == 6 ? "no nameservers listed in file" :
		               "unknown error", rc);
		goto leave1b;
	}

	if (OPTS_DEBUG(opts)) {
		proxy_debug_base(ctx->evbase);
	}

	ctx->thrmgr = pxy_thrmgr_new(opts);
	if (!ctx->thrmgr) {
		log_err_printf("Error creating thread manager\n");
		goto leave1b;
	}

	head = ctx->lctx = NULL;
	for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
		head = proxy_listener_setup(ctx->evbase, ctx->thrmgr,
		                            spec, opts);
		if (!head)
			goto leave2;
		head->next = ctx->lctx;
		ctx->lctx = head;
	}

	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++) {
		ctx->sev[i] = evsignal_new(ctx->evbase, signals[i],
		                           proxy_signal_cb, ctx);
		if (!ctx->sev[i])
			goto leave3;
		evsignal_add(ctx->sev[i], NULL);
	}

	struct timeval gc_delay = {60, 0};
	ctx->gcev = event_new(ctx->evbase, -1, EV_PERSIST, proxy_gc_cb, ctx);
	if (!ctx->gcev)
		goto leave4;
	evtimer_add(ctx->gcev, &gc_delay);

	return ctx;

leave4:
	if (ctx->gcev) {
		event_free(ctx->gcev);
	}

leave3:
	for (size_t i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
		if (ctx->sev[i]) {
			event_free(ctx->sev[i]);
		}
	}
leave2:
	if (ctx->lctx) {
		proxy_listener_ctx_free(ctx->lctx);
	}
	pxy_thrmgr_free(ctx->thrmgr);
leave1b:
	event_base_free(ctx->evbase);
leave1:
	free(ctx);
leave0:
	return NULL;
}

/*
 * Run the event loop.  Returns when the event loop is cancelled by a signal
 * or on failure.
 */
void
proxy_run(proxy_ctx_t *ctx)
{
	if (ctx->opts->detach) {
		event_reinit(ctx->evbase);
	}
#ifndef PURIFY
	if (OPTS_DEBUG(ctx->opts)) {
		event_base_dump_events(ctx->evbase, stderr);
	}
#endif /* PURIFY */
	if (pxy_thrmgr_run(ctx->thrmgr) == -1) {
		log_err_printf("Failed to start thread manager\n");
		return;
	}
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Starting main event loop.\n");
	}
	event_base_dispatch(ctx->evbase);
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Main event loop stopped.\n");
	}
}

/*
 * Free the proxy data structures.
 */
void
proxy_free(proxy_ctx_t *ctx)
{
	if (ctx->gcev) {
		event_free(ctx->gcev);
	}
	if (ctx->lctx) {
		proxy_listener_ctx_free(ctx->lctx);
	}
	for (size_t i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
		if (ctx->sev[i]) {
			event_free(ctx->sev[i]);
		}
	}
	if (ctx->thrmgr) {
		pxy_thrmgr_free(ctx->thrmgr);
	}
	if (ctx->evbase) {
		event_base_free(ctx->evbase);
	}
	free(ctx);
}

/* vim: set noet ft=c: */
