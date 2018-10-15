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

#include "privsep.h"

#include "sys.h"
#include "util.h"
#include "log.h"
#include "attrib.h"
#include "defaults.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>
#ifdef __linux__
#include <limits.h>
#endif /* __linux__ */

/*
 * Privilege separation functionality.
 *
 * The server code has limitations on the internal functionality that can be
 * used, namely only those that are initialized before forking.
 */

/* maximal message sizes */
#define PRIVSEP_MAX_REQ_SIZE	512	/* arbitrary limit */
#ifdef __linux__
#define PRIVSEP_MAX_ANS_SIZE	PATH_MAX + 255
#else /* !__linux__ */
#define PRIVSEP_MAX_ANS_SIZE	(1+sizeof(int))
#endif /* !__linux__ */

/* command byte */
#define PRIVSEP_REQ_CLOSE	0	/* closing command socket */
#define PRIVSEP_REQ_OPENFILE	1	/* open content log file */
#define PRIVSEP_REQ_OPENFILE_P	2	/* open content log file w/mkpath */
#define PRIVSEP_REQ_OPENSOCK	3	/* open socket and pass fd */
#define PRIVSEP_REQ_CERTFILE	4	/* open cert file in certgendir */
#ifdef __linux__
#define PRIVSEP_REQ_LX_GET_PID	5	/* find pid for address */
#define PRIVSEP_REQ_LX_GET_INFO	6	/* get info for pid */
#endif /* __linux__ */

/* response byte */
#define PRIVSEP_ANS_SUCCESS	0	/* success */
#define PRIVSEP_ANS_UNK_CMD	1	/* unknown command */
#define PRIVSEP_ANS_INVALID	2	/* invalid message */
#define PRIVSEP_ANS_DENIED	3	/* request denied */
#define PRIVSEP_ANS_SYS_ERR	4	/* system error; arg=errno */

/* Whether we short-circuit calls to privsep_client_* directly to
 * privsep_server_* within the client process, bypassing the privilege
 * separation mechanism; this is a performance optimization for use cases
 * where the user choses performance over security, especially with options
 * that require privsep operations for each connection passing through.
 * In the current implementation, for consistency, we still fork normally, but
 * will not actually send any privsep requests to the parent process. */
static int privsep_fastpath;

/* communication with signal handler */
static volatile sig_atomic_t received_sighup;
static volatile sig_atomic_t received_sigint;
static volatile sig_atomic_t received_sigquit;
static volatile sig_atomic_t received_sigterm;
static volatile sig_atomic_t received_sigchld;
static volatile sig_atomic_t received_sigusr1;
/* write end of pipe used for unblocking select */
static volatile sig_atomic_t selfpipe_wrfd;

static void
privsep_server_signal_handler(int sig)
{
	int saved_errno;

	saved_errno = errno;

#ifdef DEBUG_PRIVSEP_SERVER
	log_dbg_printf("privsep_server_signal_handler\n");
#endif /* DEBUG_PRIVSEP_SERVER */

	switch (sig) {
	case SIGHUP:
		received_sighup = 1;
		break;
	case SIGINT:
		received_sigint = 1;
		break;
	case SIGQUIT:
		received_sigquit = 1;
		break;
	case SIGTERM:
		received_sigterm = 1;
		break;
	case SIGCHLD:
		received_sigchld = 1;
		break;
	case SIGUSR1:
		received_sigusr1 = 1;
		break;
	}
	if (selfpipe_wrfd != -1) {
		ssize_t n;

#ifdef DEBUG_PRIVSEP_SERVER
		log_dbg_printf("writing to selfpipe_wrfd %i\n", selfpipe_wrfd);
#endif /* DEBUG_PRIVSEP_SERVER */
		do {
			n = write(selfpipe_wrfd, "!", 1);
		} while (n == -1 && errno == EINTR);
		if (n == -1) {
			log_err_printf("Failed to write from signal handler: "
			               "%s (%i)\n", strerror(errno), errno);
			/* ignore error */
		}
#ifdef DEBUG_PRIVSEP_SERVER
	} else {
		log_dbg_printf("selfpipe_wrfd is %i - not writing\n", selfpipe_wrfd);
#endif /* DEBUG_PRIVSEP_SERVER */
	}
	errno = saved_errno;
}

static int WUNRES
privsep_server_openfile_verify(opts_t *opts, const char *fn, int mkpath)
{
	if (mkpath && !(opts->contentlog_isspec || opts->pcaplog_isspec))
		return -1;
	if (!mkpath && !(opts->contentlog_isdir || opts->pcaplog_isdir))
		return -1;
	if (strstr(fn, opts->contentlog_isspec ? opts->contentlog_basedir
	                                        : opts->contentlog) != fn &&
	    strstr(fn, opts->pcaplog_isspec ? opts->pcaplog_basedir
	                                     : opts->pcaplog) != fn)
		return -1;
	if (strstr(fn, "/../"))
		return -1;
	return 0;
}

static int WUNRES
privsep_server_openfile(const char *fn, int mkpath)
{
	int fd, tmp;

	if (mkpath) {
		char *filedir, *fn2;

		fn2 = strdup(fn);
		if (!fn2) {
			tmp = errno;
			log_err_printf("Could not duplicate filname: %s (%i)\n",
			               strerror(errno), errno);
			errno = tmp;
			return -1;
		}
		filedir = dirname(fn2);
		if (!filedir) {
			tmp = errno;
			log_err_printf("Could not get dirname: %s (%i)\n",
			               strerror(errno), errno);
			free(fn2);
			errno = tmp;
			return -1;
		}
		if (sys_mkpath(filedir, DFLT_DIRMODE) == -1) {
			tmp = errno;
			log_err_printf("Could not create directory '%s': %s (%i)\n",
			               filedir, strerror(errno), errno);
			free(fn2);
			errno = tmp;
			return -1;
		}
		free(fn2);
	}

	fd = open(fn, O_RDWR|O_CREAT, DFLT_FILEMODE);
	if (fd == -1) {
		tmp = errno;
		log_err_printf("Failed to open '%s': %s (%i)\n",
		               fn, strerror(errno), errno);
		errno = tmp;
		return -1;
	}
	if (lseek(fd, 0, SEEK_END) == -1) {
		tmp = errno;
		log_err_printf("Failed to seek on '%s': %s (%i)\n",
		               fn, strerror(errno), errno);
		errno = tmp;
		return -1;
	}
	return fd;
}

static int WUNRES
privsep_server_opensock_verify(opts_t *opts, void *arg)
{
	/* This check is safe, because modifications of the spec in the child
	 * process do not affect the copy of the spec here in the parent. */
	for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
		if (spec == arg)
			return 0;
	}
	return 1;
}

static int WUNRES
privsep_server_opensock(const proxyspec_t *spec)
{
	evutil_socket_t fd;
	int on = 1;
	int rv;

	fd = socket(spec->listen_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		log_err_printf("Error from socket(): %s (%i)\n",
		               strerror(errno), errno);
		evutil_closesocket(fd);
		return -1;
	}

	rv = evutil_make_socket_nonblocking(fd);
	if (rv == -1) {
		log_err_printf("Error making socket nonblocking: %s (%i)\n",
		               strerror(errno), errno);
		evutil_closesocket(fd);
		return -1;
	}

	rv = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on));
	if (rv == -1) {
		log_err_printf("Error from setsockopt(SO_KEEPALIVE): %s (%i)\n",
		               strerror(errno), errno);
		evutil_closesocket(fd);
		return -1;
	}

	rv = evutil_make_listen_socket_reuseable(fd);
	if (rv == -1) {
		log_err_printf("Error from setsockopt(SO_REUSABLE): %s\n",
		               strerror(errno));
		evutil_closesocket(fd);
		return -1;
	}

	if (spec->natsocket && (spec->natsocket(fd) == -1)) {
		log_err_printf("Error from spec->natsocket()\n");
		evutil_closesocket(fd);
		return -1;
	}

	rv = bind(fd, (struct sockaddr *)&spec->listen_addr,
	          spec->listen_addrlen);
	if (rv == -1) {
		log_err_printf("Error from bind(): %s\n", strerror(errno));
		evutil_closesocket(fd);
		return -1;
	}

	return fd;
}

static int WUNRES
privsep_server_certfile_verify(opts_t *opts, const char *fn)
{
	if (!opts->certgendir)
		return -1;
	if (strstr(fn, opts->certgendir) != fn || strstr(fn, "/../"))
		return -1;
	return 0;
}

static int WUNRES
privsep_server_certfile(const char *fn)
{
	int fd;

	fd = open(fn, O_WRONLY|O_CREAT|O_EXCL, DFLT_FILEMODE);
	if (fd == -1 && errno != EEXIST) {
		log_err_printf("Failed to open '%s': %s (%i)\n",
		               fn, strerror(errno), errno);
		return -1;
	}
	return fd;
}

#ifdef __linux__
#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>

enum { ST_START, ST_NUM, ST_BEFORE_IP, ST_LOCAL_IP, ST_LOCAL_PORT };

static int
ishex(int c)
{
	return (isdigit(c) != 0 || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)) ? 1 : 0;
}

static int
hextoi(int c)
{
	if (c >= 65 && c <= 70) {
		return c - 55;
	}
	if (c >= 97 && c <= 102) {
		return c - 87;
	}
	return c - 48;
}

static pid_t
find_pid(ino_t inode)
{
	DIR *d = opendir("/proc"), *dfd;
	struct dirent entry, *res;
	struct stat sbuf;
	char *ep, fdn[1024], fdf[1024];
	pid_t pid;

	if (d != NULL) {
		while(1) {
			readdir_r(d, &entry, &res);
			if (res == NULL) {
				break;
			}
			if (entry.d_type == DT_DIR) {
				pid = strtol(entry.d_name, &ep, 10);
				if (ep[0] == '\0') {
					snprintf(fdn, sizeof(fdn), "/proc/%s/fd", entry.d_name);
					dfd = opendir(fdn);
					if (dfd != NULL) {
						while(1) {
							readdir_r(dfd, &entry, &res);
							if (res == NULL) {
								break;
							}
							snprintf(fdf, sizeof(fdf), "%s/%s", fdn, entry.d_name);
							if (stat(fdf, &sbuf) == 0) {
								if ((sbuf.st_mode & S_IFMT) == S_IFSOCK && sbuf.st_ino == inode) {
									closedir(dfd);
									closedir(d);
									return pid;
								}
							}
						}
						closedir(dfd);
					}
				}
			}
		}
		closedir(d);
	}
	return -1;
}

/*
 * This currently only supports IPv4 sockaddrs.
 */
static pid_t WUNRES
privsep_server_linux_get_pid(struct sockaddr *addr)
{
	if (addr->sa_family != AF_INET)
		return -1;

	struct sockaddr_in *sai = (struct sockaddr_in *)addr;

	int fd = open("/proc/net/tcp", O_RDONLY);
	if (fd != -1) {
		char bufc[4096], inode[64];
		char *buf;
		int i, state, sh = 0;
		uint32_t s_addr;
		in_port_t sin_port = 0;
		char c;
		FILE *file = fdopen(fd, "r");

		if (file != NULL) {
			while (fgets(bufc, sizeof(bufc), file) != NULL) {
				state = ST_START;
				buf = (char *)&bufc;
				for (c = *buf; c != 0; buf++, c = *buf) {
					if (state == ST_START) {
						if (c == ' ') {
							continue;
						}
						if (isdigit(c) == 0) {
							break;
						}
						state = ST_NUM;
					} else if (state == ST_NUM) {
						if (c == ':') {
							state = ST_BEFORE_IP;
							continue;
						}
						if (isdigit(c) == 0) {
							break;
						}
					} else if (state == ST_BEFORE_IP) {
						if (c == ' ') {
							continue;
						}
						if (ishex(c) != 0) {
							state = ST_LOCAL_IP;
							sh = 24;
							s_addr = hextoi(c) << 28;
							continue;
						}
						break;
					} else if (state == ST_LOCAL_IP) {
						if (c == ':') {
							state = ST_LOCAL_PORT;
							sin_port = 0;
							sh = 12;
							continue;
						}
						if (ishex(c) != 0) {
							s_addr += (hextoi(c) << sh);
							sh -= 4;
							continue;
						}
						break;
					} else if (state == ST_LOCAL_PORT) {
						if (c == ' ') {
							if (s_addr == sai->sin_addr.s_addr && htons(sin_port) == sai->sin_port) {
								/* find inode */
								buf += 72;
								for (c = *buf, i = 0; c != 0; i++, buf++, c = *buf) {
									if (c == ' ') {
										inode[i] = 0;
										break;
									}
									if (isdigit(c) == 0) {
										inode[0] = 0;
										break;
									}
									inode[i] = c;
								}
								if (inode[0] == 0) {
									break;
								}
								return find_pid(atoll(inode));
							}
							break;
						}
						if (ishex(c) != 0) {
							sin_port += (hextoi(c) << sh);
							sh -= 4;
							continue;
						}
						break;
					}
				}
			}
			fclose(file);
		}
	}
	return -1;
}

static size_t WUNRES
privsep_server_linux_get_info(pid_t pid, char **path, uid_t *uid, gid_t *gid) {
	struct stat sbuf;
	char dn[32], exe[PATH_MAX];
	ssize_t n;

	snprintf(dn, sizeof(dn), "/proc/%lu", (unsigned long)pid);
	if (stat(dn, &sbuf) == 0) {
		*uid = sbuf.st_uid;
		*gid = sbuf.st_gid;
		snprintf(dn, sizeof(dn), "/proc/%lu/exe", (unsigned long)pid);
		n = readlink(dn, exe, sizeof(exe) - 1);
		if (n != -1) {
			exe[n] = 0;
			*path = strdup(exe);
			return n;
		}
	}
	return 0;
}
#endif /* __linux__ */

/*
 * Handle a single request on a readable server socket.
 * Returns 0 on success, 1 on EOF and -1 on error.
 */
static int WUNRES
privsep_server_handle_req(opts_t *opts, int srvsock)
{
	char req[PRIVSEP_MAX_REQ_SIZE];
	char ans[PRIVSEP_MAX_ANS_SIZE];
	ssize_t n;
	int mkpath = 0;

	if ((n = sys_recvmsgfd(srvsock, req, sizeof(req),
	                       NULL)) == -1) {
		if (errno == EPIPE || errno == ECONNRESET) {
			/* unfriendly EOF, leave server */
			return 1;
		}
		log_err_printf("Failed to receive msg: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (n == 0) {
		/* EOF, leave server; will not happen for SOCK_DGRAM sockets */
		return 1;
	}
	log_dbg_printf("Received privsep req type %02x sz %zd on srvsock %i\n",
	               req[0], n, srvsock);
	switch (req[0]) {
	case PRIVSEP_REQ_CLOSE: {
		/* client indicates EOF through close message */
		return 1;
	}
	case PRIVSEP_REQ_OPENFILE_P:
		mkpath = 1;
		/* fall through */
	case PRIVSEP_REQ_OPENFILE: {
		char *fn;
		int fd;

		if (n < 2) {
			ans[0] = PRIVSEP_ANS_INVALID;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
		}
		if (!(fn = malloc(n))) {
			ans[0] = PRIVSEP_ANS_SYS_ERR;
			*((int*)&ans[1]) = errno;
			if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(int),
			                  -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		memcpy(fn, req + 1, n - 1);
		fn[n - 1] = '\0';
		if (privsep_server_openfile_verify(opts, fn, mkpath) == -1) {
			free(fn);
			ans[0] = PRIVSEP_ANS_DENIED;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		if ((fd = privsep_server_openfile(fn, mkpath)) == -1) {
			free(fn);
			ans[0] = PRIVSEP_ANS_SYS_ERR;
			*((int*)&ans[1]) = errno;
			if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(int),
			                  -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		} else {
			free(fn);
			ans[0] = PRIVSEP_ANS_SUCCESS;
			if (sys_sendmsgfd(srvsock, ans, 1, fd) == -1) {
				close(fd);
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			close(fd);
			return 0;
		}
		/* not reached */
		break;
	}
	case PRIVSEP_REQ_OPENSOCK: {
		proxyspec_t *arg;
		int s;

		if (n != sizeof(char) + sizeof(arg)) {
			ans[0] = PRIVSEP_ANS_INVALID;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		arg = *(proxyspec_t**)(&req[1]);
		if (privsep_server_opensock_verify(opts, arg) == -1) {
			ans[0] = PRIVSEP_ANS_DENIED;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		if ((s = privsep_server_opensock(arg)) == -1) {
			ans[0] = PRIVSEP_ANS_SYS_ERR;
			*((int*)&ans[1]) = errno;
			if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(int),
			                  -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		} else {
			ans[0] = PRIVSEP_ANS_SUCCESS;
			if (sys_sendmsgfd(srvsock, ans, 1, s) == -1) {
				evutil_closesocket(s);
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			evutil_closesocket(s);
			return 0;
		}
		/* not reached */
		break;
	}
	case PRIVSEP_REQ_CERTFILE: {
		char *fn;
		int fd;

		if (n < 2) {
			ans[0] = PRIVSEP_ANS_INVALID;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
		}
		if (!(fn = malloc(n))) {
			ans[0] = PRIVSEP_ANS_SYS_ERR;
			*((int*)&ans[1]) = errno;
			if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(int),
			                  -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		memcpy(fn, req + 1, n - 1);
		fn[n - 1] = '\0';
		if (privsep_server_certfile_verify(opts, fn) == -1) {
			free(fn);
			ans[0] = PRIVSEP_ANS_DENIED;
			if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		}
		if ((fd = privsep_server_certfile(fn)) == -1) {
			free(fn);
			ans[0] = PRIVSEP_ANS_SYS_ERR;
			*((int*)&ans[1]) = errno;
			if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(int),
			                  -1) == -1) {
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			return 0;
		} else {
			free(fn);
			ans[0] = PRIVSEP_ANS_SUCCESS;
			if (sys_sendmsgfd(srvsock, ans, 1, fd) == -1) {
				close(fd);
				log_err_printf("Sending message failed: %s (%i"
				               ")\n", strerror(errno), errno);
				return -1;
			}
			close(fd);
			return 0;
		}
		/* not reached */
		break;
	}
#ifdef __linux__
	case PRIVSEP_REQ_LX_GET_PID: {
		ans[0] = PRIVSEP_ANS_SUCCESS;
		*(pid_t *)(&ans[1]) = privsep_server_linux_get_pid(
		                (struct sockaddr *)(&req[1]));
		if (sys_sendmsgfd(srvsock, ans, 1 + sizeof(pid_t), -1) == -1) {
			log_err_printf("Sending message failed: %s (%i)\n",
			               strerror(errno), errno);
			return -1;
		}
		return 0;
	}
	case PRIVSEP_REQ_LX_GET_INFO: {
		char *path;
		uid_t uid;
		gid_t gid;
		size_t anssz = 1, plen;

		ans[0] = PRIVSEP_ANS_SUCCESS;
		if ((plen = privsep_server_linux_get_info(
		                *(pid_t *)(&req[1]),
		                &path, &uid, &gid)) != 0) {
			anssz = 1 + sizeof(size_t) + plen + sizeof(uid_t) + sizeof(gid_t);
			*(size_t *)(&ans[1]) = plen;
			memcpy((void *)(ans + 1 + sizeof(size_t)), (void *)path, plen);
			free(path);
			*(uid_t *)(&ans[1 + sizeof(size_t) + plen]) = uid;
			*(gid_t *)(&ans[1 + sizeof(size_t) + plen] + sizeof(gid_t)) = gid;
		} else {
			*(size_t *)(&ans[1]) = 0;
			anssz = 1 + sizeof(size_t);
		}
		if (sys_sendmsgfd(srvsock, ans, anssz, -1) == -1) {
			log_err_printf("Sending message failed: %s (%i)\n",
			               strerror(errno), errno);
			return -1;
		}
		return 0;
	}
#endif /* __linux__ */
	default:
		ans[0] = PRIVSEP_ANS_UNK_CMD;
		if (sys_sendmsgfd(srvsock, ans, 1, -1) == -1) {
			log_err_printf("Sending message failed: %s (%i"
			               ")\n", strerror(errno), errno);
			return -1;
		}
	}
	return 0;
}

/*
 * Privilege separation server (main privileged monitor loop)
 *
 * sigpipe is the self-pipe trick pipe used for communicating signals to
 * the main event loop and break out of select() without race conditions.
 * srvsock[] is a dynamic array of connected privsep server sockets to serve.
 * Caller is responsible for freeing memory after returning, if necessary.
 * childpid is the pid of the child process to forward signals to.
 *
 * Returns 0 on a successful clean exit and -1 on errors.
 */
static int
privsep_server(opts_t *opts, int sigpipe, int srvsock[], size_t nsrvsock,
               pid_t childpid)
{
	int srveof[nsrvsock];
	size_t i = 0;

	for (i = 0; i < nsrvsock; i++) {
		srveof[i] = 0;
	}

	for (;;) {
		fd_set readfds;
		int maxfd, rv;

#ifdef DEBUG_PRIVSEP_SERVER
		log_dbg_printf("privsep_server select()\n");
#endif /* DEBUG_PRIVSEP_SERVER */
		do {
			FD_ZERO(&readfds);
			FD_SET(sigpipe, &readfds);
			maxfd = sigpipe;
			for (i = 0; i < nsrvsock; i++) {
				if (!srveof[i]) {
					FD_SET(srvsock[i], &readfds);
					maxfd = util_max(maxfd, srvsock[i]);
				}
			}
			rv = select(maxfd + 1, &readfds, NULL, NULL, NULL);
#ifdef DEBUG_PRIVSEP_SERVER
			log_dbg_printf("privsep_server woke up (1)\n");
#endif /* DEBUG_PRIVSEP_SERVER */
		} while (rv == -1 && errno == EINTR);
		if (rv == -1) {
			log_err_printf("select() failed: %s (%i)\n",
			               strerror(errno), errno);
			return -1;
		}
#ifdef DEBUG_PRIVSEP_SERVER
		log_dbg_printf("privsep_server woke up (2)\n");
#endif /* DEBUG_PRIVSEP_SERVER */

		if (FD_ISSET(sigpipe, &readfds)) {
			char buf[16];
			ssize_t n;
			/* first drain the signal pipe, then deal with
			 * all the individual signal flags */
			n = read(sigpipe, buf, sizeof(buf));
			if (n == -1) {
				log_err_printf("read(sigpipe) failed:"
				               " %s (%i)\n",
				               strerror(errno), errno);
				return -1;
			}
			if (received_sigquit) {
				if (kill(childpid, SIGQUIT) == -1) {
					log_err_printf("kill(%i,SIGQUIT) "
					               "failed: %s (%i)\n",
					               childpid,
					               strerror(errno), errno);
				}
				received_sigquit = 0;
			}
			if (received_sigterm) {
				if (kill(childpid, SIGTERM) == -1) {
					log_err_printf("kill(%i,SIGTERM) "
					               "failed: %s (%i)\n",
					               childpid,
					               strerror(errno), errno);
				}
				received_sigterm = 0;
			}
			if (received_sighup) {
				if (kill(childpid, SIGHUP) == -1) {
					log_err_printf("kill(%i,SIGHUP) "
					               "failed: %s (%i)\n",
					               childpid,
					               strerror(errno), errno);
				}
				received_sighup = 0;
			}
			if (received_sigusr1) {
				if (kill(childpid, SIGUSR1) == -1) {
					log_err_printf("kill(%i,SIGUSR1) "
					               "failed: %s (%i)\n",
					               childpid,
					               strerror(errno), errno);
				}
				received_sigusr1 = 0;
			}
			if (received_sigint) {
				/* if we don't detach from the TTY, the
				 * child process receives SIGINT directly */
				if (opts->detach) {
					if (kill(childpid, SIGINT) == -1) {
						log_err_printf("kill(%i,SIGINT"
						               ") failed: "
						               "%s (%i)\n",
						               childpid,
						               strerror(errno),
						               errno);
					}
				}
				received_sigint = 0;
			}
			if (received_sigchld) {
				/* break the loop; because we are using
				 * SOCKET_DGRAM we don't get EOF conditions
				 * on the disconnected socket ends here
				 * unless we attempt to write or read, so
				 * we depend on SIGCHLD to notify us of
				 * our child erroring out or crashing */
				break;
			}
		}

		for (i = 0; i < nsrvsock; i++) {
			if (FD_ISSET(srvsock[i], &readfds)) {
				int rv = privsep_server_handle_req(opts,
				                                   srvsock[i]);
				if (rv == -1) {
					log_err_printf("Failed to handle "
					               "privsep req "
					               "on srvsock %i\n",
					               srvsock[i]);
					return -1;
				}
				if (rv == 1) {
#ifdef DEBUG_PRIVSEP_SERVER
					log_dbg_printf("srveof[%zu]=1\n", i);
#endif /* DEBUG_PRIVSEP_SERVER */
					srveof[i] = 1;
				}
			}
		}

		/*
		 * We cannot exit as long as we need the signal handling,
		 * which is as long as the child process is running.
		 * The only way out of here is receiving SIGCHLD.
		 */
	}

	return 0;
}

int
privsep_client_openfile(int clisock, const char *fn, int mkpath)
{
	char ans[PRIVSEP_MAX_ANS_SIZE];
	char req[1 + strlen(fn)];
	int fd = -1;
	ssize_t n;

	if (privsep_fastpath)
		return privsep_server_openfile(fn, mkpath);

	req[0] = mkpath ? PRIVSEP_REQ_OPENFILE_P : PRIVSEP_REQ_OPENFILE;
	memcpy(req + 1, fn, sizeof(req) - 1);

	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		return -1;
	}

	if ((n = sys_recvmsgfd(clisock, ans, sizeof(ans), &fd)) == -1) {
		return -1;
	}

	if (n < 1) {
		errno = EINVAL;
		return -1;
	}

	switch (ans[0]) {
	case PRIVSEP_ANS_SUCCESS:
		break;
	case PRIVSEP_ANS_DENIED:
		errno = EACCES;
		return -1;
	case PRIVSEP_ANS_SYS_ERR:
		if (n < (ssize_t)(1 + sizeof(int))) {
			errno = EINVAL;
			return -1;
		}
		errno = *((int*)&ans[1]);
		return -1;
	case PRIVSEP_ANS_UNK_CMD:
	case PRIVSEP_ANS_INVALID:
	default:
		errno = EINVAL;
		return -1;
	}

	return fd;
}

int
privsep_client_opensock(int clisock, const proxyspec_t *spec)
{
	char ans[PRIVSEP_MAX_ANS_SIZE];
	char req[1 + sizeof(spec)];
	int fd = -1;
	ssize_t n;

	if (privsep_fastpath)
		return privsep_server_opensock(spec);

	req[0] = PRIVSEP_REQ_OPENSOCK;
	*((const proxyspec_t **)&req[1]) = spec;

	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		return -1;
	}

	if ((n = sys_recvmsgfd(clisock, ans, sizeof(ans), &fd)) == -1) {
		return -1;
	}

	if (n < 1) {
		errno = EINVAL;
		return -1;
	}

	switch (ans[0]) {
	case PRIVSEP_ANS_SUCCESS:
		break;
	case PRIVSEP_ANS_DENIED:
		errno = EACCES;
		return -1;
	case PRIVSEP_ANS_SYS_ERR:
		if (n < (ssize_t)(1 + sizeof(int))) {
			errno = EINVAL;
			return -1;
		}
		errno = *((int*)&ans[1]);
		return -1;
	case PRIVSEP_ANS_UNK_CMD:
	case PRIVSEP_ANS_INVALID:
	default:
		errno = EINVAL;
		return -1;
	}

	return fd;
}

int
privsep_client_certfile(int clisock, const char *fn)
{
	char ans[PRIVSEP_MAX_ANS_SIZE];
	char req[1 + strlen(fn)];
	int fd = -1;
	ssize_t n;

	if (privsep_fastpath)
		return privsep_server_certfile(fn);

	req[0] = PRIVSEP_REQ_CERTFILE;
	memcpy(req + 1, fn, sizeof(req) - 1);

	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		return -1;
	}

	if ((n = sys_recvmsgfd(clisock, ans, sizeof(ans), &fd)) == -1) {
		return -1;
	}

	if (n < 1) {
		errno = EINVAL;
		return -1;
	}

	switch (ans[0]) {
	case PRIVSEP_ANS_SUCCESS:
		break;
	case PRIVSEP_ANS_DENIED:
		errno = EACCES;
		return -1;
	case PRIVSEP_ANS_SYS_ERR:
		if (n < (ssize_t)(1 + sizeof(int))) {
			errno = EINVAL;
			return -1;
		}
		errno = *((int*)&ans[1]);
		return -1;
	case PRIVSEP_ANS_UNK_CMD:
	case PRIVSEP_ANS_INVALID:
	default:
		errno = EINVAL;
		return -1;
	}

	return fd;
}

int
privsep_client_close(int clisock)
{
	char req[1];

	req[0] = PRIVSEP_REQ_CLOSE;

	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		close(clisock);
		return -1;
	}

	close(clisock);
	return 0;
}

#ifdef __linux__
pid_t
privsep_client_linux_get_pid(int clisock, struct sockaddr *addr)
{
	char req[sizeof(struct sockaddr_storage) + 1];
	char ans[PRIVSEP_MAX_ANS_SIZE];
	ssize_t n;
	int fd = -1;

	if (privsep_fastpath)
		return privsep_server_linux_get_pid(addr);

	req[0] = PRIVSEP_REQ_LX_GET_PID;
	if (addr->sa_family == AF_INET)
		memcpy(&req[1], addr, sizeof(struct sockaddr_in));
	else if (addr->sa_family == AF_INET6)
		memcpy(&req[1], addr, sizeof(struct sockaddr_in6));
	else
		return -1;

	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		return -1;
	}

	if ((n = sys_recvmsgfd(clisock, ans, sizeof(ans), &fd)) == -1) {
		return -1;
	}

	if (n < 1) {
		errno = EINVAL;
		return -1;
	}

	switch (ans[0]) {
	case PRIVSEP_ANS_SUCCESS:
		return *(pid_t*)(&ans[1]);
	case PRIVSEP_ANS_DENIED:
		errno = EACCES;
		return -1;
	case PRIVSEP_ANS_SYS_ERR:
		if (n < (ssize_t)(1 + sizeof(int))) {
			errno = EINVAL;
			return -1;
		}
		errno = *((int*)&ans[1]);
		return -1;
	case PRIVSEP_ANS_UNK_CMD:
	case PRIVSEP_ANS_INVALID:
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

char *
privsep_client_linux_get_info(int clisock, pid_t pid, uid_t *uid, gid_t *gid)
{
	char req[sizeof(pid_t) + 1];
	char ans[PRIVSEP_MAX_ANS_SIZE];
	size_t plen;
	char *exe;
	ssize_t n;
	int fd = -1;

	if (privsep_fastpath) {
		plen = privsep_server_linux_get_info(pid, &exe, uid, gid);
		return exe;
	}

	req[0] = PRIVSEP_REQ_LX_GET_INFO;
	*(pid_t *)(&req[1]) = pid;
	if (sys_sendmsgfd(clisock, req, sizeof(req), -1) == -1) {
		return NULL;
	}

	if ((n = sys_recvmsgfd(clisock, ans, sizeof(ans), &fd)) == -1) {
		return NULL;
	}

	if (n < 1) {
		errno = EINVAL;
		return NULL;
	}

	switch (ans[0]) {
	case PRIVSEP_ANS_SUCCESS:
		plen = *(size_t *)(&ans[1]);
		exe = malloc(plen + 1);
		if (exe != NULL) {
			memcpy((void *)exe, (void *)(ans + 1 + sizeof(size_t)), plen);
			exe[plen] = 0;
			*uid = *(uid_t *)(&ans[1 + sizeof(size_t) + plen]);
			*gid = *(gid_t *)(&ans[1 + sizeof(size_t) + sizeof(uid_t) + plen]);
			return exe;
		}
		errno = ENOMEM;
		return NULL;
	case PRIVSEP_ANS_DENIED:
		errno = EACCES;
		return NULL;
	case PRIVSEP_ANS_SYS_ERR:
		if (n < (ssize_t)(1 + sizeof(int))) {
			errno = EINVAL;
			return NULL;
		}
		errno = *((int*)&ans[1]);
		return NULL;
	case PRIVSEP_ANS_UNK_CMD:
	case PRIVSEP_ANS_INVALID:
	default:
		errno = EINVAL;
		return NULL;
	}

	return 0;
}
#endif /* __linux__ */

/*
 * Fork and set up privilege separated monitor process.
 * Returns -1 on error before forking, 1 as parent, or 0 as child.
 * The array of clisock's will get filled with nclisock privsep client
 * sockets only for the child; on error and in the parent process it
 * will not be touched.
 */
int
privsep_fork(opts_t *opts, int clisock[], size_t nclisock)
{
	int selfpipev[2]; /* self-pipe trick: signal handler -> select */
	int chldpipev[2]; /* el cheapo interprocess sync early after fork */
	int sockcliv[nclisock][2];
	pid_t pid;

	if (!opts->dropuser) {
		log_dbg_printf("Not dropping privileges: "
		               "privsep fastpath enabled\n");
		privsep_fastpath = 1;
	} else {
		privsep_fastpath = 0;
	}

	received_sigquit = 0;
	received_sighup = 0;
	received_sigint = 0;
	received_sigchld = 0;
	received_sigusr1 = 0;

	if (pipe(selfpipev) == -1) {
		log_err_printf("Failed to create self-pipe: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	log_dbg_printf("Created self-pipe [r=%i,w=%i]\n",
	               selfpipev[0], selfpipev[1]);

	if (pipe(chldpipev) == -1) {
		log_err_printf("Failed to create chld-pipe: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	log_dbg_printf("Created chld-pipe [r=%i,w=%i]\n",
	               chldpipev[0], chldpipev[1]);

	for (size_t i = 0; i < nclisock; i++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockcliv[i]) == -1) {
			log_err_printf("Failed to create socket pair %zu: "
			               "%s (%i)\n", i, strerror(errno), errno);
			return -1;
		}
		log_dbg_printf("Created socketpair %zu [p=%i,c=%i]\n",
		               i, sockcliv[i][0], sockcliv[i][1]);
	}

	log_dbg_printf("Privsep parent pid %i\n", getpid());
	pid = fork();
	if (pid == -1) {
		log_err_printf("Failed to fork: %s (%i)\n",
		               strerror(errno), errno);
		close(selfpipev[0]);
		close(selfpipev[1]);
		close(chldpipev[0]);
		close(chldpipev[1]);
		for (size_t i = 0; i < nclisock; i++) {
			close(sockcliv[i][0]);
			close(sockcliv[i][1]);
		}
		return -1;
	} else if (pid == 0) {
		/* child */
		close(selfpipev[0]);
		close(selfpipev[1]);
		for (size_t i = 0; i < nclisock; i++)
			close(sockcliv[i][0]);
		/* wait until parent has installed signal handlers,
		 * intentionally ignoring errors */
		char buf[1];
		ssize_t n;
		close(chldpipev[1]);
		do {
			n = read(chldpipev[0], buf, sizeof(buf));
		} while (n == -1 && errno == EINTR);
		close(chldpipev[0]);
		log_dbg_printf("Privsep child pid %i\n", getpid());
		/* return the privsep client sockets */
		for (size_t i = 0; i < nclisock; i++)
			clisock[i] = sockcliv[i][1];
		return 0;
	}
	/* parent */
	for (size_t i = 0; i < nclisock; i++)
		close(sockcliv[i][1]);
	selfpipe_wrfd = selfpipev[1];

	/* close file descriptors opened by preinit's only needed in client;
	 * we still call the preinit's before forking in order to provide
	 * better user feedback and less privsep complexity */
	nat_preinit_undo();
	log_preinit_undo();

	/* If the child exits before the parent installs the signal handler
	 * here, we have a race condition; this is solved by the client
	 * blocking on the reading end of a pipe (chldpipev[0]). */
	if (signal(SIGHUP, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGHUP handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (signal(SIGINT, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGINT handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (signal(SIGTERM, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGTERM handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (signal(SIGQUIT, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGQUIT handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (signal(SIGUSR1, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGUSR1 handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}
	if (signal(SIGCHLD, privsep_server_signal_handler) == SIG_ERR) {
		log_err_printf("Failed to install SIGCHLD handler: %s (%i)\n",
		               strerror(errno), errno);
		return -1;
	}

	/* unblock the child */
	close(chldpipev[0]);
	close(chldpipev[1]);

	int socksrv[nclisock];
	for (size_t i = 0; i < nclisock; i++)
		socksrv[i] = sockcliv[i][0];
	if (privsep_server(opts, selfpipev[0], socksrv, nclisock, pid) == -1) {
		log_err_printf("Privsep server failed: %s (%i)\n",
		               strerror(errno), errno);
		/* fall through */
	}
#ifdef DEBUG_PRIVSEP_SERVER
	log_dbg_printf("privsep_server exited\n");
#endif /* DEBUG_PRIVSEP_SERVER */

	for (size_t i = 0; i < nclisock; i++)
		close(sockcliv[i][0]);
	selfpipe_wrfd = -1; /* tell signal handler not to write anymore */
	close(selfpipev[0]);
	close(selfpipev[1]);

	int status;
	wait(&status);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			log_err_printf("Child proc %lld exited with status %d\n",
			               (long long)pid, WEXITSTATUS(status));
		} else {
			log_dbg_printf("Child proc %lld exited with status %d\n",
			               (long long)pid, WEXITSTATUS(status));
		}
	} else if (WIFSIGNALED(status)) {
		log_err_printf("Child proc %lld killed by signal %d\n",
		               (long long)pid, WTERMSIG(status));
	} else {
		log_err_printf("Child proc %lld neither exited nor killed\n",
		               (long long)pid);
	}

	return 1;
}

/* vim: set noet ft=c: */



