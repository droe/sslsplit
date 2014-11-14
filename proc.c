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

#include "proc.h"

#include "log.h"
#include "attrib.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_DARWIN_LIBPROC
#include <libproc.h>
#endif /* HAVE_DARWIN_LIBPROC */


/*
 * Local process lookup.
 */

#ifdef HAVE_DARWIN_LIBPROC
int
proc_pid_for_addr(pid_t *result, struct sockaddr *dst_addr,
                  UNUSED socklen_t dst_addrlen)
{
	pid_t *pids = NULL;
	struct proc_fdinfo *fds = NULL;
	int ret = -1;

	/* default result if no pid matches */
	*result = -1;

	/* iterate over all pids to find a matching socket */
	int pid_count = proc_listallpids(NULL, 0);
	pids = malloc(sizeof(pid_t) * pid_count);
	if (!pids) {
		goto errout1;
	}

	pid_count = proc_listallpids(pids, sizeof(pid_t) * pid_count);

	for (int i = 0; i < pid_count; i++) {
		pid_t pid = pids[i];

		/* fetch fd info for this pid */
		int fd_count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
		if (fd_count == -1) {
			/* failed to fetch pidinfo; process may have exited */
			continue;
		}

		if (fds) {
			free(fds);
		}
		fds = malloc(PROC_PIDLISTFD_SIZE * fd_count);
		if (!fds) {
			goto errout2;
		}
		fd_count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds,
		                        sizeof(fds[0]) * fd_count);

		/* look for a matching socket file descriptor */
		for (int j = 0; j < fd_count; j++) {
			struct proc_fdinfo *fd = &fds[j];
			struct socket_fdinfo sinfo;

			if (fd->proc_fdtype != PROX_FDTYPE_SOCKET) {
				continue;
			}

			if (proc_pidfdinfo(pid, fd->proc_fd, PROC_PIDFDSOCKETINFO,
			                   &sinfo,
			                   sizeof(struct socket_fdinfo)) == -1) {
				/* process may have exited or socket may have
				 * been released. */
				continue;
			}

			if (sinfo.psi.soi_kind != SOCKINFO_TCP) {
				continue;
			}

			uint16_t sock_fport = sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport;
			if (sinfo.psi.soi_family == AF_INET &&
			    dst_addr->sa_family == AF_INET) {
				struct sockaddr_in *dst_sai = (struct sockaddr_in *)dst_addr;
				if (dst_sai->sin_addr.s_addr != sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr) {
					continue;
				}

				if (dst_sai->sin_port != sock_fport) {
					continue;
				}
			} else if (sinfo.psi.soi_family == AF_INET6 &&
			           dst_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *dst_sai = (struct sockaddr_in6 *)dst_addr;
				if (memcmp(dst_sai->sin6_addr.s6_addr,  sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6.s6_addr, 16) != 0) {
					continue;
				}

				if (dst_sai->sin6_port != sock_fport) {
					continue;
				}
			}

			/* valid match */
			*result = pid;
			break;
		}
	}

	ret = 0;
	free(fds);
errout2:
	free(pids);
errout1:
	return ret;
}
#else /* !HAVE_DARWIN_LIBPROC */
int
proc_pid_for_addr(pid_t *result, UNUSED struct sockaddr *dst_addr,
                    UNUSED socklen_t dst_addrlen) {
	*result = -1;
	return 0;
}
#endif /* !HAVE_DARWIN_LIBPROC */


/*
 * Fetch process info for the given pid.
 * On success, returns 0 and fills in path, uid, and gid.
 * Caller must free returned path string.
 * Returns -1 on failure, or if unsupported on this platform.
 */
#if HAVE_DARWIN_LIBPROC
int
proc_get_info(pid_t pid, char **path, uid_t *uid, gid_t *gid) {
	/* fetch process structure */
	struct proc_bsdinfo bsd_info;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info,
	                 sizeof(bsd_info)) == -1) {
		return -1;
	}

	*uid = bsd_info.pbi_uid;
	*gid = bsd_info.pbi_gid;

	/* fetch process path */
	*path = malloc(PROC_PIDPATHINFO_MAXSIZE);
	if (!*path) {
		return -1;
	}
	int path_len = proc_pidpath(pid, *path, PROC_PIDPATHINFO_MAXSIZE);
	if (path_len == -1) {
		free(*path);
		return -1;
	}

	return 0;
}
#else /* !HAVE_DARWIN_LIBPROC */
int
proc_get_info(UNUSED pid_t pid, UNUSED char **path,
              UNUSED uid_t *uid, UNUSED gid_t *gid) {
	/* unsupported */
	return -1;
}
#endif /* !HAVE_DARWIN_LIBPROC */


/* vim: set noet ft=c: */
