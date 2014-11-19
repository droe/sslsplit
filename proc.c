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

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/user.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>
#endif /* __FreeBSD__ */

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


#ifdef __FreeBSD__

/*
 * Get the list of open files from the kernel and do basic consistency checks.
 * If successful, returns 0, and *pxfiles will receive a pointer to the
 * received xfiles structure and *pnxfiles the number of file records in it.
 * If unsuccessful, returns -1 and *pxfiles will be NULL.
 * Caller is responsible to free() *pxfiles after use.
 */
static int
proc_freebsd_getfiles(struct xfile **pxfiles, int *pnxfiles)
{
	int mib[4];
	size_t sz;

	mib[0] = CTL_KERN;
	mib[1] = KERN_FILE;
	mib[2] = mib[3] = 0;

	for (;;) {
		if (sysctl(mib, 2, NULL, &sz, NULL, 0) < 0) {
			*pxfiles = NULL;
			return -1;
		}
		if (!(*pxfiles = malloc(sz))) {
			return -1;
		}
		if (sysctl(mib, 2, *pxfiles, &sz, NULL, 0) < 0) {
			free(*pxfiles);
			if (errno == ENOMEM)
				continue;
			*pxfiles = NULL;
			return -1;
		}
		break;
	}

	if (sz > 0 && (*pxfiles)->xf_size != sizeof **pxfiles) {
		log_err_printf("struct xfile size mismatch\n");
		return -1;
	}
	*pnxfiles = sz / sizeof **pxfiles;

	return 0;
}

/*
 * Get the list of active TCP connections and do basic consistency checks.
 * If successful, returns 0, and *pxig will receive a pointer to the
 * received data structure, *pexig a pointer to the end of the buffer.
 * If unsuccessful, returns -1 and *pxig will be NULL.
 * Caller is responsible to free() *pxig after use.
 */
static int
proc_freebsd_gettcppcblist(struct xinpgen **pxig, struct xinpgen **pexig)
{
	int mib[4];
	size_t sz;
	int retry = 5;

	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = IPPROTO_TCP;
	mib[3] = TCPCTL_PCBLIST;
	do {
		for (;;) {
			if (sysctl(mib, 4, NULL, &sz, NULL, 0) < 0) {
				*pxig = NULL;
				return -1;
			}
			if (!(*pxig = malloc(sz))) {
				return -1;
			}
			if (sysctl(mib, 4, *pxig, &sz, NULL, 0) < 0) {
				free(*pxig);
				if (errno == ENOMEM)
					continue;
				*pxig = NULL;
				return -1;
			}
			break;
		}

		*pexig = (struct xinpgen *)(void *)
		         ((char *)(*pxig) + sz - sizeof(**pexig));
		if ((*pxig)->xig_len != sizeof(**pxig) ||
		    (*pexig)->xig_len != sizeof(**pexig)) {
			log_err_printf("struct xinpgen size mismatch\n");
			free(*pxig);
			*pxig = NULL;
			return -1;
		}
	} while ((*pxig)->xig_gen != (*pexig)->xig_gen && retry--);

	/* check if first and last record are from same generation */
	if ((*pxig)->xig_gen != (*pexig)->xig_gen) {
		log_err_printf("Warning: data inconsistent "
		               "(xig->xig_gen != exig->xig_gen)\n");
	}

	return 0;
}

int
proc_freebsd_pid_for_addr(pid_t *result, struct sockaddr *src_addr,
                          UNUSED socklen_t src_addrlen)
{
	struct xfile *xfiles;
	int nxfiles;
	struct xfile *xf;

	struct xinpgen *xig, *exig, *txig;
	struct xtcpcb *xtp;
	struct inpcb *inp;
	struct xsocket *so;

	if (proc_freebsd_getfiles(&xfiles, &nxfiles) == -1) {
		return -1;
	}

	if (proc_freebsd_gettcppcblist(&xig, &exig) == -1) {
		free(xfiles);
		return -1;
	}

	for (txig = (struct xinpgen *)(void *)((char *)xig + xig->xig_len);
	     txig < exig;
	     txig = (struct xinpgen *)(void *)((char *)txig + txig->xig_len)) {
		xtp = (struct xtcpcb *)txig;
		if (xtp->xt_len != sizeof *xtp) {
			free(xfiles);
			free(xig);
			return -1;
		}
		inp = &xtp->xt_inp;
		so = &xtp->xt_socket;

		if (!(so->so_state & SS_ISCONNECTED))
			/* we are only interested in connected sockets */
			continue;

		if ((inp->inp_vflag & INP_IPV4) &&
		    (src_addr->sa_family == AF_INET)) {
			struct sockaddr_in *src_sai =
					(struct sockaddr_in *)src_addr;

			if (src_sai->sin_addr.s_addr != inp->inp_laddr.s_addr) {
				continue;
			}

			if (src_sai->sin_port != inp->inp_lport) {
				continue;
			}
		} else if ((inp->inp_vflag & INP_IPV6) &&
		          (src_addr->sa_family == AF_INET6)) {
			struct sockaddr_in6 *src_sai =
					(struct sockaddr_in6 *)src_addr;

			if (memcmp(src_sai->sin6_addr.s6_addr, inp->in6p_laddr.s6_addr, 16) != 0) {
				continue;
			}

			if (src_sai->sin6_port != inp->inp_lport) {
				continue;
			}
		} else {
			/* other address family */
			continue;
		}

		/* valid match */

		/* only do this if we have a match */
		xf = NULL;
		for (int i = 0; i < nxfiles; ++i) {
			if (so->xso_so == xfiles[i].xf_data) {
				/* there can be several processes sharing a
				 * connected socket file descriptor */
				xf = &xfiles[i];
			}
		}
		if (!xf)
			continue;
		*result = xf->xf_pid;
		break;
	}

	free(xfiles);
	free(xig);
	return 0;
}

int
proc_freebsd_get_info(pid_t pid, char **path, uid_t *uid, gid_t *gid) {
	static struct kinfo_proc proc;
	size_t len;
	int mib[4];
	char buf[PATH_MAX + 1];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = (int)pid;
	len = sizeof(buf);
	if (sysctl(mib, 4, buf, &len, NULL, 0) == -1) {
		if (errno != ESRCH) {
			log_err_printf("Failed to get proc pathname: %s (%i)",
			               strerror(errno), errno);
		}
		*path = NULL;
	} else {
		*path = strdup(buf);
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = (int)pid;
	len = sizeof proc;
	if (sysctl(mib, 4, &proc, &len, NULL, 0) == -1) {
		if (errno != ESRCH) {
			log_err_printf("Failed to get proc info: %s (%i)",
			               strerror(errno), errno);
		}
		*uid = -1;
		*gid = -1;
	} else {
		if (*path == NULL)
			*path = strdup(proc.ki_comm);
		*uid = proc.ki_uid;
		*gid = proc.ki_groups[0];
	}

	return 0;
}

#endif /* __FreeBSD__ */


#ifdef HAVE_DARWIN_LIBPROC

int
proc_darwin_pid_for_addr(pid_t *result, struct sockaddr *src_addr,
                         UNUSED socklen_t src_addrlen)
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

			if (proc_pidfdinfo(pid, fd->proc_fd,
			                   PROC_PIDFDSOCKETINFO,
			                   &sinfo,
			                   sizeof(struct socket_fdinfo)) == -1) {
				/* process may have exited or socket may have
				 * been released. */
				continue;
			}

			if (sinfo.psi.soi_kind != SOCKINFO_TCP) {
				continue;
			}

			uint16_t sock_lport = sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
			if (sinfo.psi.soi_family == AF_INET &&
			    src_addr->sa_family == AF_INET) {
				struct sockaddr_in *src_sai = (struct sockaddr_in *)src_addr;

				if (src_sai->sin_addr.s_addr != sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr) {
					continue;
				}

				if (src_sai->sin_port != sock_lport) {
					continue;
				}
			} else if (sinfo.psi.soi_family == AF_INET6 &&
			           src_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *src_sai = (struct sockaddr_in6 *)src_addr;

				if (memcmp(src_sai->sin6_addr.s6_addr, sinfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6.s6_addr, 16) != 0) {
					continue;
				}

				if (src_sai->sin6_port != sock_lport) {
					continue;
				}
			} else {
				/* other address family */
				continue;
			}

			/* valid match */
			*result = pid;
			goto success;
		}
	}

success:
	ret = 0;
	free(fds);
errout2:
	free(pids);
errout1:
	return ret;
}

/*
 * Fetch process info for the given pid.
 * On success, returns 0 and fills in path, uid, and gid.
 * Caller must free returned path string.
 * Returns -1 on failure, or if unsupported on this platform.
 */
int
proc_darwin_get_info(pid_t pid, char **path, uid_t *uid, gid_t *gid) {
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

#endif /* HAVE_DARWIN_LIBPROC */

/* vim: set noet ft=c: */



