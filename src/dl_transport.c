/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef _KERNEL
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/sbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <strings.h>
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_transport.h"
#include "dl_utils.h"

struct dl_transport {
	int dlt_fd;
};

int
dl_transport_new(struct dl_transport **self)
{
	struct dl_transport *transport;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
       
	transport = (struct dl_transport *) dlog_alloc(
	    sizeof(struct dl_transport));
#ifdef _KERNEL
	DL_ASSERT(transport != NULL ,
	    ("Failed to allocate transport instance"));
#else
	if (transport == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed to allocate transport instance\n");
		return -1;
	}
#endif
	bzero(transport, sizeof(struct dl_transport));
#ifdef _KERNEL
	transport->dlt_fd = NULL;
#else
	transport->dlt_fd = -1;
#endif

	*self = transport;
	return 0;
}

void dl_transport_delete(struct dl_transport *self)
{
	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));

	// Disconnect and free?
	dlog_free(self);
}

int
dl_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnumber)
{
	struct sockaddr_in dest;
	int rc;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

#ifdef _KERNEL
	struct thread *td = curthread;

 	rc = socreate(AF_INET, &self->dlt_fd, SOCK_STREAM, IPPROTO_TCP,
	    td->td_ucred, td);
	DLOGTR1(PRIO_LOW, "socreate = %d\n", rc);
	// TODO: error checking

	dest.sin_len = sizeof(struct sockaddr_in);	
	//dest.sin_addr.s_addr = htonl((((((127 << 8) | 0) << 8) | 0) << 8) | 1);
	dest.sin_addr.s_addr = htonl((((((192 << 8) | 168) << 8) | 100) << 8) | 11);
	rc = soconnect(self->dlt_fd, (struct sockaddr *) &dest, td);
	DLOGTR1(PRIO_LOW, "soconnect = %d\n", rc);
	// TODO: error checking
#else
	self->dlt_fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (self->dlt_fd == -1)
		return -1;

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;

	rc = connect(self->dlt_fd, (struct sockaddr *) &dest, sizeof(dest));
#endif
	return rc;
}

int
dl_transport_read_msg(struct dl_transport *self, struct dl_bbuf **target)
{
	char *buffer;
	int ret, total = 0;
	int32_t msg_size;
	
	DL_ASSERT(self != NULL, "Transport instance cannot be NULL");
	DL_ASSERT(self != NULL, "Target buffer  cannot be NULL");

	/* Read the size of the request or response to process. */
#ifdef _KERNEL
	struct thread *td = curthread;
	struct iovec iov[1];
	struct uio u;

	iov[0].iov_base = &msg_size;
	iov[0].iov_len = sizeof(int32_t);

	bzero(&u, sizeof(struct uio));
	u.uio_iov = iov;
	u.uio_iovcnt = 1;
	u.uio_offset = 0;
        u.uio_resid = sizeof(int32_t);
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_READ;
        u.uio_td = td;

	ret = soreceive(self->dlt_fd, NULL, &u, NULL, NULL, NULL);
#else
	ret = recv(self->dlt_fd, &msg_size, sizeof(int32_t), 0);
#endif
	msg_size = be32toh(msg_size);
	DLOGTR2(PRIO_LOW, "Read %d bytes (%d)...\n", ret, msg_size);
	if (ret == 0) {
		/* Peer has closed connection */
	} else if (ret > 0) {
		DLOGTR1(PRIO_LOW, "\tNumber of bytes: %d\n", msg_size);

		buffer = dlog_alloc(sizeof(char) * msg_size);
		// TODO: error handling
		dl_bbuf_new(target, NULL, msg_size,
			DL_BBUF_FIXEDLEN | DL_BBUF_BIGENDIAN);

		while (total < msg_size) {
#ifdef _KERNEL
			iov[0].iov_base = buffer;
			iov[0].iov_len = msg_size-total;

			bzero(&u, sizeof(struct uio));
			u.uio_iov = iov;
			u.uio_iovcnt = 1;
			u.uio_offset = 0;
			u.uio_resid = sizeof(int32_t);
			u.uio_segflg  = UIO_SYSSPACE;
			u.uio_rw = UIO_READ;
			u.uio_td = td;

			total += ret = soreceive(self->dlt_fd, NULL, &u,
			    NULL, NULL, NULL);
#else
			total += ret = recv(self->dlt_fd, buffer,
				msg_size-total, 0);
#endif
			DLOGTR2(PRIO_LOW,
			    "\tRead %d characters; expected %d\n",
			    ret, msg_size);
			dl_bbuf_bcat(*target, buffer, ret);
		}
		dlog_free(buffer);

		return 0;
	} else {
		return -1;
	}
	return -1;
}

int
dl_transport_send_request(const struct dl_transport *self,
    const struct dl_bbuf *buffer)
{
	struct iovec iov[2];
	int32_t buflen;

	DL_ASSERT(self != NULL, "Transport instance cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer to send cannot be NULL");

	buflen = htobe32(dl_bbuf_pos(buffer));

	iov[0].iov_base = &buflen;
	iov[0].iov_len = sizeof(int32_t);

	iov[1].iov_base = dl_bbuf_data(buffer);
	iov[1].iov_len = dl_bbuf_pos(buffer);

#ifdef _KERNEL
	struct thread *td = curthread;
	struct uio u;

	bzero(&u, sizeof(struct uio));
	u.uio_iov = iov;
	u.uio_iovcnt = 2;
	u.uio_offset = 0;
        u.uio_resid = iov[0].iov_len + iov[1].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	return sosend(self->dlt_fd, NULL, &u, NULL, NULL, 0, td);
#else
	return writev(self->dlt_fd, iov, 2);
#endif
}

int
dl_transport_poll(const struct dl_transport *self, int events, int timeout)
{
#ifdef _KERNEL
	struct thread *td = curthread;
#else
	struct pollfd ufd;

	ufd.fd = self->dlt_fd;
	ufd.events = events;
#endif

	DL_ASSERT(self != NULL, "Transport instance cannot be NULL");

#ifdef _KERNEL
	return sopoll(self->dlt_fd, events, td->td_ucred, td);
#else
	return poll(&ufd, 1, timeout);
#endif
}

int
dl_transport_get_fd(struct dl_transport *self)
{
	return self->dlt_fd;
}
