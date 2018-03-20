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
#include <sys/sbuf.h>
#else
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <strings.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_transport.h"
#include "dl_utils.h"

int
dl_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnumber)
{
	struct sockaddr_in dest;
	int sockfd = -1;

	DL_ASSERT(self != NULL, "Transport instance cannot be NULL\n");

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

#ifdef _KERNEL
	struct thread *td = curthread;

 	socreate(AF_INET, &transport->dlt_sock, SOCK_STREAM, IPPROTO_TCP, td->td_ucred, td);
	// TODO: error checking
	
	// soconnect(int dom, struct socket **aso, int	type, int proto,
	// 	 struct	ucred *cred, struct thread *td);
	// TODO: error checking
#else
	self->dlt_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (self->dlt_sock == -1)
		return -1;

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;

	if (connect(self->dlt_sock, (struct sockaddr *) &dest,
	    sizeof(dest)) < 0)
		return -3;
#endif
	return sockfd;
}

int
dl_transport_read_msg(struct dl_transport *self, struct dl_bbuf **target)
{
	struct dl_request_or_response *req_or_res;
	int ret, total = 0;
	int32_t msg_size;
	
	DL_ASSERT(self != NULL, "Transport instance cannot be NULL");
	DL_ASSERT(self != NULL, "Target buffer  cannot be NULL");

	/* Read the size of the request or response to process. */
#ifdef _KERNEL
	//soreceive
#else
	ret = recv(self->dlt_sock, &msg_size, sizeof(int32_t), 0);
	msg_size = be32toh(msg_size);
#endif
	DLOGTR2(PRIO_LOW, "Read %d bytes (%p)...\n", ret, msg_size);
	if (ret == 0) {
		/* Peer has closed connection */
	} else if (ret > 0) {
		DLOGTR1(PRIO_LOW, "\tNumber of bytes: %d\n", msg_size);

		char *buffer = dlog_alloc(sizeof(char) * msg_size);
		dl_bbuf_new(target, NULL, msg_size,
			DL_BBUF_FIXEDLEN | DL_BBUF_BIGENDIAN);

		while (total < msg_size) {
			total += ret = recv(self->dlt_sock, buffer,
				msg_size-total, 0);
			DLOGTR2(PRIO_LOW,
				"\tRead %d characters; expected %d\n",
				ret, msg_size);
			dl_bbuf_bcat(*target, buffer, ret);
		}
		dlog_free(buffer);

		for (int b = 0; b < msg_size; b++) {
			DLOGTR1(PRIO_LOW, "<0x%02hhX>", buffer[b]);
		}
		DLOGTR0(PRIO_LOW, "\n");

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
	struct uio *u;

	bzero(&u, sizeof(struct uio));
	u.uio_iov = iov;
	u.uio_iovcnt = 2;
	u.uio_offset = 0;
        u.uio_resid = iov[0].iov_len + iov[1].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	return sosend(self->dlt_sock, NULL, u, NULL, NULL, 0, td);
#else
	return writev(self->dlt_sock, iov, 2);
#endif
}

int
dl_transport_poll(const struct dl_transport *self, int timeout)
{
#ifdef _KERNEL
#else
	struct pollfd ufd;
#endif

	DL_ASSERT(self != NULL, "Transport instance cannot be NULL");

#ifdef _KERNEL
	//return sopoll(struct socket *so, int events, struct ucred
	//*active_cred, structthread *td);
#else
	ufd.fd = self->dlt_sock;
	ufd.events = POLLIN;

	return poll(&ufd, 1, timeout);
#endif
}
