/*-
 * Copyright (c) 2017 (Graeme Jenkinson)
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
#include <netinet/ip.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_protocol_parser.h"
#include "dl_transport.h"
#include "dl_utils.h"

int
dl_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnumber)
{
	struct sockaddr_in dest;
	int sockfd;

	DL_ASSERT(self != NULL, "Transport cannot be NULL\n");

 	// socreate(int dom, struct socket **aso, int	type, int proto,
     	// struct	ucred *cred, struct thread *td);
	if ((self->dlt_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;

#ifdef _KERNEL
	// socreate(int dom, struct socket **aso, int	type, int proto,
	// 	 struct	ucred *cred, struct thread *td);
#else
	if (connect(self->dlt_sock, (struct sockaddr *) &dest,
	    sizeof(dest)) != 0)
		return -3;
#endif

	return sockfd;
}

int
dl_transport_read_msg(struct dl_transport *self, char *saveto)
{
	char *buffer = saveto;
	struct dl_request_or_response req_or_res;
	int ret;
	int total = 0;

	/* Read the size of the request or response to process. */
#ifdef _KERNEL
	//soreceive
#else
	ret = recv(self->dlt_sock, buffer, sizeof(req_or_res.dlrx_size), 0);
#endif
	debug(PRIO_LOW, "Read %d bytes (%s)...\n", ret, buffer);
	if (ret == 0) {
		/* Peer has closed connection */
	} else if (ret > 0) {
		if (dl_decode_request_or_response(&req_or_res, buffer)) {
			debug(PRIO_LOW, "\tNumber of bytes: %d\n",
			    req_or_res.dlrx_size);

			buffer += sizeof(int32_t);

			while (total < req_or_res.dlrx_size) {
				ret = recv(self->dlt_sock, &buffer[total], req_or_res.dlrx_size-total, 0);
				debug(PRIO_LOW, "\tRead %d characters; expected %d\n",
				ret, req_or_res.dlrx_size);
				total += ret;
			}

			for (int b = 0; b < req_or_res.dlrx_size; b++) {
				printf("0x%02X\n", buffer[b]);
			}

			return ret;
		}
	} else {
		return -1;
	}
}

int
dl_transport_send_request(const struct dl_transport *self,
    const struct dl_request *request)
{
	int nbytes_sent = 0, nbytes_to_send;
	char *buffer;
	
	DL_ASSERT(self != NULL, "Transport cannot be NULL");
	DL_ASSERT(request != NULL, "Request cannot be NULL");

	buffer = (char *) distlog_alloc((sizeof(char) * MTU));
	if (buffer != NULL) {

		nbytes_to_send = dl_encode_request(request, buffer);
		DISTLOGTR1(PRIO_NORMAL, "Sending request: %d bytes\n",
		    nbytes_to_send);
#ifdef _KERNEL
		// sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
		// 	 struct	mbuf *top, struct mbuf *control, int flags,
		// 	 	 struct	thread *td);
#else
		nbytes_sent = send(self->dlt_sock, buffer, nbytes_to_send, 0);
#endif
		distlog_free(buffer);
	}
	return nbytes_sent;
}

int
dl_transport_poll(const struct dl_transport *self, int timeout)
{
	struct pollfd ufd;

	ufd.fd = self->dlt_sock;
	ufd.events = POLLIN;

#ifdef _KERNEL
	//rv = sopoll(struct socket *so, int events, struct ucred
	//*active_cred, structthread *td);
#else
	return poll(&ufd, 1, timeout);
#endif
}

