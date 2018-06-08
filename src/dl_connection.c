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

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#include <stdbool.h>
#include <strings.h>
#endif

#include "dl_assert.h"
#include "dl_connection.h"
#include "dl_memory.h"
#include "dl_utils.h"

typedef enum dl_connection_state {
	DLC_INITIAL,
	DLC_ESTABLISHING,
	DLC_CONNECTED,
	DLC_DISCONNECTED} dl_connection_state;

struct dl_connection {
	struct dl_transport *dlc_transport;
	dl_connection_state dlc_state;
};

static void dl_connection_connected(struct dl_connection *);
static void dl_connection_disconnected(struct dl_connection *);
static void dl_connection_establishing(struct dl_connection *);

void dl_connection_connected(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	self->dlc_state = DLC_CONNECTED;
	DLOGTR0(PRIO_LOW, "Connection state = CONNECTED\n");
}

void dl_connection_disconnected(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	self->dlc_state = DLC_DISCONNECTED;
	DLOGTR0(PRIO_LOW, "Connection state = DISCONNECTED\n");
}

void dl_connection_establishing(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	self->dlc_state = DLC_ESTABLISHING;
	DLOGTR0(PRIO_LOW, "Connection state = ESTABLISHING\n");

	if (0 == dl_transport_connect(self->dlc_transport, "192.168.100.11", 9092))
	    dl_connection_up(self);
	else
	    dl_connection_down(self);
}

void
dl_connection_down(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	switch (self->dlc_state) {
	case DLC_ESTABLISHING:
		/* FALLTHROUGH */	
	case DLC_CONNECTED:
		dl_connection_disconnected(self);
		break;
	case DLC_DISCONNECTED:
		/* Ignore */
		break;
	default:
		DL_ASSERT(0, ("Connection state is invalid"));
	}
}

void
dl_connection_up(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	switch (self->dlc_state) {
	case DLC_ESTABLISHING:
		dl_connection_connected(self);
		break;
	case DLC_CONNECTED:
		/* Ignore */
		break;
	case DLC_DISCONNECTED:
		break;
	default:
		DL_ASSERT(0, ("Connection state is invalid"));
	}
}

void
dl_connection_recon_timeout(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	switch (self->dlc_state) {
	case DLC_ESTABLISHING:
	case DLC_CONNECTED:
		/* Ignore */
		break;
	case DLC_DISCONNECTED:
		dl_connection_establishing(self);
		break;
	default:
		DL_ASSERT(0, ("Connection state is invalid"));
	}

}

int dl_connection_new(struct dl_connection **self,
    struct dl_transport *transport, char const * const hostname, const int port)
{
	struct dl_connection *conn;

	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));
	DL_ASSERT(transport != NULL, ("Transport instance cannot be NULL"));

	conn = (struct dl_connection *) dlog_alloc(
	    sizeof(struct dl_connection));
#ifdef _KERNEL
	DL_ASSERT(conn != NULL, ("Failed allocating Connection instance"));
#else
	if (conn == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed allocating Connection instance\n");
		return -1;
	}
#endif
	bzero(conn, sizeof(struct dl_connection));
	conn->dlc_transport = transport;
	conn->dlc_state = DLC_INITIAL;

	*self = conn;

	/* Synchornously create in the establishing state. */
	dl_connection_establishing(*self);
	return 0;
}

void
dl_connection_delete(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	/* Bring the connection down. */
	dl_connection_down(self);
	dlog_free(self);
}

struct dl_transport *
dl_connection_get_transport(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	return self->dlc_transport;
}

bool
dl_connection_is_establlished(struct dl_connection *self)
{
	DL_ASSERT(self != NULL, ("Connection instance cannot be NULL"));

	return self->dlc_state == DLC_CONNECTED;
}
