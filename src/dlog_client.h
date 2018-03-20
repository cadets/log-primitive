/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DLOG_CLIENT_H
#define _DLOG_CLIENT_H

#include <sys/queue.h>
#include <sys/tree.h>
#ifdef KERNEL
#include <sys/sbuf.h>
#include <sys/types.h>
#else
#include <sbuf.h>
#include <stdbool.h>
#endif

#include "dl_response.h" 
#include "dl_request.h"
#include "dl_config.h"

struct dlog_handle;

/**
 * This function is invoked as a callback in case a disconnect on
 * TCP level is detected.
 */
typedef void (*dl_on_server_closed_func)(void *, void *);

struct dl_client_event_notifier {
	/** An instance of the server owning the client.
	 *  This instance shall be passed as an argument to the callbacks.
	 */
	void *server;

	/** Specifies a callback to be used by the client to
	 *  inform its server about a closed connection.
	 */
	dl_on_server_closed_func on_client_closed;

	struct broker_configuration *dlben_conf;
};

extern int dlog_client_init();
extern int dlog_client_fini();

extern struct dlog_handle * dlog_client_open(struct sbuf *,
    const int, struct dl_client_configuration const * const);
extern int dlog_client_close(struct dlog_handle *);

extern int dlog_fetch(struct dlog_handle *, struct sbuf *, 
    const int32_t, const int32_t,  const int64_t, const int32_t);
extern int dlog_list_offset(struct dlog_handle *, struct sbuf *, int64_t);
extern int dlog_produce(struct dlog_handle *, struct sbuf *, char *, int,
    char *, int); 

#endif
