/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _CAML_CLIENT_H
#define _CAML_CLIENT_H

#define MAX_SIZE_HOSTNAME 16

#include <pthread.h>

#include "protocol.h"
#include "protocol_common.h"
#include "caml_common.h"

static int NUM_NOTIFIERS = 5;
static int NUM_READERS   = 1;
static int REQUESTS_PER_NOTIFIER = 10;
static int NODE_POOL_SIZE = 128; // number of maximum outstanding un-acked messages

struct notifier_argument {
	int index;
	pthread_t* tid;
	struct client_configuration *config;
	ack_function on_ack;
	response_function on_response;
};
typedef struct notifier_argument notifier_argument;

struct reader_argument {
	int index;
	pthread_t* tid;
	struct client_configuration *config;
	char hostname[MAX_SIZE_HOSTNAME];
	int portnumber;
};
typedef struct reader_argument reader_argument;

extern void client_busyloop(const char *hostname, int portnumber,
	struct client_configuration *cc);

extern int send_request(int server_id, enum request_type rt, int correlationId,
	char *clientId, int should_resend, int resend_timeout, ...);

#endif
