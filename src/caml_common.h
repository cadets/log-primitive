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

#ifndef _CAML_COMMON_H
#define _CAML_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "protocol.h" 

static const int MAX_NUM_REQUESTS_PER_PROCESSOR  = 128; // Maximum outstanding requests per processor.
static const int NUM_PROCESSORS                  = 10;   // Number of processors.
static const int MAX_NUM_RESPONSES_PER_PROCESSOR = 128; // Maximum outstanding responses per processor.
static const int CONNECTIONS_PER_PROCESSOR       = 10; // Number of connections per processor.
static const int MAX_NUM_UNFSYNCED = 20; // Maximum number of unfsynced inserts

typedef void (*ack_function)(unsigned long);
typedef void (*response_function)(struct RequestMessage *rm,
    struct ResponseMessage *rs);

typedef int correlationId_t;

enum broker_confs {
	BROKER_SEND_ACKS = 1 << 1,
	BROKER_FSYNC_ALWAYS = 1 << 2,
};

struct broker_configuration{
	int	fsync_thread_sleep_length;
	int	processor_thread_sleep_length;
	int	val;
};

struct client_configuration{
	ack_function		on_ack;
	response_function	on_response;
	int 	to_resend;
	int	resender_thread_sleep_length;
	int	request_notifier_thread_sleep_length;
	int	reconn_timeout;
	int	poll_timeout;
};

#undef ASSERT
#if DEBUG
#define ASSERT(x)	((void)0)
#else 
#define ASSERT(x)	((void)0)
#endif

extern void	print_configuration(struct broker_configuration *);

#endif
