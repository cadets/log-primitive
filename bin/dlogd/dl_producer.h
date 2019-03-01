/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#ifndef _DL_PRODUCER_H
#define _DL_PRODUCER_H

#include <sys/nv.h>

#include <stdbool.h>

#include "dl_bbuf.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_request_queue.h"

#define DL_MAX_STATE_NAME_LEN 255

struct dl_producer_stats_msg {
	time_t dlpsm_timestamp;
	int32_t dlpsm_cid;
	bool dlpsm_error;
};

struct dl_producer_stats {
	volatile uint64_t dlps_bytes_sent;
	volatile uint64_t dlps_bytes_received;
	struct dl_producer_stats_msg dlps_sent;
	struct dl_producer_stats_msg dlps_received;
	struct dl_request_q_stats dlps_request_q_stats;
	int32_t dlps_rtt;
	int dlps_resend_timeout;
	bool dlps_tcp_connected;
	bool dlps_tls_connected;
	bool dlps_resend;
	char dlps_topic_name[DL_MAX_TOPIC_NAME_LEN];	
	char dlps_state_name[DL_MAX_STATE_NAME_LEN];	
};

struct dl_producer;
struct dl_topic;

extern int dl_producer_new(struct dl_producer **, struct dl_topic *,
    char *, char *, int, nvlist_t *);
extern void dl_producer_delete(struct dl_producer *);

extern struct dl_topic * dl_producer_get_topic(struct dl_producer *); 

extern int dl_producer_response(struct dl_producer *, struct dl_bbuf *);

extern void dl_producer_produce(struct dl_producer const * const);
extern void dl_producer_up(struct dl_producer const * const);
extern void dl_producer_down(struct dl_producer const * const);
extern void dl_producer_syncd(struct dl_producer const * const);
extern void dl_producer_reconnect(struct dl_producer const * const);
extern void dl_producer_error(struct dl_producer const * const);

extern void dl_producer_stats_tcp_connect(struct dl_producer *, bool);
extern void dl_producer_stats_tls_connect(struct dl_producer *, bool);
extern void dl_producer_stats_bytes_sent(struct dl_producer *self, int32_t);
extern void dl_producer_stats_bytes_received(struct dl_producer *self, int32_t);

#endif
