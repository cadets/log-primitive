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

#ifndef _DL_PRODUCE_RESPONSE_H
#define _DL_PRODUCE_RESPONSE_H

#include <sys/types.h>
#include <sys/queue.h>

#include "dl_protocol.h"

SLIST_HEAD(dl_produce_response_q, dl_produce_responses);
SLIST_HEAD(dl_produce_partition_response_q, dl_produce_partition_responses);

struct dl_produce_partition_responses {
	SLIST_ENTRY(dl_produce_partition_responses) dlpprs_entries;
	int64_t dlpprs_base_offset;
	int32_t dlpprs_partition;
	int16_t dlpprs_error_code;
};

struct dl_produce_responses {
	SLIST_ENTRY(dl_produce_responses) dlprs_entries;
	struct dl_produce_partition_response_q dlprs_partition_responses;
	char dlprs_topic_name[DL_MAX_TOPIC_NAME_LEN];
};	

struct dl_produce_response {
	struct dl_produce_response_q dlpr_responses;
	int32_t dlpr_throttle_time;
};

extern struct dl_produce_response * dl_decode_produce_response(char *);
extern dl_produce_response_encode(struct dl_produce_response *, char *);

#endif
