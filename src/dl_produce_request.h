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

#ifndef _DL_PRODUCE_REQUEST_H
#define _DL_PRODUCE_REQUEST_H

#include <sys/types.h>
#include <sys/queue.h>

#include "dl_message_set.h"
#include "dl_protocol.h"

SLIST_HEAD(dl_produce_request_partitions, dl_produce_request_partition);
SLIST_HEAD(dl_produce_request_topics, dl_produce_request_topic);

struct dl_produce_request_partition {
	SLIST_ENTRY(dl_produce_request_partition) dlprp_entries;
	struct dl_message_set dlprp_message_set;
	int32_t dlprp_partition;
};

struct dl_produce_request_topic {
	SLIST_ENTRY(dl_produce_request_topic) dlprt_entries;
	struct dl_produce_request_partitions dlprt_partitions;
	int32_t dlprt_npartitions;
	char dlprt_topic_name[DL_MAX_TOPIC_NAME_LEN];
};

struct dl_produce_request {
	int16_t dlpr_required_acks;
	int32_t dlpr_timeout;
	int32_t dlpr_ntopics;
	struct dl_produce_request_topics dlpr_topics;
};

extern struct dl_produce_request * dl_produce_request_decode(char *);
extern int dl_produce_request_encode(struct dl_produce_request const * const,
    char *);
extern struct dl_request * dl_produce_request_new(const int32_t,
    char *, char *, char*, int, char *, int);

#endif
