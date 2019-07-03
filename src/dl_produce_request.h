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

#ifndef _DL_PRODUCE_REQUEST_H
#define _DL_PRODUCE_REQUEST_H

#include "dl_bbuf.h"
#include "dl_message_set.h"
#include "dl_request.h"

enum dl_required_acks {
	DL_NO_ACKS = 0,
	DL_LEADER_ACKS = 1,
	DL_ISR_ACKS = -1,
};
typedef enum dl_required_acks dl_required_acks;

struct dl_produce_request;
struct dl_produce_request_topic;
struct dl_produce_request_partition;

typedef void (*dl_produce_request_topic_callback)(
    struct dl_produce_request_topic *, void *);
typedef void (*dl_produce_request_partition_callback)(
    struct dl_produce_request_partition *, void *);

extern int dl_produce_request_new(struct dl_produce_request **, const int32_t,
    struct sbuf *, dl_required_acks, int32_t, struct sbuf *,
    struct dl_message_set *);
extern int dl_produce_request_new_nomsg(struct dl_produce_request **,
    const int32_t, struct sbuf *, dl_required_acks, int32_t, struct sbuf *);
extern void dl_produce_request_delete(struct dl_produce_request *);

extern int dl_produce_request_decode(struct dl_produce_request **,
    struct dl_bbuf *);
extern int dl_produce_request_get_singleton_topic(struct dl_produce_request *,
    struct dl_produce_request_topic **);

extern int32_t dl_produce_request_get_timeout(struct dl_produce_request *);
extern dl_required_acks dl_produce_request_get_required_acks(
    struct dl_produce_request *);

extern void dl_produce_request_topic_foreach(struct dl_produce_request *,
    dl_produce_request_topic_callback, void *);
extern struct sbuf * dl_produce_request_topic_get_name(
    struct dl_produce_request_topic *);
extern int dl_produce_request_topic_get_singleton_partition(
    struct dl_produce_request_topic *,
    struct dl_produce_request_partition **);

extern void dl_produce_request_partition_foreach(
    struct dl_produce_request_topic *, dl_produce_request_partition_callback,
    void *);
extern int32_t dl_produce_request_partition_get_num(
    struct dl_produce_request_partition *);
extern struct dl_message_set * dl_produce_request_partition_get_message_set(
    struct dl_produce_request_partition *);

#endif
