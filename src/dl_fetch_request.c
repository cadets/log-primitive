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

#include <stddef.h>

#include "dl_assert.h"
#include "dl_fetch_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_request.h"

static const int32_t DL_DEFAULT_PARTITION = 0;
static const int32_t DL_DEFAULT_REPLICA_ID = -1;

#define DL_ENCODE_MAX_WAIT_TIME(target, value) \
    dl_encode_int32(target, value)
#define DL_ENCODE_MIN_BYTES(target, value) \
    dl_encode_int32(target, value)
#define DL_ENCODE_REPLICA_ID(target, value) \
    dl_encode_int32(target, value)
#define DL_ENCODE_TOPIC_NAME(target, source) \
    dl_encode_string(target, source, DL_MAX_TOPIC_NAME_LEN)

struct dl_request *
dl_fetch_request_new(const int32_t correlation_id, char *client_id,
    char *topic_name, const int32_t min_bytes, const int32_t max_wait_time, 
    const int64_t fetch_offset, const int32_t max_bytes)
{
	struct dl_request *request;
	struct dl_fetch_request *fetch_request;
	struct dl_fetch_request_topic *topic;
	struct dl_fetch_request_partition *partition;

	/* Construct the super class Request. */
	request = dl_request_new(DL_FETCH_REQUEST, correlation_id,
	    client_id);
	DL_ASSERT(request != NULL, "Failed constructing super class");

	/* Construct the FetchRequest. */
	fetch_request = request->dlrqm_message.dlrqmt_fetch_request =
	    (struct dl_fetch_request *) dlog_alloc(
		sizeof(struct dl_fetch_request));
	
	fetch_request->dlfr_replica_id = DL_DEFAULT_REPLICA_ID;
	fetch_request->dlfr_max_wait_time = max_wait_time;
	fetch_request->dlfr_min_bytes = min_bytes;
	
	fetch_request->dlfr_nrequests = 1;
	SLIST_INIT(&fetch_request->dlfr_requests);

	topic = (struct dl_fetch_request_topic *) dlog_alloc(
		sizeof(struct dl_fetch_request_topic));

	topic->dlfrt_topic_name = topic_name;

	topic->dlfrt_nrequests = 1;
	SLIST_INIT(&topic->dlfrt_partition_requests);

	partition = (struct dl_fetch_request_partition *) dlog_alloc(
		sizeof(struct dl_fetch_request_partition));
		
	partition->dlfrp_partition = DL_DEFAULT_PARTITION;
	partition->dlfrp_fetch_offset = fetch_offset;
	partition->dlfrp_max_bytes = max_bytes;
	
	SLIST_INSERT_HEAD(&topic->dlfrt_partition_requests, partition,
	    dlfrp_entries);
	SLIST_INSERT_HEAD(&fetch_request->dlfr_requests, topic, dlfrt_entries);

	return request;
}

int
dl_fetch_request_encode(struct dl_fetch_request *self, char *target)
{
	struct dl_fetch_request_partition *partition_request;
	struct dl_fetch_request_topic *topic_request;
	int32_t request_size = 0;

	DL_ASSERT(self != NULL, "FetchRequest cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the FetchRequest ReplicaId into the buffer. */
	request_size += DL_ENCODE_REPLICA_ID(&target[request_size],
	    self->dlfr_replica_id);

	/* Encode the FetchRequest MaxWaitTime into the buffer. */
	request_size += DL_ENCODE_MAX_WAIT_TIME(&target[request_size],
	    self->dlfr_max_wait_time);

	/* Encode the FetchRequest MinBytes into the buffer. */
	request_size += DL_ENCODE_MIN_BYTES(&target[request_size],
	    self->dlfr_min_bytes);

	/* Encode the [topics] into the buffer. */
	request_size += dl_encode_int32(&target[request_size],
	    self->dlfr_nrequests);

	/* Encode the FetchRequest ReplicaId into the buffer. */
	SLIST_FOREACH(topic_request, &self->dlfr_requests, dlfrt_entries) {

		/* Encode the FetchRequest TopicName into the buffer. */
		request_size += DL_ENCODE_TOPIC_NAME(&target[request_size],
		    topic_request->dlfrt_topic_name);

		/* Encode the [partitions] into the buffer. */	
		request_size += dl_encode_int32(&target[request_size],
		    topic_request->dlfrt_nrequests);

		SLIST_FOREACH(partition_request,
		    &topic_request->dlfrt_partition_requests, dlfrp_entries) {

			/* Encode the FetchRequest Partition into the
			 * buffer.
			 */
			request_size += dl_encode_int32(&target[request_size],
			    partition_request->dlfrp_partition);

			/* Encode the FetchRequest FetchOffset into the
			 * buffer.
			 */
			request_size += dl_encode_int64(&target[request_size],
			    partition_request->dlfrp_fetch_offset);

			/* Encode the FetchRequest MaxBytes into the buffer. */
			request_size += dl_encode_int32(&target[request_size],
			    partition_request->dlfrp_max_bytes);
		}
	}

	return request_size;
}

struct dl_fetch_request *
dl_fetch_request_decode(char *source)
{
	// TODO: Decode a FetchRequest
	return NULL;
}
