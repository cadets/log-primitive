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
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_request.h"

#define DL_ENCODE_PARTITION(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_TOPIC_NAME(target, value) \
    dl_encode_string(target, value, DL_MAX_TOPIC_NAME_LEN)
#define DL_ENCODE_REPLICA_ID(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_TIMESTAMP(target, value) dl_encode_int64(target, value)

struct dl_request *
dl_list_offset_request_new(int32_t correlation_id, char *client_id,
    char *topic_name, int64_t time)
{
	struct dl_request *request;
	struct dl_list_offset_request *list_offset_request;
	struct dl_list_offset_request_topic *topic;
	struct dl_list_offset_request_partition *partition;

	/* Construct the ListOffsetRequest. */
	request = dl_request_new(DL_OFFSET_REQUEST, correlation_id,
	    client_id);
	
	list_offset_request = request->dlrqm_message.dlrqmt_offset_request =
	    (struct dl_list_offset_request *) dlog_alloc(
		sizeof(struct dl_list_offset_request));

	SLIST_INIT(&list_offset_request->dlor_topics);
	list_offset_request->dlor_ntopics = 1;
	list_offset_request->dlor_replica_id = 0;

	topic = (struct dl_list_offset_request_topic *) dlog_alloc(
	    sizeof(struct dl_list_offset_request_topic));	    
	topic->dlort_topic_name = topic_name;
	topic->dlort_npartitions = 1;
	SLIST_INIT(&topic->dlort_partitions);

	SLIST_INSERT_HEAD(&list_offset_request->dlor_topics, topic,
	    dlort_entries);
	
	partition = (struct dl_list_offset_request_partition *) dlog_alloc(
	    sizeof(struct dl_list_offset_request_partition));	    
	
	partition->dlorp_partition = 0;
	partition->dlorp_time = time;

	SLIST_INSERT_HEAD(&topic->dlort_partitions, partition, dlorp_entries);

	return request;
}

/**
 * Encode the ListOffsetRequest.
 *
 * ListOffsetRequest = ReplicaId [Topics]
 * Topics = TopicName [Partitions]
 * TopicName
 * Partitions = Partition Timestamp
 * Partition
 * Timestamp
 */
int
dl_list_offset_request_encode(struct dl_list_offset_request *self,
    char *target)
{
	struct dl_list_offset_request_partition *partition;
	struct dl_list_offset_request_topic *topic;
	int32_t request_size = 0;

	DL_ASSERT(self != NULL, "ListOffsetRequest cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the ListOffsetRequest ReplicaId into the target. */
	request_size += DL_ENCODE_REPLICA_ID(&target[request_size],
	    self->dlor_replica_id);

	/* Encode the ListOffsetRequest Topics. */
	request_size += dl_encode_int32(&target[request_size],
	    self->dlor_ntopics);

	SLIST_FOREACH(topic, &self->dlor_topics, dlort_entries) {

		/* Encode the ListOffsetRequest TopicName into the target. */
		request_size += DL_ENCODE_TOPIC_NAME(&target[request_size],
		    topic->dlort_topic_name);

		/* Encode the Partitions. */
		request_size += dl_encode_int32(&target[request_size],
		    topic->dlort_npartitions);

		SLIST_FOREACH(partition, &topic->dlort_partitions,
		    dlorp_entries) {

			/* Encode the ListOffsetRequest Partition into the
			 * target.
			 */
			request_size += DL_ENCODE_PARTITION(
			    &target[request_size], partition->dlorp_partition);
			
			/* Encode the ListOffsetRequest Timestamp into the
			 * target.
			 */
			request_size += DL_ENCODE_TIMESTAMP(
			    &target[request_size], partition->dlorp_time);
		}
	}

	return request_size;
}
