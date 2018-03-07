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

#ifdef KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_request.h"
#include "dl_utils.h"

/**
 * TODO
 */
struct dl_request *
dl_list_offset_request_new(int32_t correlation_id, struct sbuf *client_id,
    struct sbuf *topic_name, int64_t time)
{
	struct dl_request *request;
	struct dl_list_offset_request *list_offset_request;
	struct dl_list_offset_request_topic *topic;
	struct dl_list_offset_request_partition *partition;

	/* Construct the ListOffsetRequest. */
	request = dl_request_new(DL_OFFSET_API_KEY, correlation_id,
	    client_id);
#ifdef KERNEL
	DL_ASSERT(request != NULL, ("Failed allocating FetchRequest."));
	{
#else
	if (request != NULL) {
#endif
		list_offset_request = request->dlrqm_message.dlrqmt_offset_request =
		(struct dl_list_offset_request *) dlog_alloc(
			sizeof(struct dl_list_offset_request));
#ifdef KERNEL
		DL_ASSERT(list_offfset_request != NULL,
		("Failed allocating ListOffsetequest."));
		{
#else
		if (list_offset_request != NULL) {
#endif
			SLIST_INIT(&list_offset_request->dlor_topics);
			list_offset_request->dlor_ntopics = 1;
			list_offset_request->dlor_replica_id = 0;

			/* Construct a single Topic/Partition. */
			topic = (struct dl_list_offset_request_topic *)
			    dlog_alloc(sizeof(struct dl_list_offset_request_topic));	    
#ifdef KERNEL
			DL_ASSERT(topic != NULL,
			    ("Failed allocating ListOffsetRequest [topic_data]."));
			{
#else
			if (topic!= NULL) {
#endif
				topic->dlort_topic_name = topic_name;
				topic->dlort_npartitions = 1;

				partition = &topic->dlort_partitions[0];
				partition->dlorp_partition = 0;
				partition->dlorp_time = time;

				SLIST_INSERT_HEAD(
				    &list_offset_request->dlor_topics, topic,
				    dlort_entries);
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Failed allocating ListOffsetRequest [topic_data].\n");
				dlog_free(list_offset_request);
				dlog_free(request);
				request = NULL;
			}
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Failed allocating ListOffsetRequest.\n");
			dlog_free(request);
			request = NULL;
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Failed allocating ListOffsetRequest.\n");
	}
	return request;
}

/**
 * Decode the ListOffsetRequest.
 *
 * ListOffsetRequest = ReplicaId [Topics]
 * Topics = TopicName [Partitions]
 * TopicName
 * Partitions = Partition Timestamp
 * Partition
 * Timestamp
 */
struct dl_list_offset_request *
dl_list_offset_request_decode(char *source)
{
	struct dl_list_offset_request *request;
	struct dl_list_offset_request_topic *request_topic;
	struct dl_list_offset_request_partition *request_partition;
	struct sbuf *topic_name;
	int32_t topic_it, partition_it;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL\n");

	/* Construct the ProduceRequest. */
	request = (struct dl_list_offset_request *) dlog_alloc(
	    sizeof(struct dl_list_offset_request));
// TODO
	/* Decode the ListOffsetRequest ReplicaId. */
	DL_DECODE_REPLICA_ID(source, &request->dlor_replica_id);

	/* Decode the [topic_data] array. */
	dl_buf_get_int32(source, &request->dlor_ntopics);
		
	SLIST_INIT(&request->dlor_topics);

	for (topic_it = 0; topic_it < request->dlor_ntopics; topic_it++) {

		request_topic = (struct dl_list_offset_request_topic *)
		    dlog_alloc(sizeof(struct dl_list_offset_request_topic));
// TODO

		/* Decode the TopicName. */
		DL_DECODE_TOPIC_NAME(source, &topic_name);

		/* Decode the [data] array. */
		dl_buf_get_int32(source, &request_topic->dlort_npartitions);
			
		for (partition_it = 0;
		    partition_it < request_topic->dlort_npartitions;
		    partition_it++) {

			request_partition =
			    (struct dl_list_offset_request_partition *)
			    dlog_alloc(sizeof(
				struct dl_list_offset_request_partition));

			/* Decode the Partition. */
			DL_DECODE_PARTITION(source,
			    &request_partition->dlorp_partition);

			/* Decode the Time. */
			DL_DECODE_TIMESTAMP(source,
			    &request_partition->dlorp_time);
		}

		SLIST_INSERT_HEAD(&request->dlor_topics, request_topic,
		    dlort_entries);
	}
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
    struct dl_buf *target)
{
	struct dl_list_offset_request_partition *req_partition;
	struct dl_list_offset_request_topic *req_topic;
	int partition;

	DL_ASSERT(self != NULL, "ListOffsetRequest cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the ListOffsetRequest ReplicaId into the target. */
	if (DL_ENCODE_REPLICA_ID(target, self->dlor_replica_id) != 0)
		goto err;

	/* Encode the ListOffsetRequest Topics. */
	if (dl_buf_put_int32(target, self->dlor_ntopics) != 0)
		goto err;

	SLIST_FOREACH(req_topic, &self->dlor_topics, dlort_entries) {

		/* Encode the Request TopicName into the buffer. */
		if (DL_ENCODE_TOPIC_NAME(target,
		    req_topic->dlort_topic_name) != 0)
			goto err;

		/* Encode the Partitions. */
		if (dl_buf_put_int32(target,
		    req_topic->dlort_npartitions) != 0)
			goto err;

		for (partition = 0; partition < req_topic->dlort_npartitions;
		    partition++) {

			req_partition = &req_topic->dlort_partitions[partition];

			/* Encode the ListOffsetRequest Partition into the
			 * target.
			 */
			if (DL_ENCODE_PARTITION(target,
			    req_partition->dlorp_partition) != 0)
				goto err;
			
			/* Encode the ListOffsetRequest Timestamp into the
			 * target.
			 */
			if (DL_ENCODE_TIMESTAMP(target,
			    req_partition->dlorp_time) != 0)
				goto err;
		}
	}
	return 0;
err:
	return -1;
}

