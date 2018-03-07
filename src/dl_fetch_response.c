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

#include <sys/types.h>
#include <sys/queue.h>
#ifdef KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_fetch_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"

struct dl_response *
dl_fetch_response_decode(char *buffer)
{
	struct dl_message_set *message_set;
	struct dl_fetch_response *fetch_response;
	struct dl_fetch_response_topic *topic;
	struct dl_fetch_response_partition *partition;
	struct dl_response *response;
	struct sbuf *topic_name;
	int32_t partition_response, response_it;
	
	/* Construct the FetchResponse. */
	response = (struct dl_response *) dlog_alloc(
		sizeof(struct dl_response));

	response->dlrs_api_key = DL_FETCH_API_KEY;

	/* Construct the FetchResponse. */
	response->dlrs_message.dlrs_fetch_message = fetch_response =
	    (struct dl_fetch_response *) dlog_alloc(
		sizeof(struct dl_fetch_response));

	/* Decode the ThrottleTime */	
	DL_DECODE_THROTTLE_TIME(buffer, &fetch_response->dlfr_throttle_time);

        /* Decode the responses */	
	SLIST_INIT(&fetch_response->dlfr_topics);

	dl_buf_get_int32(buffer, &fetch_response->dlfr_ntopics);
	DL_ASSERT(fetch_response->dlfr_ntopics > 0,
	    "Response array is not NULLABLE");

	SLIST_INIT(&fetch_response->dlfr_topics);

	for (response_it = 0; response_it < fetch_response->dlfr_ntopics;
	    response_it++) {

		topic = (struct dl_fetch_response_topic *) dlog_alloc(
		    sizeof(struct dl_fetch_response_topic));

		/* Decode the TopicName */
		DL_DECODE_TOPIC_NAME(buffer, &topic_name);

		topic->dlfrt_topic_name = topic_name;

		/* Decode the partition responses */	
		dl_buf_get_int32(buffer, &topic->dlfrt_npartitions);
	
		SLIST_INIT(&topic->dlfrt_partitions);

		for (partition_response = 0;
		    partition_response < topic->dlfrt_npartitions;
		    partition_response++) {

			partition = (struct dl_fetch_response_partition *)
			    dlog_alloc(sizeof(
				struct dl_fetch_response_partition));

			/* Decode the Partition */
			DL_DECODE_PARTITION(buffer,
			    &partition->dlfrpr_partition);

			/* Decode the ErrorCode */
			DL_DECODE_ERROR_CODE(buffer,
			    &partition->dlfrpr_error_code);

			/* Decode the HighWatermark */
		    	DL_DECODE_HIGH_WATERMARK(buffer,
			    &partition->dlfrpr_high_watermark);

			/* Decode the MessageSet */
			partition->dlfrp_message_set =
			    dl_message_set_decode(buffer);
		
			SLIST_INSERT_HEAD(&topic->dlfrt_partitions, partition,
			    dlfrp_entries);
		}

		SLIST_INSERT_HEAD(&fetch_response->dlfr_topics, topic,
		    dlfrt_entries);
	}
	return response;
}

int
dl_fetch_response_encode(struct dl_fetch_response *response,
    struct dl_buf *target)
{
	struct dl_fetch_response_partition *partition;
	struct dl_fetch_response_topic *topic;
	int32_t response_it, partition_response, response_size = 0;

	/* Encode the ThrottleTime */	
	DL_ENCODE_THROTTLE_TIME(target, response->dlfr_throttle_time);

        /* Decode the responses */	
	SLIST_INIT(&response->dlfr_topics);

	DL_ASSERT(response->dlfr_ntopics > 0,
	    "Response array is not NULLABLE");
	dl_buf_put_int32(target, response->dlfr_ntopics);

	SLIST_INIT(&response->dlfr_topics);

	for (response_it = 0; response_it < response->dlfr_ntopics;
	    response_it++) {

		topic = (struct dl_fetch_response_topic *) dlog_alloc(
		    sizeof(struct dl_fetch_response_topic));

		/* Decode the TopicName */
		DL_ENCODE_TOPIC_NAME(target, topic->dlfrt_topic_name);

		/* Decode the partition responses */	
		dl_buf_put_int32(target, topic->dlfrt_npartitions);
	
		SLIST_INIT(&topic->dlfrt_partitions);

		for (partition_response = 0;
		    partition_response < topic->dlfrt_npartitions;
		    partition_response++) {

			partition = (struct dl_fetch_response_partition *)
			    dlog_alloc(sizeof(
				struct dl_fetch_response_partition));

			/* Decode the Partition */
			DL_ENCODE_PARTITION(target,
			    partition->dlfrpr_partition);

			/* Decode the ErrorCode */
		    	DL_ENCODE_ERROR_CODE(target,
			    partition->dlfrpr_error_code);

			/* Decode the HighWatermark */
		    	DL_ENCODE_HIGH_WATERMARK(target,
			    partition->dlfrpr_high_watermark);

			/* Encode the MessageSet */
			dl_message_set_encode(partition->dlfrp_message_set,
			    target);

			SLIST_INSERT_HEAD(&topic->dlfrt_partitions, partition,
			    dlfrp_entries);
		}

		SLIST_INSERT_HEAD(&response->dlfr_topics, topic,
		    dlfrt_entries);
	}
	return response_size;
}
