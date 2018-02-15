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

#include <stdarg.h>
#include <string.h>

#include "dl_assert.h"
#include "dl_produce_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"

#define DL_ENCODE_BASE_OFFSET(target, source) dl_encode_int64(target, source)
#define DL_ENCODE_ERROR_CODE(target, source) dl_encode_int16(target, source)
#define DL_ENCODE_PARTITION(target, source) dl_encode_int32(target, source)
#define DL_ENCODE_THROTTLE_TIME(target, source) dl_encode_int32(target, source)
#define DL_ENCODE_TOPIC_NAME(target, source) \
    dl_encode_string(target, source, DL_MAX_TOPIC_NAME_LEN)

#define DL_DECODE_BASE_OFFSET(source) dl_decode_int64(source);
#define DL_DECODE_ERROR_CODE(source) dl_decode_int16(source);
#define DL_DECODE_PARTITION(source) dl_decode_int32(source);
#define DL_DECODE_THROTTLE_TIME(source) dl_decode_int32(source)
#define DL_DECODE_TOPIC_NAME(source, target) dl_decode_string(source, target)

static struct dl_produce_response_partition *
    dl_produce_response_partition_decode(char const * const);

struct dl_produce_response *
dl_produce_response_new(char * topic_name, int32_t throttle_time,
    int64_t base_offset, int16_t error_code)
{
	struct dl_produce_response *response;
	struct dl_produce_response_topic *response_topic;
	struct dl_produce_response_partition *response_partition;

	/* Construct the ProduceResponse. */
	response = (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
	
	SLIST_INIT(&response->dlpr_topics);
	response->dlpr_throttle_time = throttle_time;
	response->dlpr_ntopics = 1;

	response_topic = (struct dl_produce_response_topic *) dlog_alloc(
	    sizeof(struct dl_produce_response_topic));	    
	strlcpy(response_topic->dlprt_topic_name, topic_name,
	    DL_MAX_TOPIC_NAME_LEN);
	response_topic->dlprt_npartitions = 1;
	SLIST_INIT(&response_topic->dlprt_partitions);

	SLIST_INSERT_HEAD(&response->dlpr_topics, response_topic,
	    dlprt_entries);
	
	response_partition =
	    (struct dl_produce_response_partition *) dlog_alloc(
		sizeof(struct dl_produce_response_partition));	    
	
	response_partition->dlprp_base_offset = base_offset;
	response_partition->dlprp_partition = 0;
	response_partition->dlprp_error_code= error_code;

	SLIST_INSERT_HEAD(&response_topic->dlprt_partitions,
	    response_partition, dlprp_entries);

	return response;
}

struct dl_produce_response *
dl_produce_response_decode(char const * const source)
{
	struct dl_produce_response *response;
	struct dl_produce_response_partition *partition_response;
	struct dl_produce_response_topic *topic_response;
	int32_t partition_response_it, response_it, n_responses,
		n_partition_responses;
	int16_t topic_name_len;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Allocate and initialise the produce_response instance. */
	response = (struct dl_produce_response *)
	    dlog_alloc(sizeof(struct dl_produce_response));

	SLIST_INIT(&response->dlpr_topics);

	/* Decode the number of responses in the response array. */
	response->dlpr_ntopics = dl_decode_int32(source);
	DL_ASSERT(response->dlpr_ntopics > 0,
	    "Non-primitive array types are not NULLABLE");

	/* Decode the responses. */
	for (response_it = 0; response_it < response->dlpr_ntopics;
	    response_it++) {

		/* Allocate, decode and enque each response. */
		topic_response = (struct dl_produce_response_topic *)
		    dlog_alloc(sizeof(struct dl_produce_response_topic));

		SLIST_INIT(&topic_response->dlprt_partitions);

		/* Decode the TopicName. */
		DL_DECODE_TOPIC_NAME(source, topic_response->dlprt_topic_name); 

		SLIST_INSERT_HEAD(&response->dlpr_topics, topic_response,
		    dlprt_entries);

		/* Decode the partitions. */
		topic_response->dlprt_npartitions = dl_decode_int32(source);

		for (partition_response_it = 0;
		    partition_response_it < topic_response->dlprt_npartitions;
		    partition_response_it++) {

			/* Decode the partition responses. */
			partition_response =
			    dl_produce_response_partition_decode(source);
			SLIST_INSERT_HEAD(&topic_response->dlprt_partitions,
			    partition_response, dlprp_entries);
		}
	}

	/* Decode the ThrottleTime. */
	response->dlpr_throttle_time = DL_DECODE_THROTTLE_TIME(source);

	return response;
}

static struct dl_produce_response_partition * 
dl_produce_response_partition_decode(char const * const source)
{
	struct dl_produce_response_partition *partition_response;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	
	partition_response = (struct dl_produce_response_partition *)
	    dlog_alloc(sizeof(struct dl_produce_response_partition));

	/* Decode the Partition */
	partition_response->dlprp_partition = DL_DECODE_PARTITION(source);

	/* Decode the ErrorCode */
	partition_response->dlprp_error_code = DL_DECODE_ERROR_CODE(source);

	/* Decode the BaseOffset */
	partition_response->dlprp_base_offset = DL_DECODE_BASE_OFFSET(source);

	return partition_response;
}

int32_t
dl_produce_response_encode(struct dl_produce_response *response, char *target)
{
	struct dl_produce_response_topic *topic_response;
	struct dl_produce_response_partition *partition_response;
	int response_size = 0;

	/* Encode the number of responses in the response array. */
	response_size += dl_encode_int32(target, response->dlpr_ntopics);
	DL_ASSERT(response->dlpr_ntopics > 0,
	    "Non-primitive array types are not NULLABLE");

	SLIST_FOREACH(topic_response, &response->dlpr_topics, dlprt_entries) {

		/* Encode the TopicName. */
		response_size += DL_ENCODE_TOPIC_NAME(&target[response_size],
		    topic_response->dlprt_topic_name);

		response_size += dl_encode_int32(&target[response_size],
		    topic_response->dlprt_npartitions);

		SLIST_FOREACH(partition_response,
		    &topic_response->dlprt_partitions, dlprp_entries) {

			/* Encode the BaseOffset. */
			response_size =+ DL_ENCODE_BASE_OFFSET(
			    &target[response_size],
			    partition_response->dlprp_base_offset);
			
			/* Encode the ErrorCode. */
			response_size += DL_ENCODE_ERROR_CODE(
			    &target[response_size],
			    partition_response->dlprp_partition);

			/* Encode the Partition. */
			response_size += DL_ENCODE_PARTITION(
			    &target[response_size],
			    partition_response->dlprp_error_code);
		}
	}
	
	/* Encode the ThrottleTime. */
	response_size += DL_ENCODE_THROTTLE_TIME(&target[response_size],
	    response->dlpr_throttle_time);

	return response_size;
}

