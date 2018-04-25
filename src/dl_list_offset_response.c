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

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_list_offset_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"

struct dl_list_offset_response *
dl_list_offset_response_new(char *topic_name, int16_t error_code, int64_t time,
    int64_t offset)
{
	struct dl_list_offset_response *response;
	struct dl_list_offset_response_topic *response_topic;
	struct dl_list_offset_response_partition *response_partition;

	/* Construct the ListOffsetresponse. */
	response = (struct dl_list_offset_response *) dlog_alloc(
	    sizeof(struct dl_list_offset_response));
	
	SLIST_INIT(&response->dlor_topics);
	response->dlor_ntopics = 1;

	response_topic = (struct dl_list_offset_response_topic *) dlog_alloc(
	    sizeof(struct dl_list_offset_response_topic));	    
	//strlcpy(response_topic->dlort_topic_name, topic_name,
	//    DL_MAX_TOPIC_NAME_LEN);
	response_topic->dlort_npartitions = 1;
	SLIST_INIT(&response_topic->dlort_partitions);

	SLIST_INSERT_HEAD(&response->dlor_topics, response_topic,
	    dlort_entries);
	
	response_partition =
	    (struct dl_list_offset_response_partition *) dlog_alloc(
		sizeof(struct dl_list_offset_response_partition));	    
	
	response_partition->dlorp_partition = 0;
	response_partition->dlorp_error_code= error_code;
	response_partition->dlorp_timestamp = time;
	response_partition->dlorp_offset = offset;

	SLIST_INSERT_HEAD(&response_topic->dlort_partitions,
	    response_partition, dlorp_entries);

	return response;
}

int
dl_list_offset_response_decode(struct dl_response **self,
    struct dl_bbuf *source)
{
	struct dl_list_offset_response *offset_response;
	struct dl_list_offset_response_partition *response_partition;
	struct dl_list_offset_response_topic *response_topic;
	struct dl_response *response;
	struct sbuf *topic_name = NULL;
	int32_t topic_it, partition_it;
     
	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Construct the Response. */
	response = (struct dl_response *) dlog_alloc(
		sizeof(struct dl_response));

	response->dlrs_api_key = DL_OFFSET_API_KEY;

	/* Construct the ListOffsetResponse. */
	response->dlrs_offset_response = offset_response =
	    (struct dl_list_offset_response *) dlog_alloc(
		sizeof(struct dl_list_offset_response));

	SLIST_INIT(&offset_response->dlor_topics);

        /* Decode the [topic_data] array. */
	dl_bbuf_get_int32(source, &offset_response->dlor_ntopics);

	for (topic_it = 0; topic_it < offset_response->dlor_ntopics;
	    topic_it++) {

		response_topic = (struct dl_list_offset_response_topic *)
		    dlog_alloc(sizeof(struct dl_list_offset_response_topic));
		
		/* Decode the TopicName */
		DL_DECODE_TOPIC_NAME(source, &topic_name);
		response_topic->dlort_topic_name = topic_name;

		SLIST_INIT(&response_topic->dlort_partitions);

		/* Decode the [data] array. */
		dl_bbuf_get_int32(source, &response_topic->dlort_npartitions);
		
		for (partition_it = 0;
		    partition_it < response_topic->dlort_npartitions;
		    partition_it++) {

			response_partition =
			    (struct dl_list_offset_response_partition *)
			    dlog_alloc(sizeof(
				struct dl_list_offset_response_partition));
		
			/* Decode the Partition */
			DL_DECODE_PARTITION(source,
			    &response_partition->dlorp_partition);
			
			/* Decode the ErrorCode */
			DL_DECODE_ERROR_CODE(source,
			    &response_partition->dlorp_error_code);

			/* Decode the Timestamp */
			DL_DECODE_TIMESTAMP(source,
			    &response_partition->dlorp_timestamp);
			
			/* Decode the Offset*/
			DL_DECODE_OFFSET(source,
			    &response_partition->dlorp_offset);
		
			SLIST_INSERT_HEAD(&response_topic->dlort_partitions,
			    response_partition, dlorp_entries);
		}

		SLIST_INSERT_HEAD(&offset_response->dlor_topics,
		    response_topic, dlort_entries);
	}
	*self = response;
	return 0;
}

int32_t
dl_list_offset_response_encode(struct dl_list_offset_response *response,
    struct dl_bbuf *target)
{
	struct dl_list_offset_response_partition *response_partition;
	struct dl_list_offset_response_topic *response_topic;

	DL_ASSERT(response != NULL, "Response cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");
        
	/* Encode the [topic_data] array. */
	dl_bbuf_put_int32(target, response->dlor_ntopics);

	SLIST_FOREACH(response_topic, &response->dlor_topics, dlort_entries) {

		/* Encode the TopicName. */
		DL_ENCODE_TOPIC_NAME(target, response_topic->dlort_topic_name);

		/* Encode the [data] array. */
		dl_bbuf_put_int32(target, response_topic->dlort_npartitions);

		SLIST_FOREACH(response_partition,
		    &response_topic->dlort_partitions, dlorp_entries) {
	
			/* Encode the Partition. */
			DL_ENCODE_PARTITION(target,
			    response_partition->dlorp_partition);
	
			/* Encode the ErrorCode. */
			DL_ENCODE_ERROR_CODE(target,
			    response_partition->dlorp_error_code);
	
			/* Encode the Timestamp. */
			DL_ENCODE_TIMESTAMP(target,
			    response_partition->dlorp_timestamp);
	
			/* Encode the Offset. */
			DL_ENCODE_OFFSET(target,
			    response_partition->dlorp_offset);
		}
	}
	return 0;
}
