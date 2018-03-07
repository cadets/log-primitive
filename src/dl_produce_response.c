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

#ifdef KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#endif

#include <stdarg.h>
#include <string.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_produce_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

struct dl_produce_response *
dl_produce_response_new(char * topic_name, int32_t throttle_time,
    int64_t offset, int16_t error_code)
{
	struct dl_produce_response *response;
	struct dl_produce_response_topic *response_topic;

	/* Construct the ProduceResponse. */
	response = (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
#ifdef KERNEL
	DL_ASSERT(response != NULL, ("Failed allocating Response.\n"));
	{
#else
	if (response != NULL ) {
#endif	
		SLIST_INIT(&response->dlpr_topics);
		response->dlpr_throttle_time = throttle_time;
		response->dlpr_ntopics = 1;

		response_topic = (struct dl_produce_response_topic *)
		    dlog_alloc(sizeof(struct dl_produce_response_topic));	    
#ifdef KERNEL
		DL_ASSERT(response_topic != NULL,
		    ("Failed allocating response topic.\n"));
		{
#else
		if (response_topic != NULL ) {
#endif	
			sbuf_new(response_topic->dlprt_topic_name, topic_name,
			    DL_MAX_TOPIC_NAME_LEN, SBUF_FIXEDLEN);
			response_topic->dlprt_npartitions = 1;
			
			response_topic->dlprt_partitions[0].dlprp_offset =
			    offset;
			response_topic->dlprt_partitions[0].dlprp_partition =
			    0;
			response_topic->dlprt_partitions[0].dlprp_error_code =
			    error_code;
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Failed allocating ProduceResponse topic_data");
			dlog_free(response);
			response = NULL;
		}
	}
	return response;
}

int
dl_produce_response_decode(struct dl_response **self,
    struct dl_buf *source)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_partition *partition_response;
	struct dl_produce_response_topic *topic_response;
	struct dl_response *response;
	struct sbuf *topic_name;
	int32_t partition, response_it, n_responses, npartitions;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Construct the Response. */
	*self = response = (struct dl_response *) dlog_alloc(
	    sizeof(struct dl_response));
#ifdef KERNEL
	DL_ASSERT(response != NULL, ("Failed to allocate Response.\n"));
	{
#else
	if (response != NULL) {
#endif
		response->dlrs_api_key = DL_PRODUCE_API_KEY;

		/* Allocate and initialise the produce_response instance. */
		response->dlrs_message.dlrs_produce_message =
		    produce_response = (struct dl_produce_response *)
		    dlog_alloc(sizeof(struct dl_produce_response));
#ifdef KERNEL
		DL_ASSERT(produce_response != NULL,
		    ("Failed to allocate ProduceResponse.\n"));
		{
#else
		if (produce_response != NULL) {
#endif
			SLIST_INIT(&produce_response->dlpr_topics);

			/* Decode the number of responses in the response array. */
			printf("pos= %d\n", dl_buf_pos(source));
			dl_buf_get_int32(source,
			    &produce_response->dlpr_ntopics);
			// TODO: need to check this to verify message is well
			// formed
			printf("ntopics = %d\n", produce_response->dlpr_ntopics);
			printf("pos= %d\n", dl_buf_pos(source));

			DL_ASSERT(produce_response->dlpr_ntopics > 0,
			    ("Non-primitive array types are not NULLABLE"));

			/* Decode the responses. */
			for (response_it = 0;
			    response_it < produce_response->dlpr_ntopics;
			    response_it++) {

				/* Decode the TopicName. */
				DL_DECODE_TOPIC_NAME(source, &topic_name);
				printf("pos= %d\n", dl_buf_pos(source));

				/* Decode the partitions. */
				dl_buf_get_int32(source, &npartitions);
				printf("pos= %d\n", dl_buf_pos(source));
				printf("npartitions = %d\n", npartitions); 
			
				/* Allocate, decode and enqueue each response. */
				topic_response = (struct dl_produce_response_topic *)
				    dlog_alloc(sizeof(struct dl_produce_response_topic) +
					(topic_response->dlprt_npartitions-1 *
					sizeof(struct dl_produce_response_partition)));

				topic_response->dlprt_topic_name = topic_name; 
				topic_response->dlprt_npartitions = npartitions; 

				for (partition = 0;
				    partition < topic_response->dlprt_npartitions;
				    partition++) {

					partition_response =
					    &topic_response->dlprt_partitions[partition];

					/* Decode the Partition */
					DL_DECODE_PARTITION(source,
					    &partition_response->dlprp_partition);

					/* Decode the ErrorCode */
					DL_DECODE_ERROR_CODE(source,
					    &partition_response->dlprp_error_code);

					/* Decode the Offset */
					DL_DECODE_OFFSET(source,
					    &partition_response->dlprp_offset);
				}

				SLIST_INSERT_HEAD(
				    &produce_response->dlpr_topics,
				    topic_response, dlprt_entries);
			}

			/* Decode the ThrottleTime. */
			DL_DECODE_THROTTLE_TIME(source,
			    &produce_response->dlpr_throttle_time);
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Failed to allocate ProduceResponse,\n");
			dlog_free(response);
			response = NULL;
		}
	}
	return 0;
}

int32_t
dl_produce_response_encode(struct dl_produce_response *response,
    struct dl_buf *target)
{
	struct dl_produce_response_topic *topic_response;
	struct dl_produce_response_partition *partition_response;
	int32_t partition;

	DL_ASSERT(response != NULL, ("ProduceResponse cannot be NULL\n."));
	DL_ASSERT(response->dlpr_ntopics > 0,
	    ("Non-primitive [topic_data] array is not NULLABLE"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL.\n"));

	/* Encode the number of responses in the response array. */
	dl_buf_put_int32(target, response->dlpr_ntopics);

	SLIST_FOREACH(topic_response, &response->dlpr_topics, dlprt_entries) {

		DL_ASSERT(topic_response->dlprt_npartitions > 0,
		    "Non-primitive [response_data] array is not NULLABLE");

		/* Encode the TopicName. */
		DL_ENCODE_TOPIC_NAME(target, topic_response->dlprt_topic_name);

		/* Encode the Topic partitions. */
		dl_buf_put_int32(target, topic_response->dlprt_npartitions);

		for (partition = 0; topic_response->dlprt_npartitions;
		    partition++) {
			partition_response =
			    &topic_response->dlprt_partitions[partition];

			/* Encode the BaseOffset. */
			DL_ENCODE_OFFSET(target,
			    partition_response->dlprp_offset);
			
			/* Encode the ErrorCode. */
			DL_ENCODE_ERROR_CODE(target,
			    partition_response->dlprp_partition);

			/* Encode the Partition. */
			DL_ENCODE_PARTITION(target,
			    partition_response->dlprp_error_code);
		}
	}
	
	/* Encode the ThrottleTime. */
	DL_ENCODE_THROTTLE_TIME(target, response->dlpr_throttle_time);

	return 0;
}

