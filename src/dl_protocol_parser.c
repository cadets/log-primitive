/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#include <string.h>
#include <stdio.h>

// TODO: remove these
//#include "message.h"
//#include "dl_protocol_common.h"

#include "dl_memory.h"
#include "dl_protocol.h"

static int
dl_decode_int8(char const * buffer)
{
	return *((int8_t *) buffer);
}

static int
dl_decode_int16(char const * buffer)
{
	return be16toh(*((int32_t *) buffer));
}

static int32_t
dl_decode_int32(char const * buffer)
{
	return be32toh(*((int32_t *) buffer));
}

static int
dl_decode_int64(char const * buffer)
{
	return be64toh(*((int64_t *) buffer));
}

static int
dl_decode_string(char * buffer, char * string)
{
	int string_len, decoded_len = 0;
	/* Decode the string length */
	string_len = dl_decode_int16(buffer);
	decoded_len += sizeof(int16_t);

	/* Strings NULLABLE, therefore first check whether there is a value
	 * to decode.
	 */
	if (dl_decode_int32(&buffer[sizeof(int16_t)]) == -1) {
		decoded_len += sizeof(int32_t);
	} else {
		strlcpy(string, &buffer[sizeof(int16_t)], string_len+1);
		decoded_len += string_len;
	}

	return decoded_len;
}

int
dl_decode_offset_response(struct dl_offset_response *response,
    char *buffer)
{
	int32_t partition_response, response_it;
	int16_t topic_name_len;
       
	dl_decode_int32(buffer);
	buffer += sizeof(int32_t);

	/* Decode the TopicName */
	topic_name_len = dl_decode_string(buffer,
		response->dlors_topic_name);
	buffer += topic_name_len;
	printf("topic name = %s\n", response->dlors_topic_name);

	// No. partition offsets	
	dl_decode_int32(buffer);
	buffer += sizeof(int32_t);
	
	/* Decode the Partition */
	dl_decode_int32(buffer);
	buffer += sizeof(int32_t);
	
	/* Decode the ErrorCode */
	printf("ec = %d\n", dl_decode_int16(buffer));
	buffer += sizeof(int16_t);
	
	/* Decode the Timestamp */
	printf("ts = %d\n", dl_decode_int64(buffer));
	buffer += sizeof(int64_t);

	/* Decode the Offset*/
	response->dlors_offset = dl_decode_int64(buffer);
	printf("off = %d\n", response->dlors_offset);
	buffer += sizeof(int64_t);

	return 0;
}

int
dl_decode_fetch_response(struct dl_fetch_response *response,
    char *buffer)
{
	int32_t partition_response, response_it;
	int16_t topic_name_len;
        
	/* Decode the ThrottleTime */	
	response->dlfrs_throttle_time = dl_decode_int32(buffer);
	buffer += sizeof(int32_t);

        /* Decode the responses */	
	response->dlfrs_num_responses = dl_decode_int32(buffer);
	buffer += sizeof(int32_t);
	// TODO: Careful the responses can be NULL
	if (response->dlfrs_num_responses == -1) {
	}

	printf("num responses = %d\n", response->dlfrs_num_responses);

	response->dlfrs_responses = (struct dl_fr_response *) distlog_alloc(
	    response->dlfrs_num_responses * sizeof(struct dl_fr_response));

	for (response_it = 0; response_it < response->dlfrs_num_responses;
	    response_it++) {
		struct dl_fr_response *fetch_response =
		    &response->dlfrs_responses[response_it];

		/* Decode the TopicName */
		topic_name_len = dl_decode_string(buffer,
		    fetch_response->dl_fr_topic_name);
		buffer += topic_name_len;
		printf("topic name = %s\n", fetch_response->dl_fr_topic_name);

		/* Decode the partition responses */	
		fetch_response->dl_fr_num_partition_responses =
		    dl_decode_int32(buffer);
		buffer += sizeof(int32_t);
		printf("partition responses = %d\n", fetch_response->dl_fr_num_partition_responses);

		fetch_response->dl_fr_partition_responses = 
		    (struct dl_fr_partition_response *) distlog_alloc(
		    fetch_response->dl_fr_num_partition_responses *
		    sizeof(struct dl_fr_partition_response));

		for (partition_response = 0;
		    partition_response < fetch_response->dl_fr_num_partition_responses;
		    partition_response++) {

			struct dl_fr_partition_response *pr =
			    &fetch_response->dl_fr_partition_responses[partition_response];

			/* Decode the Partition */
			pr->dlfrpr_partition = dl_decode_int32(buffer);
			buffer += sizeof(int32_t);

			/* Decode the ErrorCode */
		    	pr->dlfrpr_error_code = dl_decode_int16(buffer);
			printf("error code = %d\n", pr->dlfrpr_error_code);
			buffer += sizeof(int16_t);

			/* Decode the HighWatermark*/
		    	pr->dlfrpr_high_watermark = dl_decode_int64(buffer);
			buffer += sizeof(int64_t);

			/* Decode the MessageSetSize */
		    	int32_t mss = dl_decode_int32(buffer);
			buffer += sizeof(int32_t);
			
			// TODO decode the MessageSet
		    	dl_decode_int64(buffer);

		    	dl_decode_int32(buffer);
		}
	}
	return 0;
}

int
dl_decode_produce_response(struct dl_produce_response *response,
    char *buffer)
{
	int32_t partition_response, response_it;
	int16_t topic_name_len;

        /* Decode the responses */	
	response->dlprs_num_responses = dl_decode_int32(buffer);
	// TODO: Careful the responses can be NULL
	if (response->dlprs_num_responses == -1) {
	}

	buffer += sizeof(int32_t);
	printf("num responses = %d\n", response->dlprs_num_responses);

	response->dlprs_responses = (struct dl_pr_response *) distlog_alloc(
	    response->dlprs_num_responses * sizeof(struct dl_pr_response));

	for (response_it = 0; response_it < response->dlprs_num_responses;
	    response_it++) {

		struct dl_pr_response *produce_response =
		    &response->dlprs_responses[response_it];

		/* Decode the TopicName */
		topic_name_len = dl_decode_string(buffer,
		    produce_response->dl_pr_topic_name);
		buffer += topic_name_len;
		printf("topic name = %s\n", produce_response->dl_pr_topic_name);

		/* Decode the partition responses */	
		produce_response->dlr_num_partition_responses =
		    dl_decode_int32(buffer);

		produce_response->dlr_partition_responses = distlog_alloc(
		    produce_response->dlr_num_partition_responses * sizeof(struct dl_pr_partition_response));

		for (partition_response = 0;
		    partition_response < produce_response->dlr_num_partition_responses;
		    partition_response++) {

			struct dl_pr_partition_response *pr =
			    &produce_response->dlr_partition_responses[partition_response];

			/* Decode the Partition */
			pr->dlpr_partition = dl_decode_int32(buffer);

			/* Decode the ErrorCode */
		    	pr->dlpr_error_code = dl_decode_int16(buffer);
			printf("error code = %d\n", pr->dlpr_error_code);

			/* Decode the BaseOffset */
		    	pr->dlpr_base_offset = dl_decode_int64(buffer);
		}
	}
	return 0;
}

// response header?
int
dl_decode_response(struct dl_response *response, char *buffer)
{
        /* Decode the Size */	
	response->dlrs_size = dl_decode_int32(buffer);

        /* Decode the CorrelationId */	
	response->dlrs_correlation_id = dl_decode_int32(
	    &buffer[sizeof(int32_t)]);

	return 0;
}

int
dl_decode_request_or_response(struct dl_request_or_response *req_or_res,
    char *buffer)
{
        /* Decode the Size */	
	req_or_res->dlrx_size = dl_decode_int32(buffer);
	buffer += sizeof(int32_t);

	return sizeof(int32_t);
}
