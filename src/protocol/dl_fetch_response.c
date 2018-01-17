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

#include <stdarg.h>
#include <string.h>

#include "dl_assert.h"
#include "dl_fetch_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"

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


