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


