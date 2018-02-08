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

#define DL_DECODE_TOPIC_NAME(target, source) \
    dl_decode_string(target, source)

static struct dl_produce_partition_responses *
    dl_decode_produce_partition_responses(char *);

struct dl_produce_response *
dl_decode_produce_response(char *source)
{
	struct dl_produce_partition_responses *partition_response;
	struct dl_produce_response *produce_response;
	struct dl_produce_responses *response;
	int32_t partition_response_it, response_it, n_responses,
		n_partition_responses;
	int16_t topic_name_len;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Allocate and initialise the produce_response instance. */
	produce_response = (struct dl_produce_response *)
	    dlog_alloc(sizeof(struct dl_produce_response));
	SLIST_INIT(&produce_response->dlpr_responses);

	/* Decode the number of responses in the response array. */
	n_responses = dl_decode_int32(source);
	DL_ASSERT(n_responses > 0,
	    "Non-primitive array types are not NULLABLE");

	/* Decode the responses. */
	for (response_it = 0; response_it < n_responses; response_it++) {

		/* Allocate, decode and enque each response. */
		response = (struct dl_produce_responses *)
		    dlog_alloc(sizeof(struct dl_produce_responses));

		SLIST_INIT(&response->dlprs_partition_responses);

		/* Decode the TopicName. */
		DL_DECODE_TOPIC_NAME(response->dlprs_topic_name, source);
		
		SLIST_INSERT_HEAD(&produce_response->dlpr_responses, response,
		    dlprs_entries);

		n_partition_responses = dl_decode_int32(source);

		for (partition_response_it = 0;
		    partition_response_it < n_partition_responses;
		    partition_response_it++) {

			/* Decode the partition responses. */
			partition_response =
			    dl_decode_produce_partition_responses(source);
			SLIST_INSERT_HEAD(&response->dlprs_partition_responses,
			    partition_response, dlpprs_entries);
		}
	}

	return produce_response;
}

static struct dl_produce_partition_responses * 
dl_decode_produce_partition_responses(char *source)
{
	struct dl_produce_partition_responses *partition_response;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	
	partition_response = (struct dl_produce_partition_responses *)
	    dlog_alloc(sizeof(struct dl_produce_partition_responses));

	/* Decode the Partition */
	partition_response->dlpprs_partition = dl_decode_int32(source);

	/* Decode the ErrorCode */
	partition_response->dlpprs_error_code = dl_decode_int16(source);

	/* Decode the BaseOffset */
	partition_response->dlpprs_base_offset = dl_decode_int64(source);

	return partition_response;
}
