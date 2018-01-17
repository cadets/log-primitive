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
#include "dl_fetch_request.h"
#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_primitive_types.h"
#include "dl_request.h"

void
dl_fetch_request_new(struct dl_request *req_msg,
    int32_t correlation_id, char *client_id, va_list varlist)
{
	struct dl_fetch_request *request;
	long timestamp;
	int message_it;

	DL_ASSERT(req_msg != NULL, "Request message cannot be NULL");
	    
	char *topic_name = va_arg(varlist, char*);
	long fetch_offset = va_arg(varlist, long);
	int maxbytes = va_arg(varlist, int);
	int minbytes = va_arg(varlist, int);

	printf("fetch request topic = %s\n", topic_name);
	printf("fetch request address = %p\n", req_msg);
	
	/* Construct the produce request header. */	
	req_msg->dlrqm_api_key = DL_FETCH_REQUEST;
	req_msg->dlrqm_api_version = 1; // TODO: fixed version of API
	req_msg->dlrqm_correlation_id = correlation_id;
	strlcpy(req_msg->dlrqm_client_id, client_id, DL_MAX_CLIENT_ID);

        /* Construct the fetch request body. */
	request = &req_msg->dlrqm_message.dlrqmt_fetch_request;

	request->dlfr_replica_id = -1;
	request->dlfr_max_wait_time = 1000;
	request->dlfr_min_bytes = minbytes;
	strlcpy(request->dlfr_topic_name, topic_name, DL_MAX_TOPIC_NAME_LEN);
	request->dlfr_partition = 0;
	request->dlfr_fetch_offset = fetch_offset;
	request->dlfr_max_bytes = maxbytes;
}

int
dl_encode_fetch_request(struct dl_fetch_request *request, char *buffer)
{
	int32_t request_size = 0;

	DL_ASSERT(request != NULL, "Fetch request cannot be NULL");
	DL_ASSERT(buffer != NULL,
	    "Buffer used to encode fetch request cannot be NULL");

	/* Encode the FetchRequest ReplicaId into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlfr_replica_id);

	/* Encode the FetchRequest MaxWaitTime into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlfr_max_wait_time);

	/* Encode the FetchRequest MinBytes into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlfr_min_bytes);

	// TODO
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the FetchRequest Topic Name into the buffer. */
	request_size += dl_encode_string(&buffer[request_size],
	    request->dlfr_topic_name, 255); // TODO: DL_MAX_TOPIC_NAME

	// TODO:
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the FetchRequest Partition into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlfr_partition);

	/* Encode the FetchRequest FetchOffset into the buffer. */
	request_size += dl_encode_int64(&buffer[request_size],
	    request->dlfr_fetch_offset);

	/* Encode the FetchRequest MaxBytes into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlfr_max_bytes);
	
	return request_size;
}
