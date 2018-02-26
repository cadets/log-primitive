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
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

static int32_t dl_encode_response_header(struct dl_response const * const,
    char * const);
static int32_t dl_encode_response_size(char const *, const int32_t);

#define DL_ENCODE_CORRELATION_ID(source, value) dl_encode_int32(source, value)
#define DL_ENCODE_SIZE(buffer, value) dl_encode_int32(buffer, value)

// response header?
int
dl_decode_response(struct dl_response *response, char *source)
{
	DL_ASSERT(response != NULL, "Response message cannot be NULL\n");
	DL_ASSERT(source != NULL, "Source buffer cannot be NULL\n");

        /* Decode the Size */	
	response->dlrs_size = dl_decode_int32(source);

        /* Decode the CorrelationId */	
	response->dlrs_correlation_id = dl_decode_int32(
	    &source[sizeof(int32_t)]);

	return 0;
}

int32_t
dl_response_encode(struct dl_response *response, char *target)
{
	int32_t response_size = 0;
	char *response_body, *response_header;

	DL_ASSERT(response != NULL, "Response message cannot be NULL\n");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL\n");

	/* Encode the Response Header. */
	response_header = target + sizeof(int32_t);

	response_size += dl_encode_response_header(response, response_header);
	response_body = response_header + response_size;
	
	printf("Response size = %d\n", response_size);

	switch (response->dlrs_api_key) {
		case DL_OFFSET_REQUEST:
			DLOGTR0(PRIO_LOW, "Encoding ListOffsetResponse...\n");

			response_size += dl_list_offset_response_encode(
			    response->dlrs_message.dlrs_offset_response,
			    response_body);
			break;
		case DL_PRODUCE_REQUEST:
			DLOGTR0(PRIO_LOW, "Encoding ProduceResponse...\n");

			response_size += dl_produce_response_encode(
			    response->dlrs_message.dlrs_offset_response,
			    response_body);
			break;
	}

	printf("Response size = %d\n", response_size);

	/* Now that the size is known, encode this in the Request Size. */ 
	response_size += dl_encode_response_size(target, response_size);

	return response_size;
}

/**
 * Encode the Response Size.
 *
 * Size (int32): The number of bytes in the Response (that is the number
 * of bytes after the Size field)
 */
static int32_t 
//dl_encode_request_size(struct dl_buffer const *buffer, const int32_t size)
dl_encode_response_size(char const *buffer, const int32_t size)
{

	DL_ASSERT(buffer != NULL, "Buffer for encoding cannot be NULL");
	DL_ASSERT(size > 0, "Request size must be greater than zero");

	/* Encode the Response Size. */
	return DL_ENCODE_SIZE(buffer, size);
}

/**
 * Encode the ResponseHeader.
 *
 * ResponseHeader = CorrelationId
 *  
 * CorrelationId
 */
static int32_t 
//dl_encode_request_header(struct dl_request * const request,
//    struct dl_buffer const *buffer)
dl_encode_response_header(struct dl_response const * const response,
    char * const target)
{

	DL_ASSERT(response != NULL, "Response cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the Response CorrelationId into the buffer. */
	return DL_ENCODE_CORRELATION_ID(target, response->dlrs_correlation_id);
}
