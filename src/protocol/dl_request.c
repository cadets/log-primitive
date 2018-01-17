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

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#include "dl_assert.h"
#include "dl_common.h"
#include "dl_fetch_request.h"
#include "dl_list_offset_request.h"
#include "dl_produce_request.h"
#include "dl_protocol.h"
#include "dl_primitive_types.h"
#include "dl_request.h"
#include "dl_utils.h"

#define DL_ENCODE_API_KEY(buffer, value) dl_encode_int16(buffer, value)
#define DL_ENCODE_CORRELATION_ID(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_API_VERSION(buffer) \
    dl_encode_int16(buffer, DISTLOG_API_VERSION)
#define DL_ENCODE_CLIENT_ID(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_CLIENT_ID)
#define DL_ENCODE_SIZE(buffer, value) dl_encode_int32(buffer, value)

static int32_t dl_encode_request_header(struct dl_request * const,
    char const *);
static int32_t dl_encode_request_size(char const *, const int32_t);
static int dl_decode_request_header(struct dl_request *, char *);

/**
 * Encode the Request.
 *
 * Request = Size RequestHeader ProduceRequest|FetchRequest|OffsetRequest
 *
 */
// TODO: should this also take the buffer size?
int
dl_encode_request(struct dl_request const *request,
    struct dl_buffer const *buffer)
{
	int32_t request_size = 0;
	char *request_body, *request_header;
	
	DL_ASSERT(request != NULL, "Request cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer for encoding cannot be NULL");
	DL_ASSERT(buffer->dlb_hdr.dlbh_len > 0,
	    "Buffer for encoding smaller than minimum size");

	/*
	 * Skip the Request Size. This is determined by encoding the request
	 * and then is added to the buffer once known.
	 */
	request_header = buffer->dlb_databuf + sizeof(uint32_t);
	
	/* Encode the Request Header. */
	request_size += dl_encode_request_header(request, request_header);
	request_body = request_header + request_size;

	/* Encode the Request Body. */
	switch (request->dlrqm_api_key) {
	case DL_PRODUCE_REQUEST:
		request_size += dl_encode_produce_request(
		    &request->dlrqm_message.dlrqmt_produce_request,
		    request_body);
		break;
	case DL_FETCH_REQUEST:
		request_size += dl_encode_fetch_request(
		    &request->dlrqm_message.dlrqmt_fetch_request,
		    request_body);
		break;
	case DL_OFFSET_REQUEST:
		request_size += dl_encode_listoffset_request(
		    &request->dlrqm_message.dlrqmt_offset_request,
		    request_body);
		break;
	default:
		DISTLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
		    request->dlrqm_api_key);
		return -1;
		break;
	}

	/* Now that the size is known encode this in the Request Size. */ 
	request_size += dl_encode_request_size(buffer->dlb_databuf,
	    request_size);

	return request_size;
}

/**
 * Encode the Request Size.
 *
 * Size (int32): The number of bytes in the Request (that is the number
 * of bytes after the Size field)
 */
static int32_t 
//dl_encode_request_size(struct dl_buffer const *buffer, const int32_t size)
dl_encode_request_size(char const *buffer, const int32_t size)
{
	DL_ASSERT(buffer != NULL, "Buffer for encoding cannot be NULL");
	DL_ASSERT(size > 0, "Request size must be greater than zero");

	/* Encode the Request Size. */
	return DL_ENCODE_SIZE(buffer, size);
}

/**
 * Encode the RequestHeader.
 *
 * RequestHeader = APIKey APIVersion CorrelationId ClientId
 *  
 * APIKey
 * APIVersion
 * CorrelationId
 * ClientId
 */
static int32_t 
//dl_encode_request_header(struct dl_request * const request,
//    struct dl_buffer const *buffer)
dl_encode_request_header(struct dl_request * const request,
    char const *buffer)
{
	int32_t req_header_size = 0;
	
	DL_ASSERT(request!= NULL, "Request cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer for encoding cannot be NULL");

	/* Encode the Request APIKey into the buffer. */
	req_header_size += DL_ENCODE_API_KEY(&buffer[req_header_size],
	    request->dlrqm_api_key);

	/* Encode the Request APIVersion into the buffer. */
	req_header_size += DL_ENCODE_API_VERSION(&buffer[req_header_size]);

	/* Encode the Request CorrelationId into the buffer. */
	req_header_size += DL_ENCODE_CORRELATION_ID(&buffer[req_header_size],
	    request->dlrqm_correlation_id);

	/* Encode the Request ClientId into the buffer. */
	req_header_size += DL_ENCODE_CLIENT_ID(&buffer[req_header_size],
	    request->dlrqm_client_id);

	return req_header_size;
}

int
dl_decode_request(struct dl_request *request, char *buffer)
{
	ssize_t request_size;
	char *request_header = buffer, *request_body;

	/* Decode the Request Header into the buffer. */
	request_size = dl_decode_request_header(request, buffer);
	
	request_body = buffer + request_size;

	/* Decode the Request Body into the buffer. */
	switch (request->dlrqm_api_key) {
	case DL_PRODUCE_REQUEST:
		request_size += dl_decode_produce_request(
			&request->dlrqm_message.dlrqmt_produce_request,
			request_body);
		break;
	case DL_FETCH_REQUEST:
		//request_size += dl_encode_fetch_request(
		//	&request->dlrqm_message.dlrqmt_fetch_request,
		//	request_body);
		break;
	case DL_OFFSET_REQUEST:
		//request_size += dl_encode_offset_request(
		//	&request->dlrqm_message.dlrqmt_offset_request,
		//	request_body);
		break;
	default:
		DISTLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
			request->dlrqm_api_key);
		return -1;
		break;
	}

	return request_size;
}
	
static int
dl_decode_request_header(struct dl_request *request, char *buffer)
{
	ssize_t header_size = 0;

	/* Decode the Request Size. */
	request->dlrqm_size = dl_decode_int16(buffer);
	header_size += sizeof(int16_t);

	/* Decode the Request APIKey. */
	request->dlrqm_api_key = dl_decode_int16(&buffer[header_size]);
	header_size += sizeof(int16_t);

	/* Decode the Request APIVersion. */
	request->dlrqm_api_version = dl_decode_int16(&buffer[header_size]);
	header_size += sizeof(int16_t);

	/* Decode the Request CorrelationId. */
	request->dlrqm_correlation_id = dl_decode_int32(&buffer[header_size]);
	header_size += sizeof(int32_t);

	/* Decode the Request ClientId. */
	header_size += dl_decode_string(&buffer[header_size],
	    request->dlrqm_client_id);

	return header_size;
}

