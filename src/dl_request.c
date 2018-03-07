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

#include <stddef.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_fetch_request.h"
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_produce_request.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

static int dl_request_header_encode(struct dl_request const * const,
    struct dl_buf *);
static int32_t dl_request_size_encode(char const *, const int32_t);
static int dl_request_header_decode(struct dl_request *, struct dl_buf *);

/**
 * Request constructor.
 */
struct dl_request *
dl_request_new(const int16_t api_key, const int32_t correlation_id,
    struct sbuf *client_id)
{
	struct dl_request *request;
	
	request = (struct dl_request *) dlog_alloc(sizeof(struct dl_request));
#ifdef KERNEL
	DL_ASSERT(request != NULL, *"Allocation for Request failed"));
	{
#else
	if (request != NULL) {
#endif
		request->dlrqm_api_key = api_key;
		request->dlrqm_correlation_id = correlation_id;
		request->dlrqm_client_id = client_id;
	}
	return request;
}

/**
 * Encode the Request.
 *
 * Request = Size RequestHeader ProduceRequest|FetchRequest|OffsetRequest
 *
 */
int
dl_request_encode(struct dl_request const *request, struct dl_buf **target)
{

	DL_ASSERT(request != NULL, ("Request cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/*
	 * Skip the Request Size. This is determined by encoding the request
	 * and then is added to the buffer once known.
	 */
	//request_header = &buffer->dlb_hdr.dlbh_data[sizeof(int32_t)];

	/* Allocate and initialise a buffer to encode the request. */
	if (dl_buf_new(target, NULL, DL_MTU,
	    DL_BUF_FIXEDLEN|DL_BUF_BIGENDIAN) == 0) {
		
		/* Encode the Request Header. */
		if (dl_request_header_encode(request, *target) == 0) {

			/* Encode the Request Body. */
			switch (request->dlrqm_api_key) {
			case DL_PRODUCE_API_KEY:
				return dl_produce_request_encode(
				    request->dlrqm_message.dlrqmt_produce_request,
				    *target);
				break;
			case DL_FETCH_API_KEY:
				return dl_fetch_request_encode(
				request->dlrqm_message.dlrqmt_fetch_request,
				*target);
				break;
			case DL_OFFSET_API_KEY:
				return dl_list_offset_request_encode(
				request->dlrqm_message.dlrqmt_offset_request,
				*target);
				break;
			default:
				DLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
				request->dlrqm_api_key);
				return -1;
			}
		} else {
			DLOGTR0(PRIO_LOW, "Failed encoding request header.\n");
			return -1;
		}

		/* Now that the size is known, encode this in the Request Size. */ 
		//request_size += dl_request_size_encode(buffer->dlb_databuf,
		//    request_size);
	}
	return 0;
}

/**
 * Encode the Request Size.
 *
 * Size (int32): The number of bytes in the Request (that is the number
 * of bytes after the Size field)
 */
static int32_t 
//dl_request_size_encode(struct dl_buffer const *buffer, const int32_t size)
dl_request_size_encode(char const *buffer, const int32_t size)
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
static int
dl_request_header_encode(struct dl_request const * const request,
    struct dl_buf *buffer)
{
	
	DL_ASSERT(request!= NULL, "Request cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer for encoding cannot be NULL");

	/* Encode the Request APIKey into the buffer. */
	if (DL_ENCODE_API_KEY(buffer, request->dlrqm_api_key) != 0)
		goto err;

	/* Encode the Request APIVersion into the buffer. */
	if (DL_ENCODE_API_VERSION(buffer, DLOG_API_VERSION) != 0)
		goto err;

	/* Encode the Request CorrelationId into the buffer. */
	if (DL_ENCODE_CORRELATION_ID(buffer,
	    request->dlrqm_correlation_id) != 0)
		goto err;

	/* Encode the Request ClientId into the buffer. */
	if (DL_ENCODE_CLIENT_ID(buffer, request->dlrqm_client_id) != 0)
		goto err;

	return 0;
err:
	return -1;
}

struct dl_request *
dl_request_decode(char *source)
{
	struct dl_request *request;
	ssize_t request_size;
	char *request_header = source, *request_body;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	request = (struct dl_request *) dlog_alloc(sizeof(struct dl_request));
	DL_ASSERT(request != NULL, "Allocation of Request failed");

	/* Decode the Request Header into the buffer. */
	request_size = dl_request_header_decode(request, source);
	
	request_body = source + request_size;

	/* Decode the Request Body into the buffer. */
	switch (request->dlrqm_api_key) {
	case DL_PRODUCE_API_KEY:
		request->dlrqm_message.dlrqmt_produce_request =
		    dl_produce_request_decode(request_body);
		break;
	case DL_FETCH_API_KEY:
		//request_size += dl_decode_fetch_request(
		//	&request->dlrqm_message.dlrqmt_fetch_request,
		//	request_body);
		break;
	case DL_OFFSET_API_KEY:
		request->dlrqm_message.dlrqmt_offset_request =
		    dl_list_offset_request_decode(request_body);
		break;
	default:
		DLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
			request->dlrqm_api_key);
		return NULL;
		break;
	}

	return request;
}
	
static int
dl_request_header_decode(struct dl_request *request, struct dl_buf *source)
{
	int16_t api_version;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	/* Decode the Request Size. */
	// TODO: verify that the size checks out
	//printf("size = %d\n", dl_decode_int32(source));

	/* Decode the Request APIKey. */
	DL_DECODE_API_KEY(source, &request->dlrqm_api_key);

	/* Decode the Request APIVersion. */
	DL_DECODE_API_VERSION(source, &api_version);
	// TODO: Check API version is supported

	/* Decode the Request CorrelationId. */
	DL_DECODE_CORRELATION_ID(source, &request->dlrqm_correlation_id);

	/* Decode the Request ClientId. */
	DL_DECODE_CLIENT_ID(source, &request->dlrqm_client_id);

	return 0;
}

