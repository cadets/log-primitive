/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * Copyright (c) 2017 (Graeme Jenkinson)
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

// TODO: CRC generation in kernel
#include <zlib.h>

#include "dl_assert.h"
#include "dl_protocol.h"
#include "dl_utils.h"

static int dl_encode_int8(char *, const int8_t);
static int dl_encode_int16(char *, const int16_t);
static int dl_encode_int32(char *, const int32_t);
static int dl_encode_int64(char *, const int64_t);
static int dl_encode_string(char *, char *);
static int dl_encode_bytes(char *, char *, const int);
static ssize_t dl_encode_request_size(char const *, ssize_t);
static ssize_t dl_encode_request_header(struct dl_request * const,
    char const *);
static int dl_encode_produce_request(struct dl_produce_request *, char *);
static int dl_encode_fetch_request(struct dl_fetch_request *, char *);
static int dl_encode_offset_request(struct dl_offset_request *, char *);

static int
dl_encode_int8(char * buffer, const int8_t value)
{
	*((int8_t *) buffer) = value;
	return sizeof(int8_t);
}

static int
dl_encode_int16(char * buffer, const int16_t value)
{
	*((int16_t *) buffer) = htobe16(value);
	return sizeof(int16_t);
}

static int
dl_encode_int32(char * buffer, const int32_t value)
{
	*((int32_t *) buffer) = htobe32(value);
	return sizeof(int32_t);
}

static int
dl_encode_int64(char * buffer, const int64_t value)
{
	*((int64_t *) buffer) = htobe64(value);
	return sizeof(int64_t);
}

/**
 * Encoded strings are prefixed with their length (int16).
 */
static int
dl_encode_string(char * buffer, char * string)
{
	ssize_t encoded_size = 0;

	encoded_size += dl_encode_int16(&buffer[encoded_size], strlen(string));

	// TODO: Permitted callers to specify maximum size; or use a global
	// maximum
	strlcpy(&buffer[encoded_size], string, 255); //DL_MAX_CLIENT_ID);
	encoded_size += strlen(string);

	return encoded_size;
}

/**
 * Encoded byte arrays are prefixed with their length (int32).
 */
static int
dl_encode_bytes(char * buffer, char * bytes, const int len_bytes)
{
	ssize_t encoded_len_bytes = 0;

	/* Prepended a 32bit value indicating the length (in bytes). */
	encoded_len_bytes = dl_encode_int32(buffer, len_bytes);

	memcpy(&buffer[sizeof(int32_t)], bytes, len_bytes);
	encoded_len_bytes += len_bytes;

	return encoded_len_bytes;
}

int
dl_encode_request(struct dl_request const *request, char const *buffer)
{
	int32_t request_size = 0;
	char *request_header = buffer, *request_body;

	/* Encode the Request Header into the buffer. */
	request_size += dl_encode_request_header(request, request_header);

	request_body = buffer + request_size;

	/* Encode the Request Body into the buffer. */
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
		request_size += dl_encode_offset_request(
			&request->dlrqm_message.dlrqmt_offset_request,
			request_body);
		break;
	default:
		DISTLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
			request->dlrqm_api_key);
		return -1;
		break;
	}

	/* Now that the size is known encode this in the request. */ 
	request_size += dl_encode_request_size(request_header, request_size);

	return request_size;
}


static ssize_t
dl_encode_request_size(char const * buffer, ssize_t size)
{
	/* Encode the Request Size . */
	return dl_encode_int32(buffer, size);
}

static ssize_t
dl_encode_request_header(struct dl_request * const request,
    char const * buffer)
{
	ssize_t req_header_size = 0;

	/* Skip the Request Size until known. */
	req_header_size += sizeof(uint32_t);

	/* Encode the Request Header into the buffer. */

	/* Encode the Request APIKey into the buffer. */
	req_header_size += dl_encode_int16(&buffer[req_header_size],
	    request->dlrqm_api_key);

	/* Encode the Request APIVersion into the buffer. */
	// TODO the API version should be fixed (or felxible once
	// the solution is fleshed out).
	// DISTLOG_API_VERSION 1
	req_header_size += dl_encode_int16(&buffer[req_header_size],
	    1); //request->dlrqm_api_version);

	/* Encode the Request CorrelationId into the buffer. */
	req_header_size += dl_encode_int32(&buffer[req_header_size],
	    request->dlrqm_correlation_id);

	/* Encode the Request ClientId into the buffer. */
	req_header_size += dl_encode_string(&buffer[req_header_size],
	    request->dlrqm_client_id);

	return req_header_size;
}

static int
dl_encode_produce_request(struct dl_produce_request *produce_request,
    char *buffer)
{
	uint8_t *ms, *mss, *temp = buffer;
	int32_t message_set_size = 0, message_size = 0, request_size = 0;

	DL_ASSERT(produce_request != NULL, "ProduceRequest cannot be NULL");
	DL_ASSERT(buffer != NULL,
	    "Buffer used to encode ProduceRequest cannot be NULL");

	/* Encode the Request RequiredAcks into the buffer. */
	request_size += dl_encode_int16(&buffer[request_size],
	    produce_request->dlpr_required_acks);

	/* Encode the Request Timeout into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    produce_request->dlpr_timeout);

	/* TODO: New function for encoding Topic Data */ 
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the Request TopicName into the buffer. */
	request_size += dl_encode_string(&buffer[request_size],
	    produce_request->dlpr_topic_name);

	/* TODO: New function for encoding Topic Data */ 
	//dl_encode_topic_data(struct dl_produce_request *produce_request,
	//    buffer);
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the Request Partition into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    produce_request->dlpr_partition);

	/* TODO: encode the MessageSet size */
	message_set_size = 0;
	mss = &buffer[request_size];
	request_size += sizeof(produce_request->dlpr_message_set_size);
		
	/* Encode the MessageSet Offset into the buffer. */
	request_size += dl_encode_int64(&buffer[request_size], 1234);

	/* TODO: encode the MessageSet size */
	ms = &buffer[request_size];
	request_size += sizeof(int32_t);

	struct dl_message *message =
	    &produce_request->dlpr_message_set[0].dlms_message;
	
	message_size = 0;

	/* Encode the Message Crc into the buffer. */
	char * crc_field = &buffer[request_size];
	message_size += sizeof(int32_t);

	/* Encode the Message Magic into the buffer. */
	char *crc_start = &buffer[request_size+message_size];
	int crc_start_size = message_size;
	message_size += dl_encode_int8(&buffer[request_size+message_size],
	    message->dlm_magic_byte);

	/* Encode the Message Attributes into the buffer. */
	message_size += dl_encode_int8(&buffer[request_size+message_size],
	    message->dlm_attributes);

	/* Encode the Message Timestamp into the buffer. */
	message_size += dl_encode_int64(&buffer[request_size+message_size],
	    message->dlm_timestamp);

	/* Encode the Message Key into the buffer. */
	// TODO: currently this is NULL
	message_size += dl_encode_int32(&buffer[request_size+message_size], -1);

	/* Encode the Message Value into the buffer. */
	message_size += dl_encode_bytes(&buffer[request_size+message_size],
	    message->dlm_value, strlen(message->dlm_value));
	
	/* ... */

	/* Encode the Message Crc into the buffer. */
	unsigned long crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, crc_start, message_size - crc_start_size);
	dl_encode_int32(crc_field, crc);

	/* Encode the Message Size into the buffer. */
	dl_encode_int32(ms, message_size);

	/* Encode the MessageSet Size into the buffer. */
	message_set_size += message_size;
	dl_encode_int32(mss, message_set_size + 12);

	request_size += message_set_size;
	
	return request_size;
}

static int
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
	    request->dlfr_topic_name);

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

static int
dl_encode_offset_request(struct dl_offset_request *request, char *buffer)
{
	int32_t request_size = 0;

	DL_ASSERT(request != NULL, "Offset request cannot be NULL");
	DL_ASSERT(buffer != NULL,
	    "Buffer used to encode fetch request cannot be NULL");

	/* Encode the OffsetRequest ReplicaId into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlor_replica_id);
	
	// TODO
	request_size += dl_encode_int32(&buffer[request_size], 1);
	
	/* Encode the OffsetRequest Topic Name into the buffer. */
	request_size += dl_encode_string(&buffer[request_size],
	    request->dlor_topic_name);

	// TODO
	request_size += dl_encode_int32(&buffer[request_size], 1);
	
	/* Encode the OffsetRequest Partition into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    request->dlor_partition);
	
	// TODO: Earliest
	request_size += dl_encode_int64(&buffer[request_size],
	    request->dlor_time);
	
	return request_size;
}
