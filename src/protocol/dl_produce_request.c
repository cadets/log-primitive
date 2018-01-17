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
//#include <stdio.h>
//#include <stdarg.h>

#include <sys/types.h>
#include <stdint.h>

// TODO: CRC generation in kernel libkern/crc32.c
#include <zlib.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_produce_request.h"
#include "dl_request.h"

#define DL_ENCODE_TOPIC_NAME(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_TOPIC_NAME_LEN)

void
dl_produce_request_new(struct dl_request *req_msg,
    int32_t correlation_id, char *client_id, va_list varlist)
{
	struct dl_produce_request *produce_request;
	long timestamp;
	int message_it;
	char *topic_name;
	int nmessages;

	DL_ASSERT(req_msg != NULL, "Request message cannot be NULL");
	    
	topic_name = va_arg(varlist, char*);
	nmessages = va_arg(varlist, int);

	/* Construct the produce request header. */	
	req_msg->dlrqm_api_key = DL_PRODUCE_REQUEST;
	// TODO remove this?
	req_msg->dlrqm_api_version = 1; // TODO: fixed version of API
	req_msg->dlrqm_correlation_id = correlation_id;
	// TODO: what should be done with the ClientId
	strlcpy(req_msg->dlrqm_client_id, client_id, DL_MAX_CLIENT_ID);

        /* Construct the produce request body. */
	produce_request = &req_msg->dlrqm_message.dlrqmt_produce_request;

	// TODO: surely this comes from the client or the configuration
	produce_request->dlpr_required_acks = 1;
	// TODO: the time to await a response
	produce_request->dlpr_timeout = 0; //-1;
	strlcpy(produce_request->dlpr_topic_name, topic_name,
	    DL_MAX_TOPIC_NAME_LEN);
	// TODO :default partition = 0
	produce_request->dlpr_partition = 0;
	
	timestamp = time(NULL);
	produce_request->dlpr_message_set_size = nmessages;

	/* Build the message set. */
	// topic_data.dltd_data = (struct dl_topic_data_data) dist_alloc(
	// sizeof(dl_topic_data_data) 
	// (nmessages * sizeof(struct dl_message_set)));

	//dl_build_message_set(struct dl_request *req_msg,
    	//	int32_t correlation_id, char *client_id, int nmessages, va_list varlist)

	//for (message = 0; message < produce_request.dl_nmessage_set; message++) {
	for (message_it = 0; message_it < nmessages; message_it++) {
		char *key = va_arg(varlist, char *);
		char *value = va_arg(varlist, char *);
		/*
		 *
		 * offset and size needed for encoding only?
		produce_request->dlpr_message_setset[message].dlms_message.crc =
		produce_request->dlpr_message_setset[message].dlms_message.crc =
		*/

		/* Construct the message. */
		struct dl_message *message =
		    &produce_request->dlpr_message_set[message_it].dlms_message;

		message->dlm_crc = 0; // get_crc(value, strlen(value));
		message->dlm_magic_byte = 1; // TODO: const
                message->dlm_attributes = 0; // TODO: &= DL_MSG_ATTR_LOG_APPEND_TIME;
		message->dlm_timestamp = timestamp;
		// TODO: The key can be NULL
		memcpy(message->dlm_key, key, strlen(key));
		//messagege->dlm_nkey = strlen(key);

		memcpy(message->dlm_value, value, strlen(value));
		//messagege->dlm_nvalue= strlen(value);
	}
}

int
dl_decode_produce_request(struct dl_produce_request *request, char *buffer)
{
	ssize_t body_size = 0;

	/* Decode the Request RequiredAcks. */
	request->dlpr_required_acks = dl_decode_int16(buffer);
	body_size += sizeof(int16_t);

	/* Decode the Request Timeout. */
	request->dlpr_timeout = dl_decode_int32(&buffer[body_size]);
	body_size += sizeof(int32_t);

	/* Decode the Request ClientId. */
	body_size += dl_decode_string(&buffer[body_size],
	    request->dlpr_topic_name);

	/* Decode the Request Partition. */
	request->dlpr_partition = dl_decode_int16(&buffer[body_size]);
	body_size += sizeof(int32_t);

	/* Decode the Request CorrelationId into the buffer. */
	request->dlpr_message_set_size = dl_decode_int32(&buffer[body_size]);
	body_size += sizeof(int32_t);

	// TODO: mss
	request->dlpr_message_set[0].dlms_offset =
	    dl_decode_int64(&buffer[body_size]);
	body_size += sizeof(int64_t);
	
	request->dlpr_message_set[0].dlms_message_size =
	    dl_decode_int32(&buffer[body_size]);
	body_size += sizeof(int32_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_crc =
	    dl_decode_int32(&buffer[body_size]);
	body_size += sizeof(int32_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_magic_byte =
	    dl_decode_int8(&buffer[body_size]);
	body_size += sizeof(int8_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_attributes =
	    dl_decode_int8(&buffer[body_size]);
	body_size += sizeof(int8_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_timestamp=
	    dl_decode_int64(&buffer[body_size]);
	body_size += sizeof(int64_t);
	
	/* Decode the Message Key. */
	body_size += dl_decode_bytes(&buffer[body_size],
	    request->dlpr_message_set[0].dlms_message.dlm_key);

	/* Decode the Message Value. */
	body_size += dl_decode_bytes(&buffer[body_size],
	    request->dlpr_message_set[0].dlms_message.dlm_value);

	return body_size;
}

int
dl_encode_produce_request(struct dl_produce_request *produce_request,
    char *buffer)
{
	uint8_t *ms, *mss, *temp = buffer;
	int32_t message_set_size = 0, message_size = 0, request_size = 0;

	DL_ASSERT(produce_request != NULL, "ProduceRequest cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer used for encoding cannot be NULL");

	/* Encode the Request RequiredAcks into the buffer. */
	request_size += dl_encode_int16(&buffer[request_size],
	    produce_request->dlpr_required_acks);

	/* Encode the Request Timeout into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    produce_request->dlpr_timeout);

	/* TODO: New function for encoding Topic Data */ 
	//dl_encode_topic_data(struct dl_produce_request *produce_request,
	//    buffer);
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the Request TopicName into the buffer. */
	request_size += DL_ENCODE_TOPIC_NAME(&buffer[request_size],
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
