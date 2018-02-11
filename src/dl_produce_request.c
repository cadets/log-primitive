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

// TODO: CRC generation in kernel libkern/crc32.c
#include <zlib.h>

#include <stddef.h>

// TODO: Remove depedency of libraries
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <stdint.h>


#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_produce_request.h"
#include "dl_request.h"

struct dl_produce_request_partition {
	int32_t dlpr_partition;
	//int32_t dlpr_message_set_size; // This is the size in bytes of the message sent
	//int32_t dl_nmessage_set;
	//struct dl_message_set dlpr_message_set[1];
	//struct dl_message_set dlpr_messages;
};

struct dl_produce_request_topic {
	char dltd_topic_name[DL_MAX_TOPIC_NAME_LEN];
	//int32_t dltd_ndata;
	//struct dl_topic_data_data dltd_data[1];
};

struct dl_produce_request {
	int16_t dlpr_required_acks;
	int32_t dlpr_timeout;
	//SLIST
	//int32_t dlpr_num_topic_data;
	//struct dl_topic_data dlpr_topic_data[1];
	// TODO: Deprecated
	char *dlpr_topic_name;
	int32_t dlpr_partition;
	struct dl_message_set dlpr_messages;
};

#define DL_ENCODE_REQUIRED_ACKS(buffer, value) \
    dl_encode_int16(buffer, value);
#define DL_ENCODE_TIMEOUT(buffer, value) \
    dl_encode_int32(buffer, value);
#define DL_ENCODE_TOPIC_NAME(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_TOPIC_NAME_LEN)

#include <stdio.h>

struct dl_request *
dl_produce_request_new(int32_t correlation_id, char *client_id,
    char *topic_name, char * key, int key_len, char *value, int value_len)
{
	struct dl_message *message;
	struct dl_produce_request *produce_request;
	struct dl_request *request;
	long timestamp;
	int message_it;
	int nmessages = 1;

	/* Construct the ProduceRequest. */
	request = dl_request_new(DL_PRODUCE_REQUEST, correlation_id,
	    client_id);

	produce_request = request->dlrqm_message.dlrqmt_produce_request =
	    (struct dl_produce_request *) dlog_alloc(
		sizeof(struct dl_produce_request));

	// TODO: surely this comes from the client or the configuration
	produce_request->dlpr_required_acks = 1;
	// TODO: the time to await a response
	produce_request->dlpr_timeout = 0; //-1;
	produce_request->dlpr_topic_name = topic_name;
	// TODO :default partition = 0
	produce_request->dlpr_partition = 0;
	
	//produce_request->dlpr_message_set_size = nmessages;

	/* Construct the MessageSet. */
	SLIST_INIT(&produce_request->dlpr_messages);

	for (message_it = 0; message_it < nmessages; message_it++) {

		message = (struct dl_message *) dlog_alloc(
		    sizeof(struct dl_message));
		message->dlm_key = key;
		message->dlm_key_len = key_len;
		message->dlm_value = value;
		message->dlm_value_len = value_len;
		
		SLIST_INSERT_HEAD(&produce_request->dlpr_messages, message,
		    dlm_entries);
	}

	return request;
}

struct dl_produce_request *
dl_produce_request_decode(char *source)
{
	struct dl_produce_request *request;
	ssize_t body_size = 0;

	DL_ASSERT(source != NULL, "Source Decode buffer cannot be NULL");
	
	request = (struct dl_produce_request *) dlog_alloc(
	    sizeof(struct dl_produce_request));
	
	/* Decode the Request RequiredAcks. */
	request->dlpr_required_acks = dl_decode_int16(source);
	body_size += sizeof(int16_t);

	/* Decode the Request Timeout. */
	request->dlpr_timeout = dl_decode_int32(&source[body_size]);
	body_size += sizeof(int32_t);

	//[topic_data]
	
	/* Decode the Request TopicName. */
	// TODO: Need to allocate the memory
	body_size += dl_decode_string(&source[body_size],
	    request->dlpr_topic_name);

	//[data]
	
	/* Decode the Request Partition. */
	request->dlpr_partition = dl_decode_int16(&source[body_size]);
	body_size += sizeof(int32_t);

	/* Decode the Request CorrelationId into the buffer. */
	//request->dlpr_message_set_size = dl_decode_int32(&source[body_size]);
	body_size += sizeof(int32_t);
/*
	// TODO: mss
	request->dlpr_message_set[0].dlms_offset =
	    dl_decode_int64(&source[body_size]);
	body_size += sizeof(int64_t);
	
	request->dlpr_message_set[0].dlms_message_size =
	    dl_decode_int32(&source[body_size]);
	body_size += sizeof(int32_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_crc =
	    dl_decode_int32(&source[body_size]);
	body_size += sizeof(int32_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_magic_byte =
	    dl_decode_int8(&source[body_size]);
	body_size += sizeof(int8_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_attributes =
	    dl_decode_int8(&source[body_size]);
	body_size += sizeof(int8_t);
	
	request->dlpr_message_set[0].dlms_message.dlm_timestamp=
	    dl_decode_int64(&source[body_size]);
	body_size += sizeof(int64_t);
	
	/* Decode the Message Key. *
	body_size += dl_decode_bytes(&source[body_size],
	    request->dlpr_message_set[0].dlms_message.dlm_key);

	/* Decode the Message Value. *
	body_size += dl_decode_bytes(&source[body_size],
	    request->dlpr_message_set[0].dlms_message.dlm_value);
*/
	return request;
}

int
dl_produce_request_encode(
    struct dl_produce_request const * const produce_request,
    char * buffer)
//    struct dl_buffer const *buffer)
{
	uint8_t *ms, *mss, *temp = buffer;
	int32_t msg_set_size = 0, request_size = 0;

	DL_ASSERT(produce_request != NULL, "ProduceRequest cannot be NULL");
	DL_ASSERT(buffer != NULL, "Target buffer cannot be NULL");

	/* Encode the Request RequiredAcks into the buffer. */
	request_size += DL_ENCODE_REQUIRED_ACKS(&buffer[request_size],
	    	produce_request->dlpr_required_acks);

	/* Encode the Request Timeout into the buffer. */
	request_size += DL_ENCODE_TIMEOUT( &buffer[request_size],
	    produce_request->dlpr_timeout);

	/* TODO: New function for encoding Topic Data */ 
	//dl_encode_topic_data(struct dl_produce_request *produce_request,
	//    buffer);
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the Request TopicName into the buffer. */
	request_size += DL_ENCODE_TOPIC_NAME(&buffer[request_size],
	    produce_request->dlpr_topic_name);

	/* TODO: New function for encoding partition Data */ 
	//dl_encode_topic_data(struct dl_produce_request *produce_request,
	//    buffer);
	request_size += dl_encode_int32(&buffer[request_size], 1);

	/* Encode the Request Partition into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    produce_request->dlpr_partition);

	/* Encode the MessageSet Size into the buffer. */
	request_size += dl_encode_int32(&buffer[request_size],
	    dl_message_set_get_size(&produce_request->dlpr_messages));

	printf("request size = %d\n", request_size);
	/* Encode the MessageSet */
	request_size += dl_message_set_encode(&produce_request->dlpr_messages,
	    &buffer[request_size]);
	printf("request size = %d\n", request_size);
		
	return request_size;
}
