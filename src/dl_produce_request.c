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

#include <stddef.h>

// TODO: Remove depedency of libraries
// TODO: CRC generation in kernel libkern/crc32.c
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_produce_request.h"
#include "dl_request.h"

#define DL_ENCODE_REQUIRED_ACKS(buffer, value) dl_encode_int16(buffer, value);
#define DL_ENCODE_TIMEOUT(buffer, value) dl_encode_int32(buffer, value);
#define DL_ENCODE_TOPIC_NAME(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_TOPIC_NAME_LEN)

struct dl_request *
dl_produce_request_new(int32_t correlation_id, char *client_id,
    char *topic_name, char * key, int key_len, char *value, int value_len)
{
	struct dl_message *message;
	struct dl_produce_request *produce_request;
	struct dl_produce_request_partition *request_partition;
	struct dl_produce_request_topic *request_topic;
	struct dl_request *request;

	/* Construct the ProduceRequest. */
	request = dl_request_new(DL_PRODUCE_API_KEY, correlation_id,
	    client_id);

	produce_request = request->dlrqm_message.dlrqmt_produce_request =
	    (struct dl_produce_request *) dlog_alloc(
		sizeof(struct dl_produce_request));

	// TODO: surely this comes from the client or the configuration
	produce_request->dlpr_required_acks = 1;

	// TODO: the time to await a response
	produce_request->dlpr_timeout = 0;

	/* Construct a single Topic. */
	produce_request->dlpr_ntopics = 1;

	/* Construct the Topics. */
	SLIST_INIT(&produce_request->dlpr_topics);
	    
	request_topic = (struct dl_produce_request_topic *) dlog_alloc(
		sizeof(struct dl_produce_request_topic));

	strlcpy(request_topic->dlprt_topic_name, topic_name,
	    DL_MAX_TOPIC_NAME_LEN); 
	
	SLIST_INSERT_HEAD(&produce_request->dlpr_topics, request_topic,
	    dlprt_entries);
	
	/* Construct a single Partition. */
	request_topic->dlprt_npartitions = 1;
	
	/* Construct the Partitions. */
	SLIST_INIT(&request_topic->dlprt_partitions);
	
	request_partition = (struct dl_produce_request_partition *) dlog_alloc(
		sizeof(struct dl_produce_request_partition));

	/* Default partition. */
	request_partition->dlprp_partition = 0;

	SLIST_INSERT_HEAD(&request_topic->dlprt_partitions, request_partition,
	    dlprp_entries);

	/* Construct the MessageSet. */
	request_partition->dlprp_message_set = dl_message_set_new(key, key_len,
	    value, value_len);

	return request;
}

struct dl_produce_request *
dl_produce_request_decode(char *source)
{
	struct dl_message_set *message_set;
	struct dl_produce_request *request;
	struct dl_produce_request_topic *request_topic;
	struct dl_produce_request_partition *request_partition;
	int32_t topic_it, partition_it, request_size = 0;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	
	/* Construct the ProduceRequest. */
	request = (struct dl_produce_request *) dlog_alloc(
	    sizeof(struct dl_produce_request));
	
	/* Decode the ProduceRequest RequiredAcks. */
	request->dlpr_required_acks = dl_decode_int16(source);
	request_size += sizeof(int16_t);

	/* Decode the ProduceRequest Timeout. */
	request->dlpr_timeout = dl_decode_int32(&source[request_size]);
	request_size += sizeof(int32_t);

	SLIST_INIT(&request->dlpr_topics);

	/* Decode the [topic_data] array. */
	request->dlpr_ntopics = dl_decode_int32(&source[request_size]);
	request_size += sizeof(int32_t);
	
	for (topic_it = 0; topic_it < request->dlpr_ntopics; topic_it++) {

		request_topic = (struct dl_produce_request_topic *) dlog_alloc(
		    sizeof(struct dl_produce_request_topic));

		/* Decode the ProduceRequest TopicName. */
		request_size += dl_decode_string(&source[request_size],
		    request_topic->dlprt_topic_name);
	
		SLIST_INIT(&request_topic->dlprt_partitions);

		/* Decode the [data] array. */
		request_topic->dlprt_npartitions = dl_decode_int32(
		    &source[request_size]);
		request_size += sizeof(int32_t);

		for (partition_it = 0;
		    partition_it < request_topic->dlprt_npartitions;
		    partition_it++) {

			request_partition =
			    (struct dl_produce_request_partition *) dlog_alloc(
				sizeof(struct dl_produce_request_partition));

			/* Decode the ProduceRequest Partition. */
			request_partition->dlprp_partition =
			    dl_decode_int32(&source[request_size]);
			request_size += sizeof(int32_t);
		
			/* Decode the MessageSet. */
			// TODO where does the messageset size come from here?
			message_set = dl_message_set_decode(
			    &source[request_size], 10);
			request_size += dl_message_set_get_size(message_set);

			SLIST_INSERT_HEAD(&request_topic->dlprt_partitions,
			    request_partition, dlprp_entries);
		}

		SLIST_INSERT_HEAD(&request->dlpr_topics, request_topic,
		    dlprt_entries);
	}
	return request;
}

int
dl_produce_request_encode(
    struct dl_produce_request const * const produce_request,
    char * buffer)
//    struct dl_buffer const *buffer)
{
	struct dl_produce_request_topic *request_topic;
	struct dl_produce_request_partition *request_partition;
	int32_t msg_set_size = 0, request_size = 0;

	DL_ASSERT(produce_request != NULL, "ProduceRequest cannot be NULL");
	DL_ASSERT(buffer != NULL, "Target buffer cannot be NULL");

	/* Encode the Request RequiredAcks into the buffer. */
	request_size += DL_ENCODE_REQUIRED_ACKS(&buffer[request_size],
	    	produce_request->dlpr_required_acks);

	/* Encode the Request Timeout into the buffer. */
	request_size += DL_ENCODE_TIMEOUT( &buffer[request_size],
	    produce_request->dlpr_timeout);

	/* Encode the [topic_data] array. */
	request_size += dl_encode_int32(&buffer[request_size],
	    produce_request->dlpr_ntopics);

	SLIST_FOREACH(request_topic, &produce_request->dlpr_topics,
	    dlprt_entries) {

		/* Encode the Request TopicName into the buffer. */
		request_size += DL_ENCODE_TOPIC_NAME(&buffer[request_size],
		    request_topic->dlprt_topic_name);

		/* Encode the [data] array. */
		request_size += dl_encode_int32(&buffer[request_size],
		    request_topic->dlprt_npartitions);

		SLIST_FOREACH(request_partition,
		    &request_topic->dlprt_partitions, dlprp_entries) {

			/* Encode the Partition into the buffer. */
			request_size += dl_encode_int32(&buffer[request_size],
			    request_partition->dlprp_partition);

			/* Encode the MessageSet Size into the buffer. */
			request_size += dl_encode_int32(&buffer[request_size],
			    dl_message_set_get_size(
			    request_partition->dlprp_message_set));

			/* Encode the MessageSet */
			request_size += dl_message_set_encode(
			    request_partition->dlprp_message_set,
			    &buffer[request_size]);
		}
	}
	return request_size;
}
