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
#include <time.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_produce_request.h"
#include "dl_request.h"
#include "dl_utils.h"

int
dl_produce_request_new(struct dl_request **self, const int32_t correlation_id,
    struct sbuf *client_id, struct sbuf *topic_name, char * key, int key_len,
    char *value, int value_len)
{
	struct dl_message *message;
	struct dl_produce_request *produce_request;
	struct dl_produce_request_partition *req_partition;
	struct dl_produce_request_topic *req_topic;
	struct dl_request *request;

	/* Construct the ProduceRequest. */
	*self = request = dl_request_new(DL_PRODUCE_API_KEY, correlation_id,
	    client_id);
#ifdef KERNEL
	DL_ASSERT(request != NULL, ("Failed to allocate Request.\n"));
	{
#else
	if (request != NULL) {
#endif
		produce_request =
		    request->dlrqm_message.dlrqmt_produce_request =
		    (struct dl_produce_request *) dlog_alloc(
			sizeof(struct dl_produce_request));
#ifdef KERNEL
		DL_ASSERT(produce_request != NULL,
		    ("Failed to allocate ProduceRequest.\n"));
		{
#else
		if (produce_request != NULL) {
#endif
			// TODO: surely this comes from the client or the configuration
			produce_request->dlpr_required_acks = 1;

			// TODO: the time to await a response
			produce_request->dlpr_timeout = 0;

			/* Construct a single Topic/Partition. */
			produce_request->dlpr_ntopics = 1;
			SLIST_INIT(&produce_request->dlpr_topics);
			
			req_topic = (struct dl_produce_request_topic *)
			    dlog_alloc(sizeof(struct dl_produce_request_topic));
#ifdef KERNEL
			DL_ASSERT(req_topic != NULL,
			    ("Failed to allocate ProduceRequest [topic_data].\n"));
			{
#else
			if (req_topic != NULL) {
#endif
				req_topic->dlprt_topic_name = topic_name;
				
				req_topic->dlprt_npartitions = 1;
				req_partition = &req_topic->dlprt_partitions[0];

				/* Default partition. */
				req_partition->dlprp_partition = 0;

				/* Construct the MessageSet. */
				req_partition->dlprp_message_set =
				    dl_message_set_new(key, key_len,
					value, value_len);
				
				SLIST_INSERT_HEAD(
				    &produce_request->dlpr_topics, req_topic,
				    dlprt_entries);
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Failed allocating ProduceRequest [topic_data].\n");
				dlog_free(produce_request);
				dlog_free(request);
				request = NULL;
			}
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Failed allocating ProduceRequest.\n");
			dlog_free(request);
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Failed allocating ProduceRequest.\n");
	}
	return 0;
}

struct dl_produce_request *
dl_produce_request_decode(struct dl_buf *source)
{
	struct dl_message_set *message_set;
	struct dl_produce_request *request;
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_partition;
	struct sbuf *topic_name;
	int32_t topic, npartitions, partition;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");
	
	/* Construct the ProduceRequest. */
	request = (struct dl_produce_request *) dlog_alloc(
	    sizeof(struct dl_produce_request));
#ifdef KERNEL
	DL_ASSERT(request != NULL, ("Failed to allocate ProduceRequest.\n"));
	{
#else
	if (request != NULL) {
#endif
		/* Decode the ProduceRequest RequiredAcks. */
		DL_DECODE_REQUIRED_ACKS(source, &request->dlpr_required_acks);

		/* Decode the ProduceRequest Timeout. */
		DL_DECODE_TIMEOUT(source, &request->dlpr_timeout);

		SLIST_INIT(&request->dlpr_topics);

		/* Decode the [topic_data] array. */
		dl_buf_get_int32(source, &request->dlpr_ntopics);
		
		for (topic= 0; topic < request->dlpr_ntopics; topic++) {

			/* Decode the ProduceRequest TopicName. */
			DL_DECODE_TOPIC_NAME(source, &topic_name);
		
			/* Decode the [data] array. */
			dl_buf_get_int32(source, &npartitions);
			
			/* Allocate the Topic/Partitions. */
			req_topic = (struct dl_produce_request_topic *)
			    dlog_alloc(
				sizeof(struct dl_produce_request_topic) + 
				(npartitions - 1) * sizeof(struct dl_produce_request_partition));

			req_topic->dlprt_npartitions = npartitions;
			req_topic->dlprt_topic_name = topic_name;
#ifdef KERNEL
			DL_ASSERT(req_topic != NULL,
			    ("Failed to allocate Request.\n"));
			{
#else
			if (req_topic != NULL) {
#endif
				req_topic->dlprt_npartitions = npartitions;
				req_topic->dlprt_topic_name = topic_name;

				for (partition = 0;
				    partition < req_topic->dlprt_npartitions;
				    partition++) {

					req_partition =
					&req_topic->dlprt_partitions[partition];

					/* Decode the ProduceRequest Partition. */
					DL_DECODE_PARTITION(source,
					    &req_partition->dlprp_partition);
				
					/* Decode the MessageSet. */
					dl_message_set_decode(source);
				}

				SLIST_INSERT_HEAD(&request->dlpr_topics,
				    req_topic, dlprt_entries);
			} else {
				// TODO
			}
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Failed to allocate ProduceRequest.\n");
	}
	return request;
}

int
dl_produce_request_encode(
    struct dl_produce_request const * const self, struct dl_buf *target)
{
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_partition;
	int partition;
		
	DL_ASSERT(self != NULL, ("ProduceRequest cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Encode the Request RequiredAcks into the buffer. */
	if (DL_ENCODE_REQUIRED_ACKS(target, self->dlpr_required_acks) != 0)
		goto err;

	/* Encode the Request Timeout into the buffer. */
	if (DL_ENCODE_TIMEOUT(target, self->dlpr_timeout) != 0)
		goto err;

	/* Encode the [topic_data] array. */
	if (dl_buf_put_int32(target, self->dlpr_ntopics) != 0)
		goto err;

	SLIST_FOREACH(req_topic, &self->dlpr_topics, dlprt_entries) {

		/* Encode the Request TopicName into the buffer. */
		if (DL_ENCODE_TOPIC_NAME(target,
		    req_topic->dlprt_topic_name) != 0)
			goto err;
	 
		/* Encode the [data] array. */
		dl_buf_put_int32(target,
			req_topic->dlprt_npartitions);

		for (partition = 0;
			partition < req_topic->dlprt_npartitions;
			partition++) {
			
			req_partition = &req_topic->dlprt_partitions[partition];

			/* Encode the Partition into the buffer. */
			if (DL_ENCODE_PARTITION(target,
			    req_partition->dlprp_partition) != 0)
				goto err;

			/* Encode the MessageSet */
			if (dl_message_set_encode(
			    req_partition->dlprp_message_set, target) != 0)
				goto err;
		}
	}
	return 0;
err:
	return -1;
}
