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
 */

#ifdef _APPLE
#include <kern/clock.h>
#else
#include <sys/time.h>
#endif
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/nv.h>

#ifdef _KERNEL
#include <sys/kthread.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/socketvar.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#else
#include <sys/sbuf.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_broker_client.h"
#include "dl_correlation_id.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_topic.h"
#include "dl_resender.h"
#include "dl_request.h"
#include "dl_response.h"
#include "dl_request_queue.h"
#include "dl_transport.h"
#include "dl_utils.h"
#include "dlog_broker.h"
#include "dlog_client.h"

//SYSCTL_DECL(_dlog_client);

//static unsigned int dlog_nopen = 0;
//SYSCTL_UINT(_dlog_client, OID_AUTO, open_handles, CTLFLAG_RD, &dlog_nopen, 0,
//    "Number of open DLog handles");

//static unsigned int dlog_nproduce= 0;
//SYSCTL_UINT(_dlog_client, OID_AUTO, produce_requests, CTLFLAG_RD,
//    &dlog_nproduce, 0, "Number of produce requests");

struct dlog_handle {
	struct dl_client_config *dlh_config;
	struct dl_topic *dlh_topic;
};

// TODO error handling
struct dlog_handle *
dlog_client_open(struct dl_client_config const * const config)
{
	struct dlog_handle *handle;
	nvlist_t *props = config->dlcc_props;
	char *hostname;
	unsigned short portnumber;
	struct dl_topic *topic;
	char *topic_name;
	
	DL_ASSERT(config != NULL, "Client configuration cannot be NULL");
	DLOGTR0(PRIO_NORMAL, "Opening the Dlog client...\n");

	if (!nvlist_exists_string(props, DL_CONF_TOPIC)) {

		topic_name = DL_DEFAULT_TOPIC;
	} else {
		topic_name = nvlist_get_string(props, DL_CONF_TOPIC);
	}

	/* Lookup the topic in the topic hashmap. */
	dl_topic_hashmap_get(topic_name, &topic);
	
	/*
	h = hashlittle(topic_name, strlen(topic_name), 0);

	LIST_FOREACH(t, &topic_hashmap[h & topic_hashmask], dlt_entries) {
		if (strcmp(topic_name, sbuf_data(t->dlt_name)) == 0) {

			topic = t;
			break;
		}
	}
	*/
	if (topic == NULL) {

		/* The specified topic was not found in the topic hashmap. */
		DLOGTR1(PRIO_NORMAL, "Topic %s has not been created\n",
		    topic_name);
		return NULL;
	}

	handle = (struct dlog_handle *) dlog_alloc(sizeof(struct dlog_handle));
#ifdef _KERNEL
	DL_ASSERT(handle != NULL, ("Failed allocating DLog client handle."));
#else
	if (handle == NULL) {
		// TODO
	}
#endif	
	bzero(handle, sizeof(struct dlog_handle));


	/* Store the client configuration. */
	handle->dlh_config = config;
	
	/* Associate the topic with this client handle. */
	handle->dlh_topic = topic;

	if (!nvlist_exists_string(props, DL_CONF_BROKER)) {
		hostname = DL_DEFAULT_BROKER;
	} else {
		hostname = nvlist_get_string(props, DL_CONF_BROKER);
	}

	if (!nvlist_exists_string(props, DL_CONF_BROKER_PORT)) {
		portnumber = DL_DEFAULT_BROKER_PORT;
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}

	return handle;
}

void
dlog_client_close(struct dlog_handle *handle)
{
	nvlist_t *props = handle->dlh_config->dlcc_props;

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	/* Free the nvlist that stores the configuration associated with this
	 * handle.
	 */
	nvlist_destroy(props);

	/* Free all the memory associated with the client handle. */
	dlog_free(handle);	

	DLOGTR0(PRIO_LOW, "DLog client finished\n");
}

#ifdef CLIENT 
int
dlog_fetch(struct dlog_handle *handle, struct sbuf *topic_name,
    int32_t min_bytes, int32_t max_wait_time, int64_t fetch_offset,
    int32_t max_bytes)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	nvlist_t *props = handle->dlh_config->dlcc_props;
	struct sbuf *client_id;
	int result = 0;

	client_id = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		sbuf_cpy(client_id, DL_DEFAULT_CLIENTID);
	} else {
		sbuf_cpy(client_id, nvlist_get_string(props, DL_CONF_CLIENTID));
	}
	sbuf_finish(client_id);

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->dlh_topic->dlt_cid));

	/* Instantiate a new FetchRequest */
	if (dl_fetch_request_new(&message,
	    dl_correlation_id_val(handle->dlh_topic->dlt_cid),
	    client_id, topic_name, min_bytes,
	    max_wait_time, fetch_offset, max_bytes) != 0)
		return -1;
	
	DLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		unsigned char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		/* Enqueue the request for processing */
		/*if (dl_request_q_enqueue_new(handle->dlh_request_q, buffer,
		    message->dlrqm_correlation_id,
		    message->dlrqm_api_key) == 0) {
			
			* Increment the monotonic correlation id. *
			dl_correlation_id_inc(handle->dlh_topic->dlt_cid);
		} else {
			DLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		}*/
	} else {
		DLOGTR0(PRIO_HIGH, "Error encoding FetchRequest\n");
		result = -1;
	}

	// TODO: mesasge xtor
	// dl_request_delete(message);

	return result;
}

int
dlog_list_offset(struct dlog_handle *handle, struct sbuf *topic_name,
    int64_t time)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	nvlist_t *props = handle->dlh_config->dlcc_props;
	struct sbuf *client_id;
	int result = 0;

	client_id = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		sbuf_cpy(client_id, DL_DEFAULT_CLIENTID);
	} else {
		sbuf_cpy(client_id, nvlist_get_string(props, DL_CONF_CLIENTID));
	}
	sbuf_finish(client_id);

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->dlh_topic->dlt_cid));

	/* Instantiate a new ListOffsetRequest. */
	if (dl_list_offset_request_new(&message,
	    dl_correlation_id_val(handle->dlh_topic->dlt_cid), 
	    client_id, topic_name, time) != 0)
		return -1;
	
	DLOGTR0(PRIO_LOW, "Constructed request message\n");

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		unsigned char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		/* Enqueue the request for processing */
		/*if (dl_request_q_enqueue_new(handle->dlh_request_q, buffer,
		    message->dlrqm_correlation_id,
		    message->dlrqm_api_key) == 0) {
			
			DLOGTR0(PRIO_LOW, "Enqued request\n");

			* Increment the monotonic correlation id. *
			dl_correlation_id_inc(handle->dlh_topic->dlt_cid);
		} else {
			DLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		}*/
	} else {
		DLOGTR0(PRIO_HIGH, "Error encoding ListOffsetRequest\n");
		result = -1;
	}

	// TODO: mesasge xtor
	// dl_request_delete(message);

	return result;
}
#endif

int
dlog_produce(struct dlog_handle *handle, unsigned char *k, int k_len,
    unsigned char *v, int v_len)
{
	struct dl_bbuf *buffer;
	struct dl_message_set *message_set;

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	/* Instantiate a new MessageSet. */
	if (dl_message_set_new(&message_set, k, k_len, v, v_len) != 0)
		return -1;

	if (dl_bbuf_new(&buffer, NULL, DL_MTU,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) != 0)
		goto err_produce_request;

	if (dl_message_set_encode(message_set, buffer) != 0) {

		DLOGTR0(PRIO_HIGH, "Error encoding MessageSet\n");
		dl_bbuf_delete(buffer);
		goto err_produce_request;
	}
	
	DLOGTR0(PRIO_LOW, "Encoded request message\n");

	unsigned char *bufval = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
	};
	DLOGTR0(PRIO_LOW, "\n");

	/* Enqueue the MessageSet for processing */
	if (dl_topic_produce_to(handle->dlh_topic, buffer) != 0) {

		DLOGTR0(PRIO_HIGH, "Error enquing MessageSet\n");
		dl_bbuf_delete(buffer);
		goto err_produce_request;
	}
		
	DLOGTR0(PRIO_LOW, "Produce request to log\n");
	return 0;

err_produce_request:
	DLOGTR0(PRIO_HIGH, "Error producing request\n");
	dl_message_set_delete(message_set);

	return -1;
}
