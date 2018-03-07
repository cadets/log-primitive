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

#include <sbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dlog_client.h"

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_response.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_HIGH;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const USAGE = "%s: [-p port number]";

static char const * const DEFAULT_CLIENT_ID = "console_consumer";
static char const * const DEFAULT_TOPIC  = "test";
static char const * const DEFAULT_HOSTNAME  = "localhost";
static const int DEFAULT_PORT = 9092;
static const int64_t DEFAULT_TIME = -1;

static struct dlog_handle *handle;
//static char const * client_id = DEFAULT_CLIENT_ID;

static void dlc_siginfo_handler(int);
static void dlc_sigint_handler(int);
static void dlc_on_response(struct dl_response const * const);

static void
dlc_siginfo_handler(int sig)
{

	dl_debug(PRIO_LOW, "Caught SIGIFO[%d]\n", sig);
}

static void
dlc_sigint_handler(int sig)
{

	dl_debug(PRIO_LOW, "Caught SIGINT[%d]\n", sig);
	
	/* Finalise the distributed log client before finishing. */
	dlog_client_close(handle);

	exit(EXIT_SUCCESS);
}

static void
dlc_on_response(struct dl_response const * const response)
{
	struct dl_fetch_response *fetch_response;
	struct dl_fetch_response_partition *fetch_partition;
	struct dl_fetch_response_topic *fetch_topic;
	struct dl_list_offset_response *offset_response;
	struct dl_list_offset_response_partition *offset_partition;
	struct dl_list_offset_response_topic *offset_topic;
	struct dl_message *message;
	struct sbuf *hostname = NULL;
	int max_wait_time = 2000;
	int maxbytes = 1000;
	int minbytes = 1;

	DL_ASSERT(response != NULL, "Response cannot be NULL\n");

	dl_debug(PRIO_LOW, "Response was recieved with correlation ID %d\n",
	    response->dlrs_correlation_id);

	switch (response->dlrs_api_key) {
	case DL_FETCH_API_KEY:
		fetch_response = response->dlrs_message.dlrs_fetch_message;

		SLIST_FOREACH(fetch_topic,
			&fetch_response->dlfr_topics, dlfrt_entries) {

			dl_debug(PRIO_LOW, "Topic: %s\n",
				sbuf_data(fetch_topic->dlfrt_topic_name));

			SLIST_FOREACH(fetch_partition,
				&fetch_topic->dlfrt_partitions,
				dlfrp_entries) {

				dl_debug(PRIO_LOW, "Partition: %d\n",
					fetch_partition->dlfrpr_partition);

				dl_debug(PRIO_LOW, "ErrorCode: %d\n",
					fetch_partition->dlfrpr_error_code);

				STAILQ_FOREACH(message,
					&fetch_partition->dlfrp_message_set->dlms_messages,
					dlm_entries) {

				dl_debug(PRIO_LOW, "Offset: %d\n",
					message->dlm_offset);
					write(1, message->dlm_value,
						message->dlm_value_len);
					write(1, "\n", 1);
				};
			
				dl_debug(PRIO_LOW, "HighWatermark: %d\n",
					fetch_partition->dlfrpr_high_watermark);
			
				hostname = sbuf_new_auto();
				sbuf_cpy(hostname, sbuf_data(fetch_topic->dlfrt_topic_name));

				dlog_fetch(handle,
				        hostname,	
					minbytes, max_wait_time,
				    	fetch_partition->dlfrpr_high_watermark,
					maxbytes);
				sbuf_delete(hostname);
			};
		};
		break;
	case DL_OFFSET_API_KEY:
		offset_response = response->dlrs_message.dlrs_offset_message;

		SLIST_FOREACH(offset_topic,
			&offset_response->dlor_topics, dlort_entries) {

			dl_debug(PRIO_LOW, "Topic: %s\n",
				offset_topic->dlort_topic_name);

			SLIST_FOREACH(offset_partition,
				&offset_topic->dlort_partitions,
				dlorp_entries) {

				dl_debug(PRIO_NORMAL, "Partition: %d\n",
					offset_partition->dlorp_partition);

				dl_debug(PRIO_NORMAL, "Offset: %d\n",
					offset_partition->dlorp_offset);
			
				hostname = sbuf_new_auto();
				sbuf_cpy(hostname, sbuf_data(offset_topic->dlort_topic_name));
	
				dlog_fetch(handle,
					hostname,
					minbytes, max_wait_time,
					offset_partition->dlorp_offset,
					maxbytes);
				sbuf_delete(hostname);

			};
		};
		break;
	default:
		dl_debug(PRIO_HIGH, "Unexcepted Response %d\n",
		    response->dlrs_api_key);
		break;
	}
}

/**
 * Utility for writing to the distributed log from the console.
 */
int
main(int argc, char **argv)
{
	struct dl_client_configuration cc;
	struct sbuf *client_id = NULL;
	struct sbuf *hostname = NULL;
	struct sbuf *topic = NULL;
	int64_t time = DEFAULT_TIME;
	int port = DEFAULT_PORT;
	int opt;
	
	/* Configure the default values. */
	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, DEFAULT_CLIENT_ID);
	
	hostname = sbuf_new_auto();
	sbuf_cpy(hostname, DEFAULT_HOSTNAME);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, DEFAULT_TOPIC);

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "c::t::h::p::v")) != -1) {
		switch (opt) {
		case 'c':
			sbuf_cpy(client_id, optarg);
			break;
		case 't':
			sbuf_cpy(topic, optarg);
			break;
		case 'h':
			sbuf_cpy(hostname, optarg);
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			PRIO_LOG = PRIO_LOW;
			break;
		default:
			fprintf(stderr, USAGE, argv[0]);
			break;
		}
	}

	/* Install signal handler to terminate broker cleanly on SIGINT. */	
	signal(SIGINT, dlc_sigint_handler);

	/* Install signal handler to report broker statistics. */
	signal(SIGINFO, dlc_siginfo_handler);

	/* Configure and initialise the distributed log client. */
	cc.dlcc_on_response = dlc_on_response;
	cc.dlcc_client_id = client_id;
	cc.resend_timeout = 40;
	cc.resender_thread_sleep_length = 10;
	cc.request_notifier_thread_sleep_length = 3;
	cc.reconn_timeout = 5;
	cc.poll_timeout = 3000;

	handle = dlog_client_open(hostname, port, &cc);
	if (handle == NULL) {
		fprintf(stderr,
		    "Error initialising the distributed log client.\n");
		exit(EXIT_FAILURE);
	}

	dlog_list_offset(handle, topic, time);
	
	for (;;) {
		sleep(1);
	}

	sbuf_delete(topic);
	sbuf_delete(hostname);
	dlog_client_close(handle);

	return 0;
}
