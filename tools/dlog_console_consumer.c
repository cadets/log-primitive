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

unsigned short PRIO_LOG = PRIO_NORMAL;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const USAGE = "%s: [-p port number]";

static char const * const DEFAULT_CLIENT_ID = "console_consumer";
static char const * const DEFAULT_TOPIC  = "test";
static char const * const DEFAULT_HOSTNAME  = "localhost";
static const int DEFAULT_PORT = 9092;

static struct dlog_handle *handle;
static char * client_id = DEFAULT_CLIENT_ID;
static char * topic = DEFAULT_TOPIC;

static void dlc_on_ack(const int32_t);
static void dlc_on_response(const int16_t,
    struct dl_response const * const);

static void dlc_siginfo_handler(int);
static void dlc_sigint_handler(int);
static void dlc_on_ack(const dl_correlation_id);
static void dlc_on_response(const int16_t,
    struct dl_response const * const);

static void
dlc_siginfo_handler(int sig)
{
	debug(PRIO_LOW, "Caught SIGIFO[%d]\n", sig);
}

static void
dlc_sigint_handler(int sig)
{
	debug(PRIO_LOW, "Caught SIGINT[%d]\n", sig);
	
	/* Deallocate the buffer used to store the user input. */
	//free(line);

	/* Finalise the distributed log client before finishing. */
	//dlog_client_close();

	exit(EXIT_SUCCESS);
}


static void
dlc_on_ack(const int32_t correlation_id)
{
	debug(PRIO_NORMAL, "Broker acknowledged message "
	    "(correlation ID = %lu)\n", correlation_id);
}

static void
dlc_on_response(const int16_t api_key,
    struct dl_response const * const response)
{
	int max_wait_time = 1000;
	int maxbytes = 1000;
	int minbytes = 0;

	DL_ASSERT(response != NULL, "Response cannot be NULL\n");

	debug(PRIO_NORMAL, "Response was recieved with correlation ID %d\n",
	    response->dlrs_correlation_id);

	//switch (response->dlrs_api_key) {
	switch (api_key) {
		case DL_PRODUCE_REQUEST:
			debug(PRIO_NORMAL,
			    "Produced the following messages: \n");
			/*
			for (int i = 0; i < rm->rm.produce_request.spr.sspr.mset.num_elems; i++) {
				printf("\tMessage: %s\n",
				    rm->rm.produce_request.spr.sspr.mset.elems[i].message.value); 
			}

			debug(PRIO_NORMAL, "Request answer: \n");
			for (int i = 0; i < rs->rm.produce_response.num_sub;
			    i++){
				for (int j = 0;
				    j < rs->rm.produce_response.spr[i].num_subsub; j++){
					struct sub_sub_produce_response *csspr = &rs->rm.produce_response.spr[i].sspr[j];
					printf("Timestamp:\t%ld\n", csspr->timestamp);
					printf("Offset:\t%ld\n", csspr->offset); 
					printf("ErrorCode:\t%d\n", csspr->error_code); 
					printf("Partition:\t%d\n", csspr->partition); 
				}
			}
			*/
			break;
		case DL_FETCH_REQUEST:
			// TODO: parse the response
			break;
		case DL_OFFSET_REQUEST:
			printf("here\n");
			debug(PRIO_NORMAL, "Offset: %d\n",
			    response->dlrs_message.dlrs_offset_response->dlors_offset);
			debug(PRIO_NORMAL, "Topic: %s\n",
			    response->dlrs_message.dlrs_offset_response->dlors_topic_name);

			dlog_fetch(handle, 
			    response->dlrs_message.dlrs_offset_response->dlors_topic_name,
			    minbytes, max_wait_time,
			    response->dlrs_message.dlrs_offset_response->dlors_offset,
			    maxbytes);
			break;
		default:
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
	char * hostname = DEFAULT_HOSTNAME;
	int port = DEFAULT_PORT;
	int resend_timeout = 40;
	int maxbytes = 1000;
	int minbytes = 0;
	int wantoff = 38565;
	int opt;
	size_t len = 0;
	size_t read = 0;

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "c::t::h::p::v")) != -1) {
		switch (opt) {
		case 'c':
			client_id = optarg;
			break;
		case 't':
			topic = optarg;
			break;
		case 'h':
			hostname = optarg;
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
	cc.dlcc_on_ack = dlc_on_ack;
	cc.dlcc_on_response = dlc_on_response;
	cc.client_id = client_id;
	cc.to_resend = true;
	cc.resend_timeout = resend_timeout;
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

	//dlog_list_offset(handle, cc.to_resend,
	//    topic, -2);
	
	dlog_fetch(handle, topic, 100, 1000, 38601, 10000);

       	/* Echo to the command line from the distributed log. */	
	for (;;) {
		sleep(1);
//		dlog_fetch(handle, topic, 100, 1000,
//		    38601, 10000);
	}

	dlog_client_close(handle);

	return 0;
}
