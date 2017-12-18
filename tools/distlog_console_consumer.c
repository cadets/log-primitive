/*-
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "distlog_client.h"
#include "dl_common.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_NORMAL;

static char const * const USAGE = "%s: [-p port number]";

static char const * const DEFAULT_CLIENT_ID = "distlog_console_producer";
static char const * const DEFAULT_TOPIC  = "test";
static char const * const DEFAULT_HOSTNAME  = "localhost";
static const int DEFAULT_PORT = 9092;

static void on_ack(const cl_correlation_id);
static void on_response(struct dl_request *, struct dl_response *);

static void dlc_siginfo_handler(int);
static void dlc_sigint_handler(int);
static void dlc_on_ack(const dl_correlation_id);
static void dlc_on_response(struct dl_request const * const,
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
	distlog_client_fini();

	exit(EXIT_SUCCESS);
}


static void
on_ack(const dl_correlation_id correlation_id)
{
	debug(PRIO_NORMAL, "Broker acknowledged message "
	    "(correlation ID = %lu\n)", correlation_id);
}

static void
on_response(struct dl_request *request, struct dl_response *response)
{
	int resend_timeout = 40;
	int maxbytes = 1000;
	int minbytes = 0;
	
	debug(PRIO_NORMAL, "Response was recieved with correlation ID %d\n",
		response->dlrs_correlation_id);

	switch (request->dlrqm_api_key) {
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
			debug(PRIO_NORMAL, "Offset: %d\n",
			    response->dlrs_message.dlrs_offset_response.dlors_offset);
			debug(PRIO_NORMAL, "Topic: %s\n",
			    response->dlrs_message.dlrs_offset_response.dlors_topic_name);


			distlog_recv(0, "test", true, resend_timeout,
			response->dlrs_message.dlrs_offset_response.dlors_topic_name,
			response->dlrs_message.dlrs_offset_response.dlors_offset, maxbytes, minbytes);
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
	char * client_id = DEFAULT_CLIENT_ID;
	char * topic = DEFAULT_TOPIC;
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
	cc.to_resend = true;
	cc.resender_thread_sleep_length = 10;
	cc.request_notifier_thread_sleep_length = 3;
	cc.reconn_timeout = 5;
	cc.poll_timeout = 3000;
	cc.dlcc_on_ack = on_ack;
	cc.dlcc_on_response = on_response;

	if (distlog_client_init(hostname, port, &cc) != 0) {
		fprintf(stderr,
		    "Error initialising the distributed log client.\n");
		exit(EXIT_FAILURE);
	}

	distlog_offset(0, client_id, cc.to_resend, resend_timeout,
		topic, wantoff, maxbytes, minbytes);

       	/* Echo to the command line from the distributed log. */	
	for (;;) {
		//distlog_recv(0, client_id, cc.to_resend, resend_timeout,
		//    topic, wantoff, maxbytes, minbytes);

		// print response to stdout
		sleep(10);
	}

	distlog_client_fini();

	return 0;
}
