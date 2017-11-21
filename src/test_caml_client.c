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

#include <unistd.h>

#include "caml_client.h"
#include "caml_common.h"
#include "utils.h"
#include "protocol.h"

static void on_ack(unsigned long);
static void on_response(struct RequestMessage *, struct ResponseMessage *);

unsigned short PRIO_LOG = PRIO_LOW;

static void
on_ack(unsigned long correlationId)
{
	printf("Acknowledged message %lu\n", correlationId);
}

static void
on_response(struct RequestMessage *rm, struct ResponseMessage *rs)
{
	debug(PRIO_NORMAL, "Response was recieved with correlationId %d\n",
		rs->CorrelationId);

	switch (rm->APIKey) {
		case REQUEST_PRODUCE:
			printf("Produced the following messages: \n");
			for (int i = 0; i < rm->rm.produce_request.spr.sspr.mset.NUM_ELEMS; i++) {
				printf("\tMessage: %s\n", rm->rm.produce_request.spr.sspr.mset.Elems[i].message.value); 
			}

			printf("Request answer: \n");
			for (int i = 0; i <rs->rm.produce_response.NUM_SUB; i++){
				for (int j=0; j < rs->rm.produce_response.spr[i].NUM_SUBSUB; j++){
					struct SubSubProduceResponse *csspr = &rs->rm.produce_response.spr[i].sspr[j];
					printf("Timestamp:\t%ld\n", csspr->Timestamp);
					printf("Offset:\t%ld\n", csspr->Offset); 
					printf("ErrorCode:\t%d\n", csspr->ErrorCode); 
					printf("Partition:\t%d\n", csspr->Partition); 
				}
			}
			break;
		case REQUEST_FETCH:
			/* FALLTHROUGH */
		case REQUEST_OFFSET:
			/* FALLTHROUGH */
		case REQUEST_OFFSET_COMMIT:
			/* FALLTHROUGH */
		case REQUEST_OFFSET_FETCH:
			/* FALLTHROUGH */
		case REQUEST_METADATA:
			/* FALLTHROUGH */
		case REQUEST_GROUP_COORDINATOR:
			break;
	}
}

int
main()
{
	int i = 0;
	char * my_client_name = "NAME";
	char * my_topic_name  = "Topic Name";
	int resend_timeout = 40;
	int maxbytes = 1000;
	int minbytes = 1;
	int wantoff = 0;

	struct client_configuration * cc =
		(struct client_configuration *) malloc(
		sizeof(struct client_configuration));
	cc->to_resend = 1;
	cc->resender_thread_sleep_length = 10;
	cc->request_notifier_thread_sleep_length = 3;
	cc->reconn_timeout = 5;
	cc->poll_timeout = 3000;
	cc->on_ack = on_ack;
	cc->on_response = on_response;

	distlog_client_busyloop("127.0.0.1", 9999, cc);
    
	while (i < 5) {
		printf("I am inserting stuffs\n");
		distlog_send_request(
			0,
			REQUEST_PRODUCE,
			i,
			my_client_name,
			cc->to_resend,
			resend_timeout,
			my_topic_name,
			3,
			"Test msg 1",
			"Test msg 2",
			"Test msg 3");
		i++;
	}

	sleep(5);

    	for (;;) {
		printf("I am requesting stuffs\n");
		distlog_send_request(
			0,
			REQUEST_FETCH,
			i,
			my_client_name,
			cc->to_resend,
			resend_timeout,
			my_topic_name,
			wantoff,
			maxbytes,
			minbytes);
		i++;
		sleep(30);
	}

	return 1;
}
