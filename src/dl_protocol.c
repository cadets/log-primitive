/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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
#include <stdio.h>
#include <stdarg.h>

//#include "message.h"
//#include "dl_protocol_common.h"

#include "dl_assert.h"
#include "dl_protocol.h"
#include "dl_common.h"
#include "dl_utils.h"

int
read_msg(int fd, char *saveto)
{
	char *buffer = saveto;
	struct dl_request_or_response req_or_res;
	int ret;
	int total = 0;

	printf("buffer = %p\n", buffer);

	/* Read the size of the request or response to process. */
	ret = recv(fd, buffer, sizeof(req_or_res.dlrx_size), 0);
	debug(PRIO_LOW, "Read %d bytes (%s)...\n", ret, buffer);
	if (ret > 0) {
		if (dl_decode_request_or_response(&req_or_res, buffer)) {
			debug(PRIO_LOW, "\tNumber of bytes: %d\n",
			    req_or_res.dlrx_size);

			buffer += sizeof(int32_t);

			while (total < req_or_res.dlrx_size) {
				ret = recv(fd, &buffer[total], req_or_res.dlrx_size-total, 0);
				debug(PRIO_LOW, "\tRead %d characters; expected %d\n",
				ret, req_or_res.dlrx_size);
				total += ret;
			}

			for (int b = 0; b < req_or_res.dlrx_size; b++) {
				printf("0x%02X\n", buffer[b]);
			}

			return ret;
		}
	} else {
		return -1;
	}
}

void
dl_build_fetch_request(struct dl_request *req_msg,
    int32_t correlation_id, char *client_id, va_list varlist)
{
	struct dl_fetch_request *request;
	long timestamp;
	int message_it;

	DL_ASSERT(req_msg != NULL, "Request message cannot be NULL");
	    
	char *topic_name = va_arg(varlist, char*);
	long fetch_offset = va_arg(varlist, long);
	int maxbytes = va_arg(varlist, int);
	int minbytes = va_arg(varlist, int);

	printf("fetch request topic = %s\n", topic_name);
	printf("fetch request address = %p\n", req_msg);
	
	/* Construct the produce request header. */	
	req_msg->dlrqm_api_key = DL_FETCH_REQUEST;
	req_msg->dlrqm_api_version = 1; // TODO: fixed version of API
	req_msg->dlrqm_correlation_id = correlation_id;
	strlcpy(req_msg->dlrqm_client_id, client_id, DL_MAX_CLIENT_ID);

        /* Construct the fetch request body. */
	request = &req_msg->dlrqm_message.dlrqmt_fetch_request;

	request->dlfr_replica_id = -1;
	request->dlfr_max_wait_time = 1000;
	request->dlfr_min_bytes = minbytes;
	strlcpy(request->dlfr_topic_name, topic_name, TOPIC_NAME_SIZE);
	request->dlfr_partition = 0;
	request->dlfr_fetch_offset = fetch_offset;
	request->dlfr_max_bytes = maxbytes;
}

void
dl_build_produce_request(struct dl_request *req_msg,
    int32_t correlation_id, char *client_id, va_list varlist)
{
	struct dl_produce_request *produce_request;
	long timestamp;
	int message_it;

	DL_ASSERT(req_msg != NULL, "Request message cannot be NULL");
	    
	char *topic_name = va_arg(varlist, char*);
	int message_set_size = va_arg(varlist, int);

	printf("topic = %s, mss = %d\n", topic_name, message_set_size);
	
	/* Construct the produce request header. */	
	req_msg->dlrqm_api_key = DL_PRODUCE_REQUEST;
	// TODO remove this
	//req_msg->dlrqm_api_version = 1; // TODO: fixed version of API
	req_msg->dlrqm_correlation_id = correlation_id;
	strlcpy(req_msg->dlrqm_client_id, client_id, DL_MAX_CLIENT_ID);

        /* Construct the produce request body. */
	produce_request = &req_msg->dlrqm_message.dlrqmt_produce_request;

	// TODO: surely this comes from the client or the configuration
	produce_request->dlpr_required_acks = 1;
	// TODO: the time to await a response
	produce_request->dlpr_timeout = 0; //-1;
	strlcpy(produce_request->dlpr_topic_name, topic_name,
	    TOPIC_NAME_SIZE);
	// TODO :default partition = 0
	produce_request->dlpr_partition = 0;
	
	timestamp = time(NULL);
	produce_request->dlpr_message_set_size = message_set_size;
	for (message_it = 0; message_it < message_set_size; message_it++) {
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
		printf("build = %p\n", message);

		message->dlm_crc = 0; // get_crc(value, strlen(value));
		message->dlm_magic_byte = 1; // TODO: const
                message->dlm_attributes = 0; // TODO: &= DL_MSG_ATTR_LOG_APPEND_TIME;
		message->dlm_timestamp = timestamp;
		// TODO: The key can be NULL
		memcpy(message->dlm_key, key, strlen(key));
		memcpy(message->dlm_value, value, strlen(value));
	}
}

/*
enum response_type
match_requesttype(enum request_type rt)
{
	switch(rt){
	case REQUEST_PRODUCE:
		return RESPONSE_PRODUCE;
	case REQUEST_FETCH:
		return RESPONSE_FETCH;
	case REQUEST_OFFSET:
		return RESPONSE_OFFSET;
	case REQUEST_METADATA:
		return RESPONSE_METADATA;
	case REQUEST_OFFSET_FETCH:
		return RESPONSE_OFFSET_FETCH;
	case REQUEST_OFFSET_COMMIT:
		return RESPONSE_OFFSET_COMMIT;
	case REQUEST_GROUP_COORDINATOR:
		return RESPONSE_GROUP_COORDINATOR;
	}
	return RESPONSE_PRODUCE;
}

dl_correlation_id
get_corrid(char *beg)
{
	return get_int(beg, CORRELATIONID_FIELD_SIZE);
}

void
clear_fetch_responsemessage(struct fetch_response* fr)
{
	fr->num_sfr = 0;
	fr->throttle_time = 0;
	for (int i=0; i < MAX_SUB_FETCH_SIZE; i++){
		fr->sfr[i].num_ssfr = 0;
		for (int j=0; j < MAX_SUB_SUB_FETCH_SIZE; j++){
			fr->sfr[i].ssfr[j].message_set_size= 0;
			fr->sfr[i].ssfr[j].message_set.num_elems = 0;
		}
	}
}

void
clear_offset_responsemessage(struct offset_response *ofr)
{
	ofr->num_sor = 0;
	for (int i = 0; i < MAX_SOR; i++){
		ofr->sor[i].num_parts = 0;
		for (int j = 0; j < MAX_PART_OFFSETS; j++){
			ofr->sor[i].partition_offsets[j].num_offsets = 0;
		}
	}
}

void
clear_produce_responsemessage(struct produce_response *pr)
{
	pr->num_sub = 0;
	for (int i = 0; i < MAX_SUB_SIZE; i++){
		pr->spr[i].num_subsub = 0;
	}
}

void
clear_metadata_responsemessage(struct metadata_response *mr)
{
	mr->num_brokers=0;
}

void
clear_offsetfetch_responsemessage(struct offset_fetch_response *ofr)
{
	ofr->num_sub_ofr = 0;

	for(int i = 0; i < MAX_SUB_OFR; i++){
		ofr->sofr[i].num_ssofr = 0;
	}
}

void
clear_offsetcommit_responsemessage(struct offset_commit_response *ocr)
{
	ocr->num_sub_ocr = 0;
	for (int i = 0; i < MAX_SUB_OCR; i++) {
		ocr->socr[i].num_ssocr = 0;
	}
}

void
clear_group_coordinator_responsemessage(struct group_coordinator_response *gcr)
{
	gcr->corrdinator_port = 0;
}

void
clear_responsemessage(struct response_message *rm, enum request_type rt)
{
	switch(rt){
	case REQUEST_FETCH:
		clear_fetch_responsemessage(&rm->rm.fetch_response);
		break;
	case REQUEST_OFFSET:
		clear_offset_responsemessage(&rm->rm.offset_response);
		break;
	case REQUEST_PRODUCE:
		clear_produce_responsemessage(&rm->rm.produce_response);
		break;
	case REQUEST_METADATA:
		clear_metadata_responsemessage(&rm->rm.metadata_response);
		break;
	case REQUEST_OFFSET_FETCH:
		clear_offsetfetch_responsemessage(
			&rm->rm.offset_fetch_response);
		break;
	case REQUEST_OFFSET_COMMIT:
		clear_offsetcommit_responsemessage(
			&rm->rm.offset_commit_response);
		break;
	case REQUEST_GROUP_COORDINATOR:
		clear_group_coordinator_responsemessage(
			&rm->rm.group_coordinator_response);
		break;
	}
}

void
clear_fetch_requestmessage(struct fetch_request *fr)
{
	fr->partition = 0;
}

void
clear_offsetfetch_requestmessage(struct offset_fetch_request *ofr)
{
	ofr->partition = 0;
}

void
clear_offset_requestmessage(struct offset_request *ofr)
{
	ofr->partition = 0;
}

void
clear_produce_requestmessage(struct produce_request *pr)
{
	pr->spr.sspr.message_set_size = 0;
	pr->spr.sspr.mset.num_elems = 0;
}

void
clear_metadata_requestmessage(struct metadata_request *mr)
{
	mr->num_topics = 0;
}

void
clear_offsetcommit_requestmessage(struct offset_commit_request *ofr)
{
	ofr->consumer_group_generation_id = 0;
}

void
clear_group_coordinator_requestmessage(struct group_coordinator_request *gcr)
{
	bzero(gcr->group_id, GROUP_ID_SIZE); 
}

void
clear_requestmessage(struct request_message *rm, enum request_type rt)
{
	printf("rt = %d\n", rt);
	switch(rt) {
	case REQUEST_FETCH:
		clear_fetch_requestmessage(&rm->rm.fetch_request);
		break;
	case REQUEST_OFFSET:
		clear_offset_requestmessage(&rm->rm.offset_request);
		break;
	case REQUEST_PRODUCE:
		clear_produce_requestmessage(&rm->rm.produce_request);
		break;
	case REQUEST_METADATA:
		clear_metadata_requestmessage(&rm->rm.metadata_request);
		break;
	case REQUEST_OFFSET_FETCH:
		clear_offsetfetch_requestmessage(&rm->rm.offset_fetch_request);
		break;
	case REQUEST_OFFSET_COMMIT:
		clear_offsetcommit_requestmessage(
		    &rm->rm.offset_commit_request);
		break;
	case REQUEST_GROUP_COORDINATOR:
		clear_group_coordinator_requestmessage(
		    &rm->rm.group_coordinator_request);
		break;
	}       
}
*/
