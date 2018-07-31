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
 */

#include <atf-c.h>
#include <stdlib.h>

#include "dl_bbuf.h"
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1
 * dl_list_offset_request_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_request *request;
	struct sbuf *client_id, *topic;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_list_offset_request_new(&request, 0, client_id, topic, 0L);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	
	dl_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 2
 * dl_produce_request_new_empty() - valid params, NULL client id. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_request *request;
	struct sbuf *topic;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_list_offset_request_new(&request, 0, NULL, topic, 0L);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	sbuf_delete(topic);
}

/* Test 3 
 * dl_produce_request_new() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_request *request;
	struct sbuf *client_id, *topic;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	atf_tc_expect_signal(6, "NULL value passed to request.");
	rc = dl_list_offset_request_new(NULL, 0, client_id, topic, 0L);

	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 4 
 * dl_request_delete() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	atf_tc_expect_signal(6, "NULL value passed to request.");
	dl_request_delete(NULL);
}

/* Test 5
 * dl_list_offset_request_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_request *request;
	struct sbuf *client_id, *topic;
	struct dl_bbuf *buffer;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_list_offset_request_new(&request, 0, client_id, topic, 0L);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	
	rc = dl_request_encode(request, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	
	dl_request_delete(request);
	dl_bbuf_delete(buffer);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 6
 * dl_list_offset_request_encode() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_bbuf *buffer;
	int rc;

	atf_tc_expect_signal(6, "NULL value passed to request.");
	rc = dl_request_encode(NULL, &buffer);
}

/* Test 7
 * dl_list_offset_request_encode() - invalid params - buffer NULL. 
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct dl_request *request;
	struct sbuf *client_id, *topic;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_list_offset_request_new(&request, 0, client_id, topic, 0L);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	
	atf_tc_expect_signal(6, "NULL value passed to request.");
	rc = dl_request_encode(request, NULL);
	
	dl_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 8
 * dl_list_offset_request_decode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test8);
ATF_TC_BODY(test8, tc)
{
	struct dl_request *request, *decoded_request;
	struct dl_list_offset_request_topic *request_topic;
	struct sbuf *client_id, *topic;
	struct dl_bbuf *buffer;
	int32_t cid = 50;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_list_offset_request_new(&request, cid, client_id, topic, -1L);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	
	rc = dl_request_encode(request, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_bbuf_flip(buffer);	

	rc = dl_request_decode(&decoded_request, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(decoded_request != NULL);
	ATF_REQUIRE(decoded_request->dlrqm_api_key == DL_OFFSET_API_KEY);
	ATF_REQUIRE(decoded_request->dlrqm_correlation_id == cid);
	ATF_REQUIRE(
	    decoded_request->dlrqm_offset_request->dlor_replica_id == 0);
	ATF_REQUIRE(strcmp(sbuf_data(decoded_request->dlrqm_client_id),
	    sbuf_data(client_id)) == 0);
	request_topic = SLIST_FIRST(
	    &decoded_request->dlrqm_offset_request->dlor_topics);
	ATF_REQUIRE(strcmp(sbuf_data(request_topic->dlort_topic_name),
	    sbuf_data(topic)) == 0);
	ATF_REQUIRE(request_topic->dlort_partitions[0].dlorp_partition == 0);
	ATF_REQUIRE(request_topic->dlort_partitions[0].dlorp_time == -1L);

	dl_request_delete(decoded_request);
	dl_request_delete(request);
	dl_bbuf_delete(buffer);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);
	ATF_TP_ADD_TC(tp, test5);
	ATF_TP_ADD_TC(tp, test6);
	ATF_TP_ADD_TC(tp, test7);
	ATF_TP_ADD_TC(tp, test8);

	return atf_no_error();
}
