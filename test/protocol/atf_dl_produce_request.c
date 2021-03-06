/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#include <sys/types.h>
#include <sys/sbuf.h>

#include <atf-c.h>
#include <stdlib.h>
#include <strings.h>

#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_new.h"
#include "dl_message_set.h"
#include "dl_produce_request.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static
void test10_cb(struct dl_produce_request_topic *self, void *arg)
{
	struct sbuf *name;

	name = dl_produce_request_topic_get_name(self);
	ATF_REQUIRE(strcmp(sbuf_data(name), "test-topic") == 0);
}

static
void test11_cb(struct dl_produce_request_partition *self, void *arg)
{

	ATF_REQUIRE(dl_produce_request_partition_get_num(self) == 0);
}

/* Test 1
 * dl_produce_request_new_nomsg() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_produce_request *request;
	struct dl_produce_request_topic *request_topic;
	struct dl_produce_request_partition *request_part;
	struct sbuf *client_id, *topic, *topic_tmp;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, client_id,
	    DL_LEADER_ACKS, 1000, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	ATF_REQUIRE(dl_produce_request_get_timeout(request) == 1000);
	ATF_REQUIRE(dl_produce_request_get_required_acks(request) == DL_LEADER_ACKS);
	ATF_REQUIRE(request != NULL);

	rc = dl_produce_request_get_singleton_topic(request, &request_topic);
	ATF_REQUIRE(rc == 0);

	topic_tmp = dl_produce_request_topic_get_name(request_topic);
	ATF_REQUIRE(strcmp(sbuf_data(topic), sbuf_data(topic_tmp)) == 0);

	rc = dl_produce_request_topic_get_singleton_partition(request_topic,
	    &request_part);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(dl_produce_request_partition_get_num(request_part) == 0);
	ATF_REQUIRE(dl_produce_request_partition_get_message_set(request_part) == NULL);

	dl_produce_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 2
 * dl_produce_request_new_nomsg() - valid params, NULL client id. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_produce_request *request;
	struct sbuf *topic;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, NULL, 1000,
	    DL_LEADER_ACKS, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	dl_produce_request_delete(request);
	sbuf_delete(topic);
}

/* Test 3 
 * dl_produce_request_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_produce_request *request;
	struct dl_message_set *msg_set;
	struct sbuf *client_id, *topic;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int key_len, value_len, rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	key_len = sizeof(key);
	value_len = sizeof(value);
	rc = dl_message_set_new(&msg_set, key, key_len, value, value_len);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msg_set != NULL);

	rc = dl_produce_request_new(&request, 0, client_id, 1000,
	    DL_LEADER_ACKS, topic, msg_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	dl_produce_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 4 
 * dl_produce_request_new() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_request *request;
	struct dl_message_set *msg_set;
	struct sbuf *client_id, *topic;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int key_len, value_len, rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	key_len = sizeof(key);
	value_len = sizeof(value);
	rc = dl_message_set_new(&msg_set, key, key_len, value, value_len);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msg_set != NULL);

	atf_tc_expect_signal(6, "NULL value passed to request.");
	rc = dl_produce_request_new(NULL, 0, client_id, 1000, DL_LEADER_ACKS,
	    topic, msg_set);

	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 5 
 * dl_produce_request_new() - invalid params - topic name NULL. 
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_produce_request *request;
	struct dl_message_set *msg_set;
	struct sbuf *client_id;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int key_len, value_len, rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	key_len = sizeof(key);
	value_len = sizeof(value);
	rc = dl_message_set_new(&msg_set, key, key_len, value, value_len);
	ATF_REQUIRE(msg_set != NULL);

	atf_tc_expect_signal(6, "NULL value passed to topic name.");
	rc = dl_produce_request_new(&request, 0, client_id, 1000, DL_LEADER_ACKS,
	    NULL, msg_set);

	sbuf_delete(client_id);
}

/* Test 6 
 * dl_request_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_bbuf *buffer;
	struct dl_produce_request *request;
	struct sbuf *client_id, *topic;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, client_id, 1000,
	    DL_LEADER_ACKS, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	rc = dl_request_encode(request, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_bbuf_delete(buffer);
	dl_produce_request_delete(request);
	sbuf_delete(topic);
	sbuf_delete(client_id);
}

/* Test 7 
 * dl_produce_request_encode() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct dl_bbuf *buffer;
	int rc;

	rc = dl_bbuf_new_auto(&buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	atf_tc_expect_signal(6, "NULL value passed to request.");
	dl_request_encode(NULL, &buffer);

	dl_bbuf_delete(buffer);
}

/* Test 8 
 * dl_produce_request_encode() - invalid params - buffer NULL. 
 */
ATF_TC_WITHOUT_HEAD(test8);
ATF_TC_BODY(test8, tc)
{
	struct dl_produce_request *request;
	struct sbuf *client_id, *topic;
	struct dl_bbuf *buffer;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, client_id, 1000,
	    DL_LEADER_ACKS, topic);
	ATF_REQUIRE(rc == 0);

	atf_tc_expect_signal(6, "NULL value passed to buffer.");
	dl_request_encode(request, NULL);
	
	dl_produce_request_delete(request);
	sbuf_delete(topic);
	sbuf_delete(client_id);
}

/* Test 9 
 * dl_produce_request_encode|decode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test9);
ATF_TC_BODY(test9, tc)
{
	struct dl_message_set *msgset;
	struct dl_produce_request *request, *decoded_request;
	struct sbuf *client_id, *topic;
	struct dl_bbuf *buffer;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int key_len, value_len, rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	key_len = sizeof(key);
	value_len = sizeof(value);
	rc = dl_message_set_new(&msgset, key, key_len, value, value_len);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_produce_request_new(&request, 0, client_id, 1000,
	    DL_LEADER_ACKS, topic, msgset);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_encode(request, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_bbuf_flip(buffer);	
	rc = dl_produce_request_decode(&decoded_request, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(decoded_request != NULL);

	dl_produce_request_delete(request);
	dl_produce_request_delete(decoded_request);
	dl_bbuf_delete(buffer);
	sbuf_delete(topic);
	sbuf_delete(client_id);
}

/* Test 10
 * dl_produce_request_topic_foreach() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test10);
ATF_TC_BODY(test10, tc)
{
	struct dl_produce_request *request;
	struct dl_produce_request_topic *request_topic;
	struct dl_produce_request_partition *request_part;
	struct sbuf *client_id, *topic, *topic_tmp;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, client_id,
	    DL_LEADER_ACKS, 1000, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	ATF_REQUIRE(dl_produce_request_get_timeout(request) == 1000);
	ATF_REQUIRE(dl_produce_request_get_required_acks(request) == DL_LEADER_ACKS);
	ATF_REQUIRE(request != NULL);

	dl_produce_request_topic_foreach(request, test10_cb, NULL);
	ATF_REQUIRE(rc == 0);

	dl_produce_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 11
 * dl_produce_request_partition_foreach() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test11);
ATF_TC_BODY(test11, tc)
{
	struct dl_produce_request *request;
	struct dl_produce_request_topic *request_topic;
	struct dl_produce_request_partition *request_part;
	struct sbuf *client_id, *topic, *topic_tmp;
	int rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_nomsg(&request, 0, client_id,
	    DL_LEADER_ACKS, 1000, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);
	ATF_REQUIRE(dl_produce_request_get_timeout(request) == 1000);
	ATF_REQUIRE(dl_produce_request_get_required_acks(request) == DL_LEADER_ACKS);
	ATF_REQUIRE(request != NULL);

	rc = dl_produce_request_get_singleton_topic(request, &request_topic);
	ATF_REQUIRE(rc == 0);

	dl_produce_request_partition_foreach(request_topic, test11_cb, NULL);
	ATF_REQUIRE(rc == 0);

	dl_produce_request_delete(request);
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
	ATF_TP_ADD_TC(tp, test9);
	ATF_TP_ADD_TC(tp, test10);
	ATF_TP_ADD_TC(tp, test11);

	return atf_no_error();
}
