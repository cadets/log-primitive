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
 * 2. Redistributions in binary form must refetch the above copyright
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
#include "dl_fetch_response.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1 
 * dl_fetch_response_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_fetch_response *response;
	struct dl_message_set *message_set;
	struct sbuf *topic;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_message_set_new(&message_set, key, sizeof(key), value,
	    sizeof(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(message_set != NULL);

	rc = dl_fetch_response_new(&response, 0, topic, 0, 0, message_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);

	dl_fetch_response_delete(response);
	sbuf_delete(topic);
}

/* Test 2
 * dl_fetch_request_new() - invalid params - NULL response. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_fetch_response *response;
	struct sbuf *topic;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	atf_tc_expect_signal(6, "NULL value passed to response.");
	rc = dl_fetch_response_new(NULL, 0, topic, 0, 0, NULL);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);

	sbuf_delete(topic);
}

/* Test 3
 * dl_fetch_request_new() - invalid params - NULL topic. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_fetch_response *response;
	int rc;

	atf_tc_expect_signal(6, "NULL value passed to topic.");
	rc = dl_fetch_response_new(&response, 0, NULL, 0, 0, NULL);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);
}

/* Test 4 
 * dl_fetch_response_delete() - invalid params - request NULL. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	atf_tc_expect_signal(6, "NULL value passed to response.");
	dl_fetch_response_delete(NULL);
}

/* Test 5 
 * dl_fetch_response_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_fetch_response *response;
	struct dl_message_set *message_set;
	struct sbuf *topic;
	struct dl_bbuf *buffer;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_message_set_new(&message_set, key, sizeof(key), value,
	    sizeof(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(message_set != NULL);

	rc = dl_fetch_response_new(&response, 0, topic, 0, 0, message_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);
	
	rc = dl_bbuf_new(&buffer, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);

	rc = dl_fetch_response_encode(response, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_fetch_response_delete(response);
	dl_bbuf_delete(buffer);
	sbuf_delete(topic);
}

/* Test 6 
 * dl_fetch_response_encode() - invalid params - buffer. 
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_fetch_response *response;
	struct sbuf *topic;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_fetch_response_new(&response, 0, topic, 0, 0, NULL);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);

	atf_tc_expect_signal(6, "NULL value passed to buffer.");
	rc = dl_fetch_response_encode(response, NULL);

	dl_fetch_response_delete(response);
	sbuf_delete(topic);
}

/* Test 7 
 * dl_fetch_response_encode() - invalid params - response. 
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct dl_bbuf *buffer;
	int rc;

	rc = dl_bbuf_new(&buffer, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);

	atf_tc_expect_signal(6, "NULL value passed to response.");
	rc = dl_fetch_response_encode(NULL, buffer);

	dl_bbuf_delete(buffer);
}

/* Test 8 
 * dl_fetch_response_decode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test8);
ATF_TC_BODY(test8, tc)
{
	struct dl_fetch_response *response, *decoded_response;
	struct dl_fetch_response_topic *response_topic;
	struct dl_message_set *message_set;
	struct sbuf *topic;
	struct dl_bbuf *buffer;
	int64_t high_watermark = 1234;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int32_t cid = 10;
	int16_t error_code = 0;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_message_set_new(&message_set, key, sizeof(key), value,
	    sizeof(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(message_set != NULL);

	rc = dl_fetch_response_new(&response, cid, topic, error_code,
	    high_watermark, message_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);

	rc = dl_bbuf_new(&buffer, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);

	rc = dl_fetch_response_encode(response, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_bbuf_flip(buffer);	
	rc = dl_fetch_response_decode(&decoded_response, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(decoded_response != NULL);
	response_topic = SLIST_FIRST(&decoded_response->dlfr_topics);
	ATF_REQUIRE(strcmp(sbuf_data(response_topic->dlfrt_topic_name),
	    sbuf_data(topic)) == 0);
	ATF_REQUIRE(response_topic->dlfrt_partitions[0].dlfrp_error_code ==
	    error_code);
	ATF_REQUIRE(response_topic->dlfrt_partitions[0].dlfrp_high_watermark==
	    high_watermark);

	dl_fetch_response_delete(response);
	dl_bbuf_delete(buffer);
	dl_fetch_response_delete(decoded_response);
	sbuf_delete(topic);
}

/* Test 9 
 * dl_fetch_response_decode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test9);
ATF_TC_BODY(test9, tc)
{
	struct dl_fetch_response *response, *decoded_response;
	struct dl_fetch_response_topic *response_topic;
	struct dl_message_set *message_set;
	struct sbuf *topic;
	struct dl_bbuf *buffer;
	int64_t high_watermark = 12345678;
	unsigned char key[] = {"key"};
	unsigned char value[] = {"value"};
	int32_t cid = 1000;
	int16_t error_code = 2;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_message_set_new(&message_set, key, sizeof(key), value,
	    sizeof(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(message_set != NULL);

	rc = dl_fetch_response_new(&response, cid, topic, error_code,
	    high_watermark, message_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(response != NULL);

	rc = dl_bbuf_new(&buffer, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);

	rc = dl_fetch_response_encode(response, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_bbuf_flip(buffer);	
	rc = dl_fetch_response_decode(&decoded_response, buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(decoded_response != NULL);
	response_topic = SLIST_FIRST(&decoded_response->dlfr_topics);
	ATF_REQUIRE(strcmp(sbuf_data(response_topic->dlfrt_topic_name),
	    sbuf_data(topic)) == 0);
	ATF_REQUIRE(response_topic->dlfrt_partitions[0].dlfrp_error_code ==
	    error_code);
	ATF_REQUIRE(response_topic->dlfrt_partitions[0].dlfrp_high_watermark==
	    high_watermark);

	dl_fetch_response_delete(response);
	dl_bbuf_delete(buffer);
	dl_fetch_response_delete(decoded_response);
	sbuf_delete(topic);
}

/* Test 10
 * dl_fetch_response_decode() - invalid params - buffer. 
 */
ATF_TC_WITHOUT_HEAD(test10);
ATF_TC_BODY(test10, tc)
{
	struct dl_fetch_response *response;
	struct sbuf *topic;
	int rc;

	atf_tc_expect_signal(6, "NULL value passed to buffer.");
	rc = dl_fetch_response_decode(&response, NULL);
}

/* Test 11 
 * dl_fetch_response_decode() - invalid params - response. 
 */
ATF_TC_WITHOUT_HEAD(test11);
ATF_TC_BODY(test11, tc)
{
	struct dl_bbuf *buffer;
	int rc;

	rc = dl_bbuf_new(&buffer, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);

	atf_tc_expect_signal(6, "NULL value passed to response.");
	rc = dl_fetch_response_decode(NULL, buffer);

	dl_bbuf_delete(buffer);
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
