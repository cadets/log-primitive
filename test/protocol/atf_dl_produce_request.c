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

#include <sys/types.h>
#include <sys/sbuf.h>

#include <atf-c.h>
#include <stdlib.h>
#include <strings.h>

#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_produce_request.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1
 * dl_produce_request_new_empty() - valid params. 
 */
ATF_TC(test1);
ATF_TC_HEAD(test1, tc)
{
	atf_tc_set_md_var(tc,
	    "descr", "dl_produce_request_new_entry() valid params");
}

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

	rc = dl_produce_request_new_empty(&request, 0, client_id, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	dl_produce_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 2
 * dl_produce_request_new_empty() - NULL client id. 
 */
ATF_TC(test2);
ATF_TC_HEAD(test2, tc)
{
	atf_tc_set_md_var(tc,
	    "descr", "dl_produce_request_new_empty() - NULL client id."); 
}

ATF_TC_BODY(test2, tc)
{
	struct dl_request *request;
	struct sbuf *topic;
	int rc;

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	rc = dl_produce_request_new_empty(&request, 0, NULL, topic);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	sbuf_delete(topic);
}

/* Test 3 */

ATF_TC(test3);
ATF_TC_HEAD(test3, tc)
{
	atf_tc_set_md_var(tc, "descr", "ProduceRequest ctor");
}

ATF_TC_BODY(test3, tc)
{
	struct dl_request *request;
	struct dl_message_set *msg_set;
	struct sbuf *client_id, *topic;
	char *key = "key", *value = "value";
	int key_len, value_len, rc;

	client_id = sbuf_new_auto();
	sbuf_cpy(client_id, "test-client");
	sbuf_finish(client_id);

	topic = sbuf_new_auto();
	sbuf_cpy(topic, "test-topic");
	sbuf_finish(topic);

	key_len = strlen(key);
	value_len = strlen(value);
	msg_set = dl_message_set_new(key, key_len, value, value_len);
	ATF_REQUIRE(msg_set != NULL);

	rc = dl_produce_request_new(&request, 0, client_id, topic, msg_set);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(request != NULL);

	dl_produce_request_delete(request);
	sbuf_delete(client_id);
	sbuf_delete(topic);
}

/* Test 4 */

ATF_TC(test4);
ATF_TC_HEAD(test4, tc)
{
	atf_tc_set_md_var(tc, "descr", "ProduceRequest ctor NULL client_id");
}

ATF_TC_BODY(test4, tc)
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

	rc = dl_produce_request_new_empty(&request, 0, client_id, topic);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_encode(request, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	dl_produce_request_delete(request);
	sbuf_delete(topic);
	sbuf_delete(client_id);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);

	return atf_no_error();
}
