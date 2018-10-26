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

#include "dl_request_queue.h"
#include "dl_memory.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1
 * dl_request_q_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_request_q *q = NULL;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	dl_request_q_delete(q);
}

/* Test 2
 * dl_request_q_new() - invalid params. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{

	atf_tc_expect_signal(6, "NULL value passed to instance.");
	dl_request_q_new(NULL, 10); 
}

/* Test 3
 * dl_request_q_enqueue() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_request_q *q = NULL;
	struct dl_request_element elem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_request_q_enqueue(q, &elem); 
	ATF_REQUIRE(rc == 0);

	dl_request_q_delete(q);
}

/* Test 4
 * dl_request_q_enqueue() - invalid params. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_request_element elem;
	
	atf_tc_expect_signal(6, "NULL value passed to instance.");
	dl_request_q_enqueue(NULL, &elem); 
}

/* Test 5
 * dl_request_q_enqueue() - invalid params. 
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_request_q *q = NULL;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);
	
	atf_tc_expect_signal(6, "NULL value passed to element.");
	dl_request_q_enqueue(q, NULL); 
}

/* Test 6
 * dl_request_q_enqueue_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_bbuf *buf;
	struct dl_request_q *q = NULL;
	struct dl_request_element elem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_bbuf_new_auto(&buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 1, 1); 
	ATF_REQUIRE(rc == 0);

	dl_bbuf_delete(buf);
	dl_request_q_delete(q);
}

/* Test 7
 * dl_request_q_deueue() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct dl_bbuf *buf;
	struct dl_request_q *q = NULL;
	struct dl_request_element elem, *delem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_bbuf_new_auto(&buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 1, 1); 
	ATF_REQUIRE(rc == 0);
	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem->dlrq_correlation_id == 1);

	dl_bbuf_delete(delem->dlrq_buffer);
	dlog_free(delem);
	dl_request_q_delete(q);
}

/* Test 8
 * dl_request_q_deueue() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test8);
ATF_TC_BODY(test8, tc)
{
	struct dl_bbuf *buf;
	struct dl_request_q *q = NULL;
	struct dl_request_element elem, *delem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_bbuf_new_auto(&buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 1, 1); 
	ATF_REQUIRE(rc == 0);
	rc = dl_request_q_enqueue_new(q, buf, 6, 1); 
	ATF_REQUIRE(rc == 0);
	rc = dl_request_q_enqueue_new(q, buf, 2, 1); 
	ATF_REQUIRE(rc == 0);
	rc = dl_request_q_enqueue_new(q, buf, 3, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem->dlrq_correlation_id == 1);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem->dlrq_correlation_id == 6);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 2);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 3);
	dlog_free(delem);

	dl_bbuf_delete(delem->dlrq_buffer);
	dl_request_q_delete(q);
}

/* Test 9
 * dl_request_q_deueue() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test9);
ATF_TC_BODY(test9, tc)
{
	struct dl_bbuf *buf;
	struct dl_request_q *q = NULL;
	struct dl_request_element elem, *delem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_bbuf_new_auto(&buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 1, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 6, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 1);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 6);
	dlog_free(delem);

	rc = dl_request_q_enqueue_new(q, buf, 2, 1); 
	ATF_REQUIRE(rc == 0);
	rc = dl_request_q_enqueue_new(q, buf, 3, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 2);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 3);
	dlog_free(delem);

	dl_bbuf_delete(delem->dlrq_buffer);
	dl_request_q_delete(q);
}

/* Test 10 
 * dl_request_q_deueue() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test10);
ATF_TC_BODY(test10, tc)
{
	struct dl_bbuf *buf;
	struct dl_request_q *q = NULL;
	struct dl_request_element elem, *delem;
	int rc;

	rc = dl_request_q_new(&q, 10); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(q != NULL);

	rc = dl_bbuf_new_auto(&buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 1, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_enqueue_new(q, buf, 6, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 1);
	dlog_free(delem);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 6);
	dlog_free(delem);

	rc = dl_request_q_enqueue_new(q, buf, 2, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 2);
	dlog_free(delem);

	rc = dl_request_q_enqueue_new(q, buf, 3, 1); 
	ATF_REQUIRE(rc == 0);

	rc = dl_request_q_dequeue(q, &delem); 
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(delem != NULL);
	ATF_REQUIRE(delem->dlrq_buffer != NULL);
	ATF_REQUIRE(delem->dlrq_correlation_id == 3);
	dlog_free(delem);

	dl_bbuf_delete(delem->dlrq_buffer);
	dl_request_q_delete(q);
}

/* Test 11
 * dl_request_q_dequeue() - invalid params. 
 */
ATF_TC_WITHOUT_HEAD(test11);
ATF_TC_BODY(test11, tc)
{
	struct dl_request_element *elem;
	
	atf_tc_expect_signal(6, "NULL value passed to instance.");
	dl_request_q_dequeue(NULL, &elem); 
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
