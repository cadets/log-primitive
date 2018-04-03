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

#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1
 * dl_correlation_id_new() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_correlation_id *id = NULL;
	int rc;

	rc = dl_correlation_id_new(&id);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(id != NULL);

	dl_correlation_id_delete(id);
}

/* Test 2
 * dl_correlation_id_new() - invalid params - correlation id NULL.
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	int rc;

	atf_tc_expect_signal(6, "NULL value passed to correlation id.");
	rc = dl_correlation_id_new(NULL);
}

/* Test 3
 * dl_correlation_id_delete() - invalid params - correlation id NULL.
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{

	atf_tc_expect_signal(6, "NULL value passed to correlation id.");
	dl_correlation_id_delete(NULL);
}

/* Test 4
 * dl_correlation_id_val() - invalid params - correlation id NULL.
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{

	atf_tc_expect_signal(6, "NULL value passed to correlation id.");
	dl_correlation_id_val(NULL);
}

/* Test 5
 * dl_correlation_id_inc() - invalid params - correlation id NULL.
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{

	atf_tc_expect_signal(6, "NULL value passed to correlation id.");
	dl_correlation_id_inc(NULL);
}

/* Test 6
 * dl_correlation_id_val() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_correlation_id *id = NULL;
	int32_t val;
	int rc;

	rc = dl_correlation_id_new(&id);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(id != NULL);
	
	val = dl_correlation_id_val(id);
	ATF_REQUIRE(val == 0);

	dl_correlation_id_delete(id);
}

/* Test 7
 * dl_correlation_id_inc() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct dl_correlation_id *id = NULL;
	int32_t val;
	int rc;

	rc = dl_correlation_id_new(&id);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(id != NULL);
	
	dl_correlation_id_inc(id);
	val = dl_correlation_id_val(id);
	ATF_REQUIRE(val == 1);

	dl_correlation_id_delete(id);
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

	return atf_no_error();
}
