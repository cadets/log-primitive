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
#include "dl_message_set.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1 
 * dl_message_set_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_message_set *message_set;
	char *key = "key", *value = "value";
	int rc;

	rc = dl_message_set_new(&message_set, key, strlen(key), value,
	    strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(message_set != NULL);

	dl_message_set_delete(message_set);
}

/* Test 2 
 * dl_message_set_new() - invalid params - NULL message set. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	int rc;
	char *key = "key", *value = "value";

	atf_tc_expect_signal(6, "NULL value passed to request.");
	rc = dl_message_set_new(NULL, key, strlen(key), value, strlen(value));
}

/* Test 3 
 * dl_message_set_delete() - invalid params - NULL message set. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{

	atf_tc_expect_signal(6, "NULL value passed to request.");
	dl_message_set_delete(NULL);
}

/* Test 4 
 * dl_message_set_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_bbuf *target;
	struct dl_message_set *msgset;
	int rc;
	char *key = "key", *value = "value";

	rc = dl_message_set_new(&msgset, key, strlen(key), value,
	    strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_bbuf_new(&target, NULL, DL_MTU,
	    (DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_message_set_encode(msgset, target);
	ATF_REQUIRE(rc == 0);

	dl_bbuf_delete(target);
	dl_message_set_delete(msgset);
}

/* Test 5 
 * dl_message_set_decode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_bbuf *buf;
	struct dl_message_set *msgset, *decoded_msgset;
	int rc;
	char *value = "Tets";

	rc = dl_message_set_new(&msgset, NULL, 0, value,
	    strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_bbuf_new(&buf, NULL, DL_MTU,
	    (DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buf != NULL);

	rc = dl_message_set_encode(msgset, buf);
	ATF_REQUIRE(rc == 0);

	unsigned char *bufval = dl_bbuf_data(buf);
	for (int i = 0; i < dl_bbuf_pos(buf); i++) {
		DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
	};
	DLOGTR0(PRIO_LOW, "\n");

	dl_bbuf_flip(buf);	
	rc = dl_message_set_decode(&decoded_msgset, buf);
	ATF_REQUIRE(rc == 0);


	dl_bbuf_delete(buf);
	dl_message_set_delete(msgset);
}

/* Test 6 
 * dl_message_set_encode_compressed() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct dl_bbuf *target;
	struct dl_message_set *msgset;
	int rc;
	char *value = "Tets";

	rc = dl_message_set_new(&msgset, NULL, 0, value,
	    strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_bbuf_new(&target, NULL, DL_MTU,
	    (DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(msgset != NULL);

	rc = dl_message_set_encode_compressed(msgset, target);
	ATF_REQUIRE(rc == 0);

	unsigned char *bufval = dl_bbuf_data(target);
	for (int i = 0; i < dl_bbuf_pos(target); i++) {
		DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
	};
	DLOGTR0(PRIO_LOW, "\n");

	DLOGTR0(PRIO_LOW, "Encoded request message\n");

	dl_message_set_delete(msgset);
	dl_bbuf_delete(target);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);
	ATF_TP_ADD_TC(tp, test5);
	ATF_TP_ADD_TC(tp, test6);

	return atf_no_error();
}
