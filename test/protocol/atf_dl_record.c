/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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
#include "dl_record.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1 
 * dl_record__new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_record *record;
	char *key = "key", *value = "value";
	int rc;

	rc = dl_record_new(&record, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(record != NULL);

	dl_record_delete(record);
}

/* Test 2
 * dl_record_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record *record;
	char *key = "key", *value = "value";
	unsigned char test_vector[] = {
	    0x11,
	    0x00,
	    0x00,
	    0x00,
	    0x06,
	    0x6B, 0x65, 0x79,
	    0x0A,
	    0x76, 0x61, 0x6C, 0x75, 0x65,
	    0x00, 0x00
	};
	int rc;

	rc = dl_record_new(&record, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(record != NULL);
	
	rc = dl_record_encode(record, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	//ATF_REQUIRE(dl_bbuf_pos(buffer) == sizeof(test_vector));

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		printf("%x == %x\n", data[i], test_vector[i]);
		//ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_delete(record);
}

/* Test 3
 * dl_record_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record *record;
	char *key = "test", *value = "TEST";
	unsigned char test_vector[] = {
	    0x11,
	    0x00,
	    0x00,
	    0x01,
	    0x04,
	    0x74, 0x65, 0x73, 0x74,
	    0x04,
	    0x54, 0x45, 0x53, 0x54,
	    0xFF, 0xFF, 0xFF, 0xFF
	};
	int rc;

	rc = dl_record_new(&record, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(record != NULL);
	
	rc = dl_record_encode(record, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE(dl_bbuf_pos(buffer) == sizeof(test_vector));

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_delete(record);
}

/* Test 4
 * dl_record_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record *record;
	char *key = "test", *value = "TESTTEST";
	unsigned char test_vector[] = {
	    0x15,
	    0x00,
	    0x00,
	    0x01,
	    0x04,
	    0x74, 0x65, 0x73, 0x74,
	    0x08,
	    0x54, 0x45, 0x53, 0x54, 0x54, 0x45, 0x53, 0x54,
	    0xFF, 0xFF, 0xFF, 0xFF
	};
	int rc;

	rc = dl_record_new(&record, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(record != NULL);
	
	rc = dl_record_encode(record, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE(dl_bbuf_pos(buffer) == sizeof(test_vector));

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_delete(record);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);

	return atf_no_error();
}
