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
#include "dl_record_header.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1 
 * dl_record_header_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_record_header *hdr;
	char *key = "key", *value = "value";
	int rc;

	rc = dl_record_header_new(&hdr, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(hdr != NULL);

	dl_record_header_delete(hdr);
}

/* Test 2 
 * dl_record_header_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record_header *hdr;
	unsigned char test_vector[] = {
	    0x03,
	    0x6B, 0x65, 0x79,
	    0x05,
	    0x76, 0x61, 0x6C, 0x75, 0x65,
	};
	char *key = "key", *value = "value";
	int32_t key_len;
	int rc;

	rc = dl_record_header_new(&hdr, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(hdr != NULL);
	
	rc = dl_record_header_encode(hdr, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_header_delete(hdr);
}

/* Test 3 
 * dl_record_header_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record_header *hdr;
	unsigned char test_vector[] = {
	    0x04,
	    0x74, 0x65, 0x73, 0x74,
	    0x04,
	    0x54, 0x45, 0x53, 0x54,
	};
	char *key = "test", *value = "TEST";
	int32_t key_len;
	int rc;

	rc = dl_record_header_new(&hdr, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(hdr != NULL);
	
	rc = dl_record_header_encode(hdr, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_header_delete(hdr);
}

/* Test 4 
 * dl_record_header_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record_header *hdr;
	unsigned char test_vector[] = {
	    0x04,
	    0x74, 0x65, 0x73, 0x74,
	    0x08,
	    0x54, 0x45, 0x53, 0x54, 0x54, 0x45, 0x53, 0x54
	};
	char *key = "test", *value = "TESTTEST";
	int32_t key_len;
	int rc;

	rc = dl_record_header_new(&hdr, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(hdr != NULL);
	
	rc = dl_record_header_encode(hdr, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_header_delete(hdr);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);

	return atf_no_error();
}
