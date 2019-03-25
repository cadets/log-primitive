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
#include <zlib.h>

#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_record.h"
#include "dl_record_batch.h"
#include "dl_protocol.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1 
 * dl_record_batch_new() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_record_batch *batch;
	int rc;

	rc = dl_record_batch_new(&batch);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(batch != NULL);

	dl_record_batch_delete(batch);
}

/* Test 2
 * dl_record_batch_encode() - valid params. 
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_bbuf *buffer;
	struct dl_record *record;
	struct dl_record_batch *batch;
	char *key = "key", *value = "value";
	//zstream stream;
	int rc;
	unsigned char test_vector[] = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* BaseOffset */
    	    0x00, 0x00, 0x00, 0x5C, /* Length */
	    0x00, 0x00, 0x00, 0x00, /* PartitionLeaderEpoch */
	    0x02, /* Magic */
	    0x00, 0x00, 0x00, 0x00, /* CRC */
	    0x01, /* Attributes */
	    0x00, 0x00, 0x00, 0x01, /* LastOffsetDelta */
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x01,
	};
	unsigned char test_record[] = {
	    0x03,
	    0x6B, 0x65, 0x79,
	    0x05,
	    0x76, 0x61, 0x6C, 0x75, 0x65,
	    0xFF, 0xFF, 0xFF, 0xFF
	};
	
	rc = dl_record_batch_new(&batch);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(batch != NULL);

	rc = dl_record_new(&record, key, value, strlen(value));
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(record != NULL);

	rc = dl_record_batch_add_record(batch, record);
	ATF_REQUIRE(rc == 0);

	rc = dl_record_batch_encode(batch, &buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	//ATF_REQUIRE(dl_bbuf_pos(buffer) == sizeof(test_vector));

	/* Compress the record */
	//stream.zalloc = Z_NULL;
	//stream.zfree= Z_NULL;
	//stream.opaque = Z_NULL;
	//rc = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
	//compress();

	unsigned char *data = dl_bbuf_data(buffer);
	for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		printf("%02X == %02X\n", data[i], test_vector[i]);
		//ATF_REQUIRE(data[i] == test_vector[i]);
	}

	dl_bbuf_delete(buffer);
	dl_record_delete(record);
	dl_record_batch_delete(batch);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);

	return atf_no_error();
}
