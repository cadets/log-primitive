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

#include "dl_index.h"
#include "dl_segment.h"
#include "dl_memory.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Test 1
 * dl_index_new() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct dl_index *idx = NULL;
	struct dl_segment *seg= NULL;
	struct sbuf *name;
	int rc;

	name = sbuf_new_auto();
	sbuf_cat(name, "topic");
	sbuf_finish(name);

	dl_make_folder(name);

	rc = dl_segment_new_default(&seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new segment");
	ATF_REQUIRE(seg != NULL);

	rc = dl_index_new(&idx, seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new index %d", rc);
	ATF_REQUIRE(idx != NULL);

	seg->dls_idx = idx;

	dl_segment_delete(seg);
	sbuf_delete(name);
	dl_del_folder(name);
}

/* Test 2
 * dl_index_update() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct dl_index *idx = NULL;
	struct dl_segment *seg= NULL;
	struct sbuf *name;
	struct dl_bbuf *buf;
	int rc;

	name = sbuf_new_auto();
	sbuf_cat(name, "topic");
	sbuf_finish(name);

	dl_make_folder(name);

	rc = dl_segment_new_default(&seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new segment");
	ATF_REQUIRE(seg != NULL);

	rc = dl_index_new(&idx, seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new index %d", rc);
	ATF_REQUIRE(idx != NULL);

	seg->dls_idx = idx;

	dl_bbuf_new_auto(&buf);
	dl_bbuf_put_int8(buf, 1);

	rc = dl_segment_insert_message(seg, buf);
	ATF_REQUIRE(rc == 0);
	dl_bbuf_delete(buf);

	dl_index_update(idx);
	ATF_REQUIRE(rc == 0);

	dl_segment_delete(seg);
	sbuf_delete(name);
	dl_del_folder(name);
}

/* Test 3
 * dl_index_update() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct dl_index *idx = NULL;
	struct dl_segment *seg= NULL;
	struct sbuf *name;
	struct dl_bbuf *buf;
	int rc;
	int32_t poffset;
	int8_t val;

	name = sbuf_new_auto();
	sbuf_cat(name, "topic");
	sbuf_finish(name);

	dl_make_folder(name);

	rc = dl_segment_new_default(&seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new segment");
	ATF_REQUIRE(seg != NULL);

	rc = dl_index_new(&idx, seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new index %d", rc);
	ATF_REQUIRE(idx != NULL);

	seg->dls_idx = idx;

	rc = dl_bbuf_new(&buf, NULL, 20, DL_BBUF_BIGENDIAN);
	dl_bbuf_put_int32(buf, 0);
	dl_bbuf_put_int32(buf, 1);
	dl_bbuf_put_int8(buf, 8);

	rc = dl_segment_insert_message(seg, buf);
	ATF_REQUIRE(rc == 0);
	dl_bbuf_delete(buf);

	dl_index_update(idx);
	
	poffset = dl_index_lookup(seg->dls_idx, 0);
	ATF_REQUIRE(poffset == 0);

	dl_segment_delete(seg);
	sbuf_delete(name);
	dl_del_folder(name);
}

/* Test 4
 * dl_index_update() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct dl_index *idx = NULL;
	struct dl_segment *seg= NULL;
	struct sbuf *name;
	struct dl_bbuf *buf;
	int rc;
	int32_t poffset;
	int8_t val;

	name = sbuf_new_auto();
	sbuf_cat(name, "topic");
	sbuf_finish(name);

	dl_make_folder(name);

	rc = dl_segment_new_default(&seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new segment");
	ATF_REQUIRE(seg != NULL);

	rc = dl_index_new(&idx, seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new index %d", rc);
	ATF_REQUIRE(idx != NULL);

	seg->dls_idx = idx;

	rc = dl_bbuf_new(&buf, NULL, 20, DL_BBUF_BIGENDIAN);
	dl_bbuf_put_int32(buf, 0);
	dl_bbuf_put_int32(buf, 1);
	dl_bbuf_put_int8(buf, 8);

	rc = dl_segment_insert_message(seg, buf);
	ATF_REQUIRE(rc == 0);

	rc = dl_segment_insert_message(seg, buf);
	ATF_REQUIRE(rc == 0);

	dl_bbuf_delete(buf);

	dl_index_update(idx);
	
	poffset = dl_index_lookup(seg->dls_idx, 0);
	ATF_REQUIRE(poffset == 0);

	poffset = dl_index_lookup(seg->dls_idx, 1);
	ATF_REQUIRE(poffset == dl_bbuf_pos(buf));

	dl_segment_delete(seg);
	sbuf_delete(name);
	dl_del_folder(name);
}

/* Test 5
 * dl_index_update() - valid params.
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct dl_index *idx = NULL;
	struct dl_segment *seg= NULL;
	struct sbuf *name;
	struct dl_bbuf *buf;
	int rc;
	int32_t size;
	int8_t val;

	name = sbuf_new_auto();
	sbuf_cat(name, "topic");
	sbuf_finish(name);

	dl_make_folder(name);

	rc = dl_segment_new_default(&seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new segment");
	ATF_REQUIRE(seg != NULL);

	rc = dl_index_new(&idx, seg, name);
	ATF_REQUIRE_MSG(rc == 0, "Failed to instantiate a new index %d", rc);
	ATF_REQUIRE(idx != NULL);

	seg->dls_idx = idx;

	rc = dl_bbuf_new(&buf, NULL, 20, DL_BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);
	dl_bbuf_put_int32(buf, 5);
	dl_bbuf_put_int8(buf, 8);

	rc = dl_segment_insert_message(seg, buf);
	ATF_REQUIRE(rc == 0);
	dl_bbuf_delete(buf);

	dl_index_update(idx);
	
	rc = dl_segment_get_message_by_offset(seg, 0, &buf);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buf != NULL);

	dl_bbuf_flip(buf);
	rc = dl_bbuf_get_int32(buf, &size);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(size == 5);

	rc = dl_bbuf_get_int8(buf, &val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(val == 8);

	dl_bbuf_delete(buf);

	dl_segment_delete(seg);
	sbuf_delete(name);
	dl_del_folder(name);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);
	ATF_TP_ADD_TC(tp, test5);

	return atf_no_error();
}
