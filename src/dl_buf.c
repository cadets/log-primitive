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
 *
 */

#ifdef __APPLE__
#include <mach/vm_param.h>
#else
#include <sys/param.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_buf.h"
#include "dl_memory.h"

struct dl_buf_hdr {
	char * dlbh_data;
	dl_buf_flags dlbh_flags;
	int dlbh_len;
	int dlbh_capacity;
};

struct dl_buf {
	struct dl_buf_hdr dlb_hdr;
	char dlb_databuf[1];
};

const int DL_BUF_USRFLAGMASK = DL_BUF_AUTOEXTEND | DL_BUF_FIXED;
const int DL_BUF_MINEXTENDSIZE = 16;
const int DL_BUF_MAXEXTENDSIZE = PAGE_SIZE;
const int DL_BUF_MAXEXTENDINC = PAGE_SIZE;

static void assert_dl_buf_integrity(const char *, struct dl_buf *);
static int dl_buf_extend(struct dl_buf **, int);
static int dl_buf_extendsize(int);

static int
dl_buf_extendsize(int len)
{
	int newlen = DL_BUF_MINEXTENDSIZE;

	while (newlen < len) {
		if (newlen < DL_BUF_MAXEXTENDSIZE)
			newlen *= 2;
		else
			newlen += DL_BUF_MAXEXTENDINC;
	}
	return newlen;
}

static int
dl_buf_extend(struct dl_buf **self, int addlen)
{
	struct dl_buf *oldbuf = *self, *newbuf;
	int newlen;

	newlen = dl_buf_extendsize(oldbuf->dlb_hdr.dlbh_len + addlen);
	if (dl_duf_new(&newbuf, NULL, newlen,
	    oldbuf->dlb_hdr.dlbh_flags) == 0) {
		
		bcopy(oldbuf->dlb_databuf, newbuf->dlb_databuf,
		    oldbuf->dlb_hdr.dlbh_capacity);
		newbuf->dlb_hdr.dlbh_len = oldbuf->dlb_hdr.dlbh_len;
		dlog_free(oldbuf);
		*self = newbuf;
		return 0;
	} else {
		return -1;
	}
}

static void
assert_dl_buf_integrity(const char *func, struct dl_buf *self)
{
	DL_ASSERT(self != NULL, ("%s called with NULL dl_buf instance", func)); 
	DL_ASSERT(self->dlb_hdr.dlbh_data != NULL,
	    ("%s called with unititialised of corrupt dl_buf", func)); 
	DL_ASSERT(self->dlb_hdr.dlbh_len <self->dlb_hdr.dlbh_capacity,
	    ("wrote past the end of the dl_buf (&d >= %d)",
	    self->dlbh_hdr.dlbh_len, self->dlbh_hdr.dlbh_capacity)); 
}

int
dl_buf_new(struct dl_buf **self, char *buf, int length, int flags)
{
	struct dl_buf *newbuf = *self;
	int newlen;

	DL_ASSERT(length >= 0,
	    ("attempt to create a dl_buf of negative length (%d)", length));
	DL_ASSERT((flags & ~DL_BUF_USRFLAGMASK) == 0,
	    ("%s called with invalid flags", __func__));

	flags &= DL_BUF_USRFLAGMASK;

	if (buf == NULL)
		newlen = sizeof(struct dl_buf) + length;
	else
		newlen = sizeof(struct dl_buf);
		flags &= DL_BUF_EXTERNBUF;

	newbuf = *self = (struct dl_buf *) dlog_alloc(newlen);
#ifdef _
	DL_ASSERT(*self != NULL, ("Failed to allocate dl_buf.\n"));
	{
#else
	if (newbuf != NULL) {
#endif
		if (buf == NULL) {
			newbuf->dlb_hdr.dlbh_data = newbuf->dlb_databuf;
		} else {
			newbuf->dlb_hdr.dlbh_data = buf;
		}
		newbuf->dlb_hdr.dlbh_flags = flags;
		newbuf->dlb_hdr.dlbh_capacity = length;
		newbuf->dlb_hdr.dlbh_len = 0;

		return 0;
	} else {
		return -1;
	}
}

int
dl_buf_new_auto(struct dl_buf **buffer)
{

	return dl_buf_new(buffer, NULL, DL_BUF_MINEXTENDSIZE,
	    DL_BUF_AUTOEXTEND);
}

void
dl_buf_clear(struct dl_buf *self)
{

	assert_dl_buf_integrity(__func__, self);
	self->dlb_hdr.dlbh_len = 0;
}

char *
dl_buf_data(struct dl_buf *self)
{

	assert_dl_buf_integrity(__func__, self);
	return self->dlb_hdr.dlbh_data;
}

int
dl_buf_len(struct dl_buf *self)
{

	assert_dl_buf_integrity(__func__, self);
	return self->dlb_hdr.dlbh_len;
}

int
dl_buf_get_int8(struct dl_buf *self, u_int8_t *value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self != NULL && self->dlb_hdr.dlbh_len >= sizeof(u_int8_t)) {

		hdr->dlbh_len -= sizeof(u_int8_t);
		*value = (* (u_int8_t *) &hdr->dlbh_data[hdr->dlbh_len]);
		return 0;
	}
	return -1;
}

int
dl_buf_get_int16(struct dl_buf *self, u_int16_t *value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self != NULL && self->dlb_hdr.dlbh_len >= sizeof(u_int16_t)) {

		hdr->dlbh_len -= sizeof(u_int16_t);
		*value = (* (u_int16_t *) &hdr->dlbh_data[hdr->dlbh_len]);
		return 0;
	}
	return -1;
}

int
dl_buf_get_int32(struct dl_buf *self, u_int32_t *value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self != NULL && self->dlb_hdr.dlbh_len >= sizeof(u_int32_t)) {

		hdr->dlbh_len -= sizeof(u_int32_t);
		*value = (* (u_int32_t *) &hdr->dlbh_data[hdr->dlbh_len]);
		return 0;
	}
	return -1;
}

int
dl_buf_get_int64(struct dl_buf *self, u_int64_t *value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self != NULL && self->dlb_hdr.dlbh_len >= sizeof(u_int64_t)) {

		hdr->dlbh_len -= sizeof(u_int64_t);
		*value = (* (u_int64_t *) &hdr->dlbh_data[hdr->dlbh_len]);
		return 0;
	}
	return -1;
}

int
dl_buf_put_int8(struct dl_buf *self, u_int8_t value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self->dlb_hdr.dlbh_len + sizeof(u_int8_t) <
	    self->dlb_hdr.dlbh_capacity) {

		(* (u_int8_t *) &hdr->dlbh_data[hdr->dlbh_len]) = value;
		hdr->dlbh_len += sizeof(u_int8_t);
		return 0;
	} else {
		if (self->dlb_hdr.dlbh_flags & DL_BUF_AUTOEXTEND) {
			// TODO: self = dlog_realloc();
		} else {
			return -1;
		}
	}
}

int
dl_buf_put_int16(struct dl_buf *self, u_int16_t value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self->dlb_hdr.dlbh_len + sizeof(u_int16_t) <
	    self->dlb_hdr.dlbh_capacity) {

		(* (u_int16_t *) &hdr->dlbh_data[hdr->dlbh_len]) = value;
		hdr->dlbh_len += sizeof(u_int16_t);
		return 0;
	} else {
		if (self->dlb_hdr.dlbh_flags & DL_BUF_AUTOEXTEND) {
			// TODO: self = dlog_realloc();
		} else {
			return -1;
		}
	}
}

int
dl_buf_put_int32(struct dl_buf *self, u_int32_t value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self->dlb_hdr.dlbh_len + sizeof(u_int32_t) <
	    self->dlb_hdr.dlbh_capacity) {

		(* (u_int32_t *) &hdr->dlbh_data[hdr->dlbh_len]) = value;
		hdr->dlbh_len += sizeof(u_int32_t);
		return 0;
	} else {
		if (self->dlb_hdr.dlbh_flags & DL_BUF_AUTOEXTEND) {
			//dl_buf_extend(struct dl_buf **self, int addlen)
			// TODO: self = dlog_realloc();
		} else {
			return -1;
		}
	}
}

int
dl_buf_put_int64(struct dl_buf *self, u_int64_t value)
{
	struct dl_buf_hdr *hdr = &self->dlb_hdr;

	assert_dl_buf_integrity(__func__, self);
	if (self->dlb_hdr.dlbh_len + sizeof(u_int64_t) <
	    self->dlb_hdr.dlbh_capacity) {

		(* (u_int64_t *) &hdr->dlbh_data[hdr->dlbh_len]) = value;
		hdr->dlbh_len += sizeof(u_int64_t);
		return 0;
	} else {
		if (self->dlb_hdr.dlbh_flags & DL_BUF_AUTOEXTEND) {
			// TODO: self = dlog_realloc();
		} else {
			return -1;
		}
	}
}
