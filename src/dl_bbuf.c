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
#include "dl_bbuf.h"
#include "dl_memory.h"

struct dl_bbuf_hdr {
	char * dlbh_data;
	dl_bbuf_flags dlbh_flags;
	int dlbh_pos;
	int dlbh_limit;
	int dlbh_capacity;
};

struct dl_bbuf {
	struct dl_bbuf_hdr dlb_hdr;
	char dlb_databuf[1];
};

const int DL_BBUF_USRFLAGMASK = DL_BBUF_AUTOEXTEND | DL_BBUF_FIXEDLEN |
    DL_BBUF_BIGENDIAN | DL_BBUF_LITTLEENDIAN;
const int DL_BBUF_MINEXTENDSIZE = 16;
const int DL_BBUF_MAXEXTENDSIZE = PAGE_SIZE;
const int DL_BBUF_MAXEXTENDINC = PAGE_SIZE;

static void dl_bbuf_assert_integrity(const char *, struct dl_bbuf *);
static int dl_bbuf_extend(struct dl_bbuf **, int);
static int dl_bbuf_extendsize(int);

static void
dl_bbuf_assert_integrity(const char *func, struct dl_bbuf *self)
{

	DL_ASSERT(self != NULL, ("%s called with NULL dl_buf instance", func)); 
	DL_ASSERT(self->dlb_hdr.dlbh_data != NULL,
	    ("%s called with unititialised of corrupt dl_buf", func)); 
	DL_ASSERT(self->dlb_hdr.dlbh_pos <= self->dlb_hdr.dlbh_capacity,
	    ("wrote past the end of the dl_buf (&d >= %d)",
	    self->dlbh_hdr.dlbh_pos, self->dlbh_hdr.dlbh_capacity)); 
}

static int
dl_bbuf_extendsize(int len)
{
	int newlen = DL_BBUF_MINEXTENDSIZE;

	while (newlen < len) {
		if (newlen < DL_BBUF_MAXEXTENDSIZE)
			newlen *= 2;
		else
			newlen += DL_BBUF_MAXEXTENDINC;
	}
	return newlen;
}

static int
dl_bbuf_extend(struct dl_bbuf **self, int addlen)
{
	struct dl_bbuf *oldbuf = *self, *newbuf;
	int newlen;

	newlen = dl_bbuf_extendsize(oldbuf->dlb_hdr.dlbh_pos + addlen);
	if (dl_duf_new(&newbuf, NULL, newlen,
	    oldbuf->dlb_hdr.dlbh_flags) == 0) {
		
		bcopy(oldbuf->dlb_databuf, newbuf->dlb_databuf,
		    oldbuf->dlb_hdr.dlbh_capacity);
		newbuf->dlb_hdr.dlbh_pos = oldbuf->dlb_hdr.dlbh_pos;
		dlog_free(oldbuf);
		*self = newbuf;
		return 0;
	} else {
		return -1;
	}
}

int
dl_bbuf_new(struct dl_bbuf **self, char *buf, int capacity, int flags)
{
	struct dl_bbuf *newbuf = *self;
	int newlen;

	DL_ASSERT(capacity >= 0,
	    ("attempt to create a dl_buf of negative length (%d)", length));
	DL_ASSERT((flags & ~DL_BBUF_USRFLAGMASK) == 0,
	    ("%s called with invalid flags", __func__));

	flags &= DL_BBUF_USRFLAGMASK;

	if (buf == NULL)
		newlen = sizeof(struct dl_bbuf) + capacity;
	else
		newlen = sizeof(struct dl_bbuf);
		flags &= DL_BBUF_EXTERNBUF;

	newbuf = *self = (struct dl_bbuf *) dlog_alloc(newlen);
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
		newbuf->dlb_hdr.dlbh_capacity = capacity;
		newbuf->dlb_hdr.dlbh_limit = capacity;
		newbuf->dlb_hdr.dlbh_pos = 0;
		return 0;
	}
	return -1;
}

int
dl_bbuf_new_auto(struct dl_bbuf **buffer)
{

	return dl_bbuf_new(buffer, NULL, DL_BBUF_MINEXTENDSIZE,
	    DL_BBUF_AUTOEXTEND);
}

int
dl_bbuf_bcat(struct dl_bbuf *self, char *source, int length)
{

	dl_bbuf_assert_integrity(__func__, self);
	if (self->dlb_hdr.dlbh_pos + length <= self->dlb_hdr.dlbh_capacity) {

		bcopy(source, &self->dlb_databuf[self->dlb_hdr.dlbh_pos],
		    length);
		self->dlb_hdr.dlbh_pos += length;
		return 0;
	} else {
		if (self->dlb_hdr.dlbh_flags & DL_BBUF_AUTOEXTEND) {
			//dl_bbuf_extend(struct dl_bbuf **self, int addlen)
			// TODO: self = dlog_realloc();
		} else {
			return -1;
		}
	}

	return 0;
}

void
dl_bbuf_clear(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	self->dlb_hdr.dlbh_pos = 0;
}

int
dl_bbuf_concat(struct dl_bbuf *self, struct dl_bbuf *source)
{
	dl_bbuf_assert_integrity(__func__, self);
	dl_bbuf_assert_integrity(__func__, source);

	if (self->dlb_hdr.dlbh_pos + source->dlb_hdr.dlbh_pos <
	    self->dlb_hdr.dlbh_capacity) {
	
		bcopy(source->dlb_databuf,
		    &self->dlb_databuf[self->dlb_hdr.dlbh_pos],
		    source->dlb_hdr.dlbh_pos);
		self->dlb_hdr.dlbh_pos += source->dlb_hdr.dlbh_pos;
		return 0;
	} else {
		return -1;
	}
	
}

char *
dl_bbuf_data(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_hdr.dlbh_data;
}

dl_bbuf_flags
dl_bbuf_get_flags(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_hdr.dlbh_flags;
}

int
dl_bbuf_flip(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	self->dlb_hdr.dlbh_limit = self->dlb_hdr.dlbh_pos;
	self->dlb_hdr.dlbh_pos = 0;
	return self->dlb_hdr.dlbh_data;
}

int
dl_bbuf_len(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_hdr.dlbh_limit;
}

int
dl_bbuf_pos(struct dl_bbuf *self)
{

	dl_bbuf_assert_integrity(__func__, self);
	return self->dlb_hdr.dlbh_pos;
}

int
dl_bbuf_get_int8(struct dl_bbuf *self, u_int8_t *value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (hdr->dlbh_pos + sizeof(u_int8_t)) <= hdr->dlbh_limit) {

		*value = hdr->dlbh_data[hdr->dlbh_pos++];
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int16(struct dl_bbuf *self, u_int16_t *value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (hdr->dlbh_pos + sizeof(u_int16_t)) <= hdr->dlbh_limit) {

		if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8)); 
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int32(struct dl_bbuf *self, u_int32_t *value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (hdr->dlbh_pos + sizeof(u_int32_t)) <= hdr->dlbh_limit) {

		if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
			*value =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0));
		} else {
			*value =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24));
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_get_int64(struct dl_bbuf *self, u_int64_t *value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int l, h;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (hdr->dlbh_pos + sizeof(u_int64_t)) <= hdr->dlbh_limit) {

		if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
			h =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0));
			l = 
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0));
			*value = (((u_int64_t) h) << 32L) |
			    (((long) l) & 0xFFFFFFFFL);
		} else {
			l =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24));
			h =
			    (((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 0) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 8) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 16) |
			    ((hdr->dlbh_data[hdr->dlbh_pos++] & 0xFF) << 24));
			*value = (((u_int64_t) h) << 32L) |
			    (((u_int64_t) l) & 0xFFFFFFFFL);
		}
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int8_at(struct dl_bbuf *self, u_int8_t value, int pos)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(u_int8_t)) >= hdr->dlbh_capacity) {

		if (self->dlb_hdr.dlbh_flags & DL_BBUF_AUTOEXTEND) {

			add_len = (int) (pos + sizeof(u_int8_t)) -
			    hdr->dlbh_capacity;
			if (dl_bbuf_extend(&self, add_len) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	hdr->dlbh_data[pos++] = value;
	return 0;
}

int
dl_bbuf_put_int8(struct dl_bbuf *self, u_int8_t value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int8_at(self, value, hdr->dlbh_pos) == 0) {

		hdr->dlbh_pos += sizeof(u_int8_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int16_at(struct dl_bbuf *self, u_int16_t value, int pos)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(u_int16_t)) >= hdr->dlbh_capacity) {

		if (self->dlb_hdr.dlbh_flags & DL_BBUF_AUTOEXTEND) {

			add_len = (int) (pos + sizeof(u_int16_t)) -
			    hdr->dlbh_capacity;
			if (dl_bbuf_extend(&self, add_len) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
	} else {
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int16(struct dl_bbuf *self, u_int16_t value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int16_at(self, value, hdr->dlbh_pos) == 0) {

		hdr->dlbh_pos += sizeof(u_int16_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int32_at(struct dl_bbuf *self, u_int32_t value, int pos)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(u_int32_t)) >= hdr->dlbh_capacity) {

		if (self->dlb_hdr.dlbh_flags & DL_BBUF_AUTOEXTEND) {

			add_len = (int) (pos + sizeof(u_int32_t)) -
			    hdr->dlbh_capacity;
			if (dl_bbuf_extend(&self, add_len) != 0)
			    return -1;
		} else {
			return -1;
		}
	}
	
	if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
		hdr->dlbh_data[pos++] = (value >> 24) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 16) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
	} else {
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 16) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 24) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int32(struct dl_bbuf *self, u_int32_t value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int32_at(self, value, hdr->dlbh_pos) == 0) {

		hdr->dlbh_pos += sizeof(u_int32_t);	
		return 0;
	}
	return -1;
}

int
dl_bbuf_put_int64_at(struct dl_bbuf *self, u_int64_t value, int pos)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (self != NULL &&
	    (int) (pos + sizeof(u_int64_t)) >= hdr->dlbh_capacity) {

		if (self->dlb_hdr.dlbh_flags & DL_BBUF_AUTOEXTEND) {

			add_len = (int) (pos + sizeof(u_int64_t)) -
			    hdr->dlbh_capacity;
			if (dl_bbuf_extend(&self, add_len) != 0)
			    return -1;
		} else {
			return -1;
		}
	}

	if (hdr->dlbh_flags & DL_BBUF_BIGENDIAN) {
		hdr->dlbh_data[pos++] = (value >> 56) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 48) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 40) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 32) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 24) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 16) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
	} else {
		hdr->dlbh_data[pos++] = (value >> 0) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 8) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 16) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 24) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 32) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 40) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 48) & 0xFF;
		hdr->dlbh_data[pos++] = (value >> 56) & 0xFF;
	}
	return 0;
}

int
dl_bbuf_put_int64(struct dl_bbuf *self, u_int64_t value)
{
	struct dl_bbuf_hdr *hdr = &self->dlb_hdr;
	int add_len;

	dl_bbuf_assert_integrity(__func__, self);
	if (dl_bbuf_put_int64_at(self, value, hdr->dlbh_pos) == 0) {

		hdr->dlbh_pos += sizeof(u_int64_t);	
		return 0;
	}
	return -1;
}

