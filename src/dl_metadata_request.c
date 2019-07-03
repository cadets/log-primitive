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
 * 2. Redistributions in binary form must relist_offset the above copyright
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

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_new.h"
#include "dl_metadata_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

struct dl_metadata_request {
	struct dl_request dlmr_super;
	struct sbuf *dlmr_topic;
	bool dlmr_auto_create;
};

static int dl_metadata_request_ctor(void *, va_list * app); 
static void dl_metadata_request_dtor(void *);
static void dl_metadata_request_tostring(void *);
static int dl_metadata_request_encode(void *, struct dl_bbuf **);
static int dl_metadata_request_encode_into(void *, struct dl_bbuf *);

extern const void *DL_REQUEST;

static const struct dl_request_class TYPE = {
	{
		sizeof(struct dl_metadata_request),
		dl_metadata_request_ctor,
		dl_metadata_request_dtor,
		dl_metadata_request_tostring
	},
	dl_metadata_request_encode,
	dl_metadata_request_encode_into
};

static const void *DL_METADATA_REQUEST = &TYPE;

#define DL_ENCODE_TOPIC_NAME(target, source) dl_encode_string(target, source)
#define DL_ENCODE_AUTO_CREATE(target, source) dl_bbuf_put_int8(target, source)

static inline void
assert_integrity(struct dl_metadata_request const * const self)
{

	DL_ASSERT(self != NULL, ("MetadataRequest instance cannot be NULL"));
	DL_ASSERT(self->dlmr_topic != NULL, ("MetadataRequest topic name cannot be NULL"));
}

static int
dl_metadata_request_ctor(void *_self, va_list *ap)
{
	struct dl_metadata_request *self = (struct dl_metadata_request *) _self;
	struct sbuf *topic;

	DL_ASSERT(self != NULL, ("MetadataRequest cannot be NULL"));

	/* Initialize the Request superclass */
	if (((const struct dl_class *) DL_REQUEST)->dl_ctor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_ctor(self, ap);

	/* Take a defensive copy of the topic name. */
	topic = va_arg(*ap, struct sbuf *);

	self->dlmr_topic = sbuf_new_auto();
	sbuf_cat(self->dlmr_topic, sbuf_data(topic));
	sbuf_finish(self->dlmr_topic);

	/* Auto create topic flag */
	self->dlmr_auto_create = va_arg(*ap, int);

	return 0;
}

static void 
dl_metadata_request_dtor(void *_self)
{
	struct dl_metadata_request *self = (struct dl_metadata_request *) _self;

	DL_ASSERT(self != NULL, ("MetadataRequest cannot be NULL"));

	/* Destroy the Request super class */
	if (((const struct dl_class *) DL_REQUEST)->dl_dtor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_dtor(self);

	/* Destroy the sbuf holding the topic name */	
	sbuf_delete(self->dlmr_topic);
}

static void 
dl_metadata_request_tostring(void *super)
{
	struct dl_metadata_request *self = (struct dl_metadata_request *) super;

	DL_ASSERT(self != NULL, ("MetadataRequest cannot be NULL"));
	DLOGTR2(PRIO_LOW, "MetadataRequest: [%s] auto_create=%s\n",
	    sbuf_data(self->dlmr_topic), self->dlmr_auto_create ? "true" : "false");
}

/**
 * MetadataRequest constructor. 
 */
int
dl_metadata_request_new(struct dl_metadata_request **self, const int32_t correlation_id,
    struct sbuf *client, struct sbuf *topic, bool create)
{
	
	return dl_new((void **) self, DL_METADATA_REQUEST, DL_METADATA_API_KEY,
	    correlation_id, client, topic, create);
}

/**
 * MetadataRequest destructor. 
 */
void
dl_metadata_request_delete(struct dl_metadata_request *self)
{

	assert_integrity(self);
	dl_delete(self);
}

/**
 * Decode the MetadataRequest.
 *
 * MetadataRequest = [topics]
 * 	topics => String
 */
int
dl_metadata_request_decode(struct dl_metadata_request **self,
    struct dl_bbuf * const source)
{


	/* TODO: implement decode */
	return -1;
}

/**
 * Encode the MetadataRequest.
 *
 * MetadataRequest = [topics]
 * 	topics => String
 */
static int
//dl_metadata_request_encode(struct dl_request const *self, struct dl_bbuf **target)
dl_metadata_request_encode(void *self, struct dl_bbuf **target)
{
	int rc;

	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Allocate and initialise a buffer to encode the response.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	rc = dl_bbuf_new(target, NULL, 1024,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	DL_ASSERT(rc == 0, ("Allocating autoextending buffer cannot fail."));
        if (rc == 0) {

		return dl_metadata_request_encode_into(self, *target);
	}

	DLOGTR0(PRIO_HIGH, "Failed encoding MetadataRequest\n");
	return -1;
}

/**
 * Encode the MetadataRequest.
 *
 * MetadataRequest = [topics]
 * 	topics => String
 */
static int
dl_metadata_request_encode_into(void *_self,
    struct dl_bbuf *target)
{
	struct dl_metadata_request const *self = (struct dl_metadata_request *) _self;
	int rc = 0;

	assert_integrity(self);
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the [topic_data] array */
	rc |= dl_bbuf_put_int32(target, 1);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the Request TopicName into the buffer */
	rc |= DL_ENCODE_TOPIC_NAME(target, self->dlmr_topic);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the allow_auto_topic_creation field */
	rc |= DL_ENCODE_AUTO_CREATE(target, self->dlmr_auto_create);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding MetadataRequest.\n");
	return -1;
}

struct sbuf *
dl_metadata_request_get_topic(struct dl_metadata_request *self)
{

	assert_integrity(self);
	return self->dlmr_topic;
}	

bool
dl_metadata_request_get_auto_create(struct dl_metadata_request *self)
{

	assert_integrity(self);
	return self->dlmr_auto_create;
}	
