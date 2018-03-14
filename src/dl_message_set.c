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

#include <sys/time.h>
#ifdef _KERNEL
#include <sys/libkern.h>
#else
#include <zlib.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_utils.h"

static const int8_t DL_MESSAGE_MAGIC_BYTE_V0 = 0x00;
static const int8_t DL_MESSAGE_MAGIC_BYTE_V1 = 0x01;
static const int8_t DL_MESSAGE_MAGIC_BYTE = DL_MESSAGE_MAGIC_BYTE_V1;
static const int8_t DL_MESSAGE_ATTRIBUTES = 0x00;
static const int64_t DL_DEFAULT_OFFSET = 0;

#define DL_ATTRIBUTES_SIZE sizeof(int8_t)
#define DL_CRC_SIZE sizeof(int32_t)
#define DL_MAGIC_BYTE_SIZE sizeof(int8_t)
#define DL_MESSAGE_SIZE sizeof(int32_t)
#define DL_OFFSET_SIZE sizeof(int64_t)
#define DL_TIMESTAMP_SIZE sizeof(int64_t)

#ifdef _KERNEL
#define Z_NULL NULL
#define CRC32(val, data, len) crc32_calculate(val, data, len)
#else
#define CRC32(val, data, len) crc32(val, data, len)
#endif

static int dl_message_decode(struct dl_message **, struct dl_bbuf *);
static int dl_message_encode(struct dl_message const *, struct dl_bbuf *);

struct dl_message_set *
dl_message_set_new(char *key, int32_t key_len, char *value, int32_t value_len)
{
	struct dl_message_set *message_set;
	struct dl_message *message;

	message_set = (struct dl_message_set *) dlog_alloc(
	    sizeof(struct dl_message_set));
#ifdef _KERNEL
	DL_ASSERT(message_set != NULL, ("Failed allocating message set.\n"));
	{
#else
	if (message_set != NULL) {
#endif
		STAILQ_INIT(&message_set->dlms_messages);
		message_set->dlms_nmessages = 1;

		message = (struct dl_message *) dlog_alloc(
		    sizeof(struct dl_message));
#ifdef _KERNEL
		DL_ASSERT(message != NULL, ("Failed allocating message.\n"));
		{
#else
		if (message != NULL) {
#endif
			message->dlm_key = key;
			message->dlm_key_len = key_len;
			message->dlm_value = value;
			message->dlm_value_len = value_len;

			STAILQ_INSERT_HEAD(&message_set->dlms_messages,
			    message, dlm_entries);

			return message_set;
		}
		DLOGTR0(PRIO_HIGH, "Failed allocating message.\n");
		dlog_free(message_set);
		message_set = NULL;
	}
	return NULL;
}

struct dl_message_set *
dl_message_set_decode(struct dl_bbuf *source)
{
	struct dl_message *message;
	struct dl_message_set *message_set;
	int32_t msg_set_size;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Decode the MessageSetSiz . */
	DL_DECODE_MESSAGE_SET_SIZE(source, &msg_set_size);

	message_set = (struct dl_message_set *) dlog_alloc(
	    sizeof(struct dl_message_set));
#ifdef _KERNEL
	DL_ASSERT(message_set != NULL, ("Failed allocating MessageSet."));
	{
#else
	if (message_set != NULL) {
#endif
		STAILQ_INIT(&message_set->dlms_messages);

		/* Decode the MessageSet. */
		while (msg_set_size > 0) {

			/* Decode the Message. */
			if (dl_message_decode(&message, source) == 0) {
				++message_set->dlms_nmessages;

				STAILQ_INSERT_TAIL(
				    &message_set->dlms_messages, message,
				    dlm_entries);
			} else {
				// TODO: Failure decoding
			}
		}
	}
	return message_set;
}
		
static int
dl_message_decode(struct dl_message **message, struct dl_bbuf *source)
{
	struct dl_message *self;
	int32_t crc, msg_crc, size;
	int8_t attributes, magic_byte;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
	DL_ASSERT(message != NULL, ("Message cannot be NULL"));

	self = *message = (struct dl_message *) dlog_alloc(
	    sizeof(struct dl_message));
#ifdef _KERNEL
	DL_ASSERT(message != NULL, ("Allocation of dl_message failed\n"));
	{
#else
	if (self != NULL) {
#endif
		/* Decode the MessageSet Offset. */
		DL_DECODE_OFFSET(source, &self->dlm_offset);

		/* Decode the MessageSize. */
		DL_DECODE_MESSAGE_SIZE(source, &size);
		if (size > 0) { //  && size <= dl_bbuf_space(source)) {
			/* Decode and verify the CRC. */
			DL_DECODE_CRC(source, &msg_crc);

			/* Computed CRC value. */
			crc = CRC32(0L, Z_NULL, 0);
			crc = CRC32(crc, dl_bbuf_data(source),
			    dl_bbuf_len(source));
			if (crc == msg_crc) {
				/* Decode and verify the MagicByte */
				DL_DECODE_MAGIC_BYTE(source, &magic_byte);
				if (magic_byte == DL_MESSAGE_MAGIC_BYTE_V0 ||
				    magic_byte == DL_MESSAGE_MAGIC_BYTE_V1) {
					/* Decode the Attributes */
					DL_DECODE_ATTRIBUTES(source, &attributes);

					/* The MagicByte determines the MessageSet
					* format v0 or v1.xi
					*/
					if (magic_byte ==
					    DL_MESSAGE_MAGIC_BYTE) {	
						/* Decode the Timestamp */
						DL_DECODE_TIMESTAMP(source,
						    &self->dlm_timestamp);
					}

					/* Decode the Key */
					//dl_decode_bytes
					/*
					dl_decode_int32(&source[*msg_size]);
					message->dlm_key_len = dl_decode_int32(&source[*msg_size]);

					if (message->dlm_key_len != -1) {
						message->dlm_key = &source[*msg_size];
						*msg_size += message->dlm_key_len;
					} else {
						message->dlm_key = NULL;
					}
					*/

					/* Decode the Value */
					//dl_decode_bytes
					/*
					message->dlm_value_len = dl_decode_int32(&source[*msg_size]);
					
					message->dlm_value = &source[*msg_size];
					*msg_size += message->dlm_value_len;
					*/
				} else {
					// TODO
				}
			} else {
				DLOGTR2(PRIO_HIGH,
				    "Computed CRC (%d) doess't match value "
				    "recieved value (%d).\n", crc, msg_crc);
				dlog_free(message);
				message = NULL;
			}
		} else {
			DLOGTR1(PRIO_HIGH,
			    "Invalid Message size (%d)\n", size);
			dlog_free(message);
			message = NULL;
		}
	}
	return -1;
}

/**
 * N.B. MessageSets are not preceded by an int32 specifying the length unlike
 * other arrays.
 */
int
dl_message_set_encode(struct dl_message_set const *message_set,
    struct dl_bbuf *target)
{
	struct dl_message const *message;
	int size_pos, size_start_pos;

	DL_ASSERT(message_set != NULL, "MessageSet cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Placeholder for the MessageSetSize. */
	size_pos = dl_bbuf_pos(target);
	dl_bbuf_put_int32(target, -1);

	size_start_pos = dl_bbuf_pos(target);
	STAILQ_FOREACH(message, &message_set->dlms_messages, dlm_entries) {
	
		/* Encode the Message. */
		dl_message_encode(message, target);
	}

	/* Encode the MessageSetSize into the buffer. */
	dl_bbuf_put_int32_at(target, dl_bbuf_pos(target)-size_start_pos,
	    size_pos);

	return 0;
}

static int
dl_message_encode(struct dl_message const *message, struct dl_bbuf *target)
{
	unsigned long crc_value, timestamp;
	int32_t msg_size = 0;
	int size_pos, crc_pos, crc_start_pos;

	DL_ASSERT(message != NULL, "Message cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the Message Offset into the target buffer. */
	if (DL_ENCODE_OFFSET(target, DL_DEFAULT_OFFSET) != 0)
		goto err;

	/* Placeholder for the size of the encoded Message. */
	size_pos = dl_bbuf_pos(target);
	if (DL_ENCODE_MESSAGE_SIZE(target, -1) != 0)
		goto err;

	/* Placeholder for the CRC computed over the encoded Message. */
	crc_pos = dl_bbuf_pos(target);
	if (DL_ENCODE_CRC(target, -1) != 0)
		goto err;
	crc_start_pos = dl_bbuf_pos(target);
	
	/* Encode the MagicByte */
	if (DL_ENCODE_MAGIC_BYTE(target) != 0)
		goto err;
	
	/* Encode the Attributes */
	if (DL_ENCODE_ATTRIBUTES(target, 0) != 0)
		goto err;
	
	/* Encode the Timestamp */
#ifdef _KERNEL
	// TODO: In-kernel timestamp ms since epoch?
#else
	timestamp = time(NULL);
#endif
	if (DL_ENCODE_TIMESTAMP(target, timestamp) != 0)
		goto err;
	
	/* Encode the Key */
	if (dl_encode_bytes(message->dlm_key, message->dlm_key_len,
	    target) != 0)
		goto err;
	
	/* Encode the Value */
	dl_encode_bytes(message->dlm_value, message->dlm_value_len, target);

	/* Encode the MessageSize. */
	DL_ENCODE_MESSAGE_SIZE_AT(target, dl_bbuf_pos(target)-crc_pos,
		size_pos);
	
	/* Encode the CRC. */
	unsigned char *crc_data = dl_bbuf_data(target) + crc_start_pos; 
	crc_value = CRC32(0L, Z_NULL, 0);
	crc_value = CRC32(crc_value, crc_data, dl_bbuf_pos(target)-crc_start_pos);
	if (DL_ENCODE_CRC_AT(target, crc_value, crc_pos) != 0)
		goto err;
		
	return 0;
err:
	return -1;
}
