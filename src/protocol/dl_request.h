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

#ifndef _DL_REQUEST_H
#define _DL_REQUEST_H

#include "dl_protocol.h"
#include "dl_fetch_request.h"
#include "dl_list_offset_request.h"
#include "dl_produce_request.h"

union dl_request_message {
	struct dl_produce_request dlrqmt_produce_request;
	struct dl_fetch_request dlrqmt_fetch_request;
	struct dl_offset_request dlrqmt_offset_request;
	//struct dl_metadata_request dlrqmt_metadata_request[1];
	//struct dl_offset_commit_request dlrqmt_offset_commit_request;
	//struct dl_offset_fetch_request dlrqmt_offset_fetch_request;
	//struct dl_group_coordinator_request dlrqmt_group_coordinator_request;
};

struct dl_request {
	int32_t dlrqm_size;
	int16_t dlrqm_api_key;
	int16_t dlrqm_api_version;
	int32_t dlrqm_correlation_id;
	char dlrqm_client_id[DL_MAX_CLIENT_ID];
	union dl_request_message dlrqm_message;
};

extern int dl_decode_request(struct dl_request *, char *);
extern int dl_encode_request(struct dl_request const *,
    struct dl_buffer const *);

#endif
