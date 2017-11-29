/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DL_PROTOCOL_COMMON_H
#define _DL_PROTOCOL_COMMON_H

#include "dl_common.h"
#include "dl_protocol.h"

#define MESSAGE_HOLDER_SIZE 1500

static int MESSAGESETSIZE_FIELD_SIZE= 12;
static int NUM_SOR_FIELD_SIZE= 12;
static int NUM_PARTITIONS_FIELD_SIZE= 12;
static int NUM_PARTS_FIELD_SIZE= 12;
static int GROUP_COORDINATOR_REQUEST_SIZE_FIELD_SIZE= 4;
static int SSPR_SIZE_FIELD_SIZE= 4;
static int METADATA_SIZE_FIELD_SIZE= 4;
static int APIKEY_FIELD_SIZE= 12;
static int TOPICERRORCODE_FIELD_SIZE= 12;
static int REPLICAS_SIZE_FIELD_SIZE= 4;
static int CONSUMERGROUPGENERATIONID_FIELD_SIZE= 12;
static int HOST_SIZE_FIELD_SIZE= 4;
static int THROTTLETIME_FIELD_SIZE= 12;
static int NUM_SUB_OFR_FIELD_SIZE= 12;
static int NUM_SUBSUB_FIELD_SIZE= 12;
static int CORRDINATORID_FIELD_SIZE= 12;
static int NUM_REPLICAS_FIELD_SIZE= 12;
static int NUM_BROKERS_FIELD_SIZE= 12;
static int ATTRIBUTES_FIELD_SIZE= 12;
static int NUM_SFR_FIELD_SIZE= 12;
static int FETCHOFFSET_FIELD_SIZE= 16;
static int MAXBYTES_FIELD_SIZE= 12;
static int REPLICA_FIELD_SIZE= 12;
static int SOFR_SIZE_FIELD_SIZE= 4;
static int FETCH_RESPONSE_SIZE_FIELD_SIZE= 4;
static int NUM_SUB_FIELD_SIZE= 12;
static int APIVERSION_FIELD_SIZE= 12;
static int CRC_FIELD_SIZE= 16;
static int VALUE_SIZE_FIELD_SIZE= 4;
static int NUM_ISRS_FIELD_SIZE= 12;
static int RM_SIZE_FIELD_SIZE= 4;
static int CORRELATIONID_FIELD_SIZE= 12;
static int NUM_TOPICS_FIELD_SIZE= 12;
static int REPOLICAID_FIELD_SIZE= 12;
static int OFFSET_COMMIT_RESPONSE_SIZE_FIELD_SIZE= 4;
static int PARTITION_FIELD_SIZE= 12;
static int OFFSET_REQUEST_SIZE_FIELD_SIZE= 4;
static int KEY_SIZE_FIELD_SIZE= 4;
static int MESSAGESIZE_FIELD_SIZE= 12;
static int OFFSET_RESPONSE_SIZE_FIELD_SIZE= 4;
static int MESSAGE_SIZE_FIELD_SIZE= 4;
static int TOPICNAME_SIZE_FIELD_SIZE= 4;
static int PARTITIONID_FIELD_SIZE= 12;
static int REPLICAID_FIELD_SIZE= 12;
static int SOR_SIZE_FIELD_SIZE= 4;
static int OFFSET_COMMIT_REQUEST_SIZE_FIELD_SIZE= 4;
static int LEADER_FIELD_SIZE= 12;
static int OFFSET_FETCH_REQUEST_SIZE_FIELD_SIZE= 4;
static int PARTITIONMETADATAS_SIZE_FIELD_SIZE= 4;
static int TIMESTAMP_FIELD_SIZE= 16;
static int NUM_OFFSETS_FIELD_SIZE= 12;
static int ERRORCODE_FIELD_SIZE= 12;
static int CONSUMERID_FIELD_SIZE= 12;
static int BROKERS_SIZE_FIELD_SIZE= 4;
static int OFFSET_FIELD_SIZE= 16;
static int SOCR_SIZE_FIELD_SIZE= 4;
static int CORRDINATORPORT_FIELD_SIZE= 12;
static int NUM_SSOCR_FIELD_SIZE= 12;
static int SSOFR_SIZE_FIELD_SIZE= 4;
static int METADATA_RESPONSE_SIZE_FIELD_SIZE= 4;
static int MAXWAITTIME_FIELD_SIZE= 12;
static int TIMEOUT_FIELD_SIZE= 12;
static int TIME_FIELD_SIZE= 16;
static int CONSUMERGROUPID_SIZE_FIELD_SIZE= 4;
static int MESSAGESET_SIZE_FIELD_SIZE= 4;
static int ELEMS_SIZE_FIELD_SIZE= 4;
static int NUM_SUB_OCR_FIELD_SIZE= 12;
static int PARTITIONOFFSETS_SIZE_FIELD_SIZE= 4;
static int PRODUCE_RESPONSE_SIZE_FIELD_SIZE= 4;
static int SSFR_SIZE_FIELD_SIZE= 4;
static int PRODUCE_REQUEST_SIZE_FIELD_SIZE= 4;
static int SSOCR_SIZE_FIELD_SIZE= 4;
static int NUM_ELEMS_FIELD_SIZE= 12;
static int SPR_SIZE_FIELD_SIZE= 4;
static int CLIENTID_SIZE_FIELD_SIZE= 4;
static int METADATA_REQUEST_SIZE_FIELD_SIZE= 4;
static int NUM_SSOFR_FIELD_SIZE= 12;
static int MSET_SIZE_FIELD_SIZE= 4;
static int HIGHWAYMARKOFFSET_FIELD_SIZE= 16;
static int TOPICNAMES_SIZE_FIELD_SIZE= 4;
static int OFFSETS_SIZE_FIELD_SIZE= 4;
static int REQUIREDACKS_FIELD_SIZE= 12;
static int FETCH_REQUEST_SIZE_FIELD_SIZE= 4;
static int CORRDINATORHOST_SIZE_FIELD_SIZE= 4;
static int GROUP_COORDINATOR_RESPONSE_SIZE_FIELD_SIZE= 4;
static int ISR_FIELD_SIZE= 12;
static int SFR_SIZE_FIELD_SIZE= 4;
static int NODEID_FIELD_SIZE= 12;
static int GROUPID_SIZE_FIELD_SIZE= 4;
static int NUM_SSFR_FIELD_SIZE= 12;
static int MINBYTES_FIELD_SIZE= 12;
static int OFFSET_FETCH_RESPONSE_SIZE_FIELD_SIZE= 4;
static int PARTITIONERRORCODE_FIELD_SIZE= 12;
static int PORT_FIELD_SIZE= 12;

struct message_holder {
	char buf[MESSAGE_HOLDER_SIZE];
	int fd;
};

extern correlationId_t get_corrid(char *);
extern void build_req(struct request_message *, enum request_type,
	int, char *, va_list);

#endif
