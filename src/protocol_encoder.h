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

#ifndef _PROTOCOL_ENCODER_H
#define _PROTOCOL_ENCODER_H

#include "message.h"
#include "protocol.h"
#include "protocol_common.h"

extern int MESSAGESETSIZE_FIELD_SIZE;
extern int NUM_SOR_FIELD_SIZE;
extern int NUM_PARTITIONS_FIELD_SIZE;
extern int NUM_PARTS_FIELD_SIZE;
extern int GROUP_COORDINATOR_REQUEST_SIZE_FIELD_SIZE;
extern int SSPR_SIZE_FIELD_SIZE;
extern int METADATA_SIZE_FIELD_SIZE;
extern int APIKEY_FIELD_SIZE;
extern int TOPICERRORCODE_FIELD_SIZE;
extern int REPLICAS_SIZE_FIELD_SIZE;
extern int CONSUMERGROUPGENERATIONID_FIELD_SIZE;
extern int HOST_SIZE_FIELD_SIZE;
extern int THROTTLETIME_FIELD_SIZE;
extern int NUM_SUB_OFR_FIELD_SIZE;
extern int NUM_SUBSUB_FIELD_SIZE;
extern int CORRDINATORID_FIELD_SIZE;
extern int NUM_REPLICAS_FIELD_SIZE;
extern int NUM_BROKERS_FIELD_SIZE;
extern int ATTRIBUTES_FIELD_SIZE;
extern int NUM_SFR_FIELD_SIZE;
extern int FETCHOFFSET_FIELD_SIZE;
extern int MAXBYTES_FIELD_SIZE;
extern int REPLICA_FIELD_SIZE;
extern int SOFR_SIZE_FIELD_SIZE;
extern int FETCH_RESPONSE_SIZE_FIELD_SIZE;
extern int NUM_SUB_FIELD_SIZE;
extern int APIVERSION_FIELD_SIZE;
extern int CRC_FIELD_SIZE;
extern int VALUE_SIZE_FIELD_SIZE;
extern int NUM_ISRS_FIELD_SIZE;
extern int RM_SIZE_FIELD_SIZE;
extern int CORRELATIONID_FIELD_SIZE;
extern int NUM_TOPICS_FIELD_SIZE;
extern int REPOLICAID_FIELD_SIZE;
extern int OFFSET_COMMIT_RESPONSE_SIZE_FIELD_SIZE;
extern int PARTITION_FIELD_SIZE;
extern int OFFSET_REQUEST_SIZE_FIELD_SIZE;
extern int KEY_SIZE_FIELD_SIZE;
extern int MESSAGESIZE_FIELD_SIZE;
extern int OFFSET_RESPONSE_SIZE_FIELD_SIZE;
extern int MESSAGE_SIZE_FIELD_SIZE;
extern int TOPICNAME_SIZE_FIELD_SIZE;
extern int PARTITIONID_FIELD_SIZE;
extern int REPLICAID_FIELD_SIZE;
extern int SOR_SIZE_FIELD_SIZE;
extern int OFFSET_COMMIT_REQUEST_SIZE_FIELD_SIZE;
extern int LEADER_FIELD_SIZE;
extern int OFFSET_FETCH_REQUEST_SIZE_FIELD_SIZE;
extern int PARTITIONMETADATAS_SIZE_FIELD_SIZE;
extern int TIMESTAMP_FIELD_SIZE;
extern int NUM_OFFSETS_FIELD_SIZE;
extern int ERRORCODE_FIELD_SIZE;
extern int CONSUMERID_FIELD_SIZE;
extern int BROKERS_SIZE_FIELD_SIZE;
extern int OFFSET_FIELD_SIZE;
extern int SOCR_SIZE_FIELD_SIZE;
extern int CORRDINATORPORT_FIELD_SIZE;
extern int NUM_SSOCR_FIELD_SIZE;
extern int SSOFR_SIZE_FIELD_SIZE;
extern int METADATA_RESPONSE_SIZE_FIELD_SIZE;
extern int MAXWAITTIME_FIELD_SIZE;
extern int TIMEOUT_FIELD_SIZE;
extern int TIME_FIELD_SIZE;
extern int CONSUMERGROUPID_SIZE_FIELD_SIZE;
extern int MESSAGESET_SIZE_FIELD_SIZE;
extern int ELEMS_SIZE_FIELD_SIZE;
extern int NUM_SUB_OCR_FIELD_SIZE;
extern int PARTITIONOFFSETS_SIZE_FIELD_SIZE;
extern int PRODUCE_RESPONSE_SIZE_FIELD_SIZE;
extern int SSFR_SIZE_FIELD_SIZE;
extern int PRODUCE_REQUEST_SIZE_FIELD_SIZE;
extern int SSOCR_SIZE_FIELD_SIZE;
extern int NUM_ELEMS_FIELD_SIZE;
extern int SPR_SIZE_FIELD_SIZE;
extern int CLIENTID_SIZE_FIELD_SIZE;
extern int METADATA_REQUEST_SIZE_FIELD_SIZE;
extern int NUM_SSOFR_FIELD_SIZE;
extern int MSET_SIZE_FIELD_SIZE;
extern int HIGHWAYMARKOFFSET_FIELD_SIZE;
extern int TOPICNAMES_SIZE_FIELD_SIZE;
extern int OFFSETS_SIZE_FIELD_SIZE;
extern int REQUIREDACKS_FIELD_SIZE;
extern int FETCH_REQUEST_SIZE_FIELD_SIZE;
extern int CORRDINATORHOST_SIZE_FIELD_SIZE;
extern int GROUP_COORDINATOR_RESPONSE_SIZE_FIELD_SIZE;
extern int ISR_FIELD_SIZE;
extern int SFR_SIZE_FIELD_SIZE;
extern int NODEID_FIELD_SIZE;
extern int GROUPID_SIZE_FIELD_SIZE;
extern int NUM_SSFR_FIELD_SIZE;
extern int MINBYTES_FIELD_SIZE;
extern int OFFSET_FETCH_RESPONSE_SIZE_FIELD_SIZE;
extern int PARTITIONERRORCODE_FIELD_SIZE;
extern int PORT_FIELD_SIZE;

extern int encode_message(struct Message* inp, char** st);
extern int encode_messagesetelement(struct MessageSetElement* inp, char** st);
extern int encode_messageset(struct MessageSet* inp, char** st);
extern int encode_topicname(struct TopicName* inp, char** st);
extern int encode_groupcoordinatorrequest(struct GroupCoordinatorRequest* inp,
	char** st);
extern int encode_metadatarequest(struct MetadataRequest* inp, char** st);
extern int encode_subsubproducerequest(struct SubSubProduceRequest* inp,
	char** st);
extern int encode_subproducerequest(struct SubProduceRequest* inp, char** st);
extern int encode_producerequest(struct ProduceRequest* inp, char** st);
extern int encode_fetchrequest(struct FetchRequest* inp, char** st);
extern int encode_offsetrequest(struct OffsetRequest* inp, char** st);
extern int encode_offsetcommitrequest(struct OffsetCommitRequest* inp,
	char** st);
extern int encode_offsetfetchrequest(struct OffsetFetchRequest* inp, char** st);
extern int encode_reqmessage(union ReqMessage* inp, char** st,
	enum request_type rt);
extern int encode_requestmessage(struct RequestMessage* inp, char** st);
extern int encode_broker(struct Broker* inp, char** st);
extern int encode_replica(struct Replica* inp, char** st);
extern int encode_isr(struct Isr* inp, char** st);
extern int encode_partitionmetadata(struct PartitionMetadata* inp, char** st);
extern int encode_topicmetadata(struct TopicMetadata* inp, char** st);
extern int encode_metadataresponse(struct MetadataResponse* inp, char** st);
extern int encode_subsubproduceresponse(struct SubSubProduceResponse* inp,
	char** st);
extern int encode_subproduceresponse(struct SubProduceResponse* inp, char** st);
extern int encode_produceresponse(struct ProduceResponse* inp, char** st);
extern int encode_subsubfetchresponse(struct subSubFetchResponse* inp,
	char** st);
extern int encode_subfetchresponse(struct subFetchResponse* inp, char** st);
extern int encode_fetchresponse(struct FetchResponse* inp, char** st);
extern int encode_offset(struct Offset* inp, char** st);
extern int encode_partitionoffsets(struct PartitionOffsets* inp, char** st);
extern int encode_suboffsetresponse(struct subOffsetResponse* inp, char** st);
extern int encode_offsetresponse(struct OffsetResponse* inp, char** st);
extern int encode_groupcoordinatorresponse(
	struct GroupCoordinatorResponse* inp, char** st);
extern int encode_subsuboffsetcommitresponse(
	struct subSubOffsetCommitResponse* inp, char** st);
extern int encode_suboffsetcommitresponse(struct subOffsetCommitResponse* inp,
	char** st);
extern int encode_offsetcommitresponse(struct OffsetCommitResponse* inp,
	char** st);
extern int encode_subsuboffsetfetchresponse(
	struct subSubOffsetFetchResponse* inp, char** st);
extern int encode_suboffsetfetchresponse(struct subOffsetFetchResponse* inp,
	char** st);
extern int encode_offsetfetchresponse(struct OffsetFetchResponse* inp,
	char** st);
extern int encode_resmessage(union ResMessage* inp, char** st);
extern int encode_responsemessage(struct ResponseMessage* inp, char** st,
	enum response_type rt);

#endif
