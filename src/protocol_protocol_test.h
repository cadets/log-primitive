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

#ifndef _PROTOCOL_PROTOCOL_TEST_H
#define _PROTOCOL_PROTOCOL_TEST_H

extern void populate_message(struct Message* inmsg);
extern int test_message(struct Message* inmsg, struct Message* outmsg);
extern void populate_messagesetelement(struct MessageSetElement* inmsg);
extern int test_messagesetelement(struct MessageSetElement* inmsg,
	struct MessageSetElement* outmsg);
extern void populate_messageset(struct MessageSet* inmsg);
extern int test_messageset(struct MessageSet* inmsg, struct MessageSet* outmsg);
extern void populate_topicname(struct TopicName* inmsg);
extern int test_topicname(struct TopicName* inmsg, struct TopicName* outmsg);
extern void populate_groupcoordinatorrequest(
	struct GroupCoordinatorRequest* inmsg);
extern int test_groupcoordinatorrequest(struct GroupCoordinatorRequest* inmsg,
	struct GroupCoordinatorRequest* outmsg);
extern void populate_metadatarequest(struct MetadataRequest* inmsg);
extern int test_metadatarequest(struct MetadataRequest* inmsg,
	struct MetadataRequest* outmsg);
extern void populate_subsubproducerequest(struct SubSubProduceRequest* inmsg);
extern int test_subsubproducerequest(struct SubSubProduceRequest* inmsg,
	struct SubSubProduceRequest* outmsg);
extern void populate_subproducerequest(struct SubProduceRequest* inmsg);
extern int test_subproducerequest(struct SubProduceRequest* inmsg,
	struct SubProduceRequest* outmsg);
extern void populate_producerequest(struct ProduceRequest* inmsg);
extern int test_producerequest(struct ProduceRequest* inmsg,
	struct ProduceRequest* outmsg);
extern void populate_fetchrequest(struct FetchRequest* inmsg);
extern int test_fetchrequest(struct FetchRequest* inmsg,
	struct FetchRequest* outmsg);
extern void populate_offsetrequest(struct OffsetRequest* inmsg);
extern int test_offsetrequest(struct OffsetRequest* inmsg,
	struct OffsetRequest* outmsg);
extern void populate_offsetcommitrequest(struct OffsetCommitRequest* inmsg);
extern int test_offsetcommitrequest(struct OffsetCommitRequest* inmsg,
	struct OffsetCommitRequest* outmsg);
extern void populate_offsetfetchrequest(struct OffsetFetchRequest* inmsg);
extern int test_offsetfetchrequest(struct OffsetFetchRequest* inmsg,
	struct OffsetFetchRequest* outmsg);
extern void populate_reqmessage(union ReqMessage* inmsg);
extern int test_reqmessage(union ReqMessage* inmsg, union ReqMessage* outmsg);
extern void populate_requestmessage(struct RequestMessage* inmsg);
extern int test_requestmessage(struct RequestMessage* inmsg,
	struct RequestMessage* outmsg);
extern void populate_broker(struct Broker* inmsg);
extern int test_broker(struct Broker* inmsg, struct Broker* outmsg);
extern void populate_replica(struct Replica* inmsg);
extern int test_replica(struct Replica* inmsg, struct Replica* outmsg);
extern void populate_isr(struct Isr* inmsg);
extern int test_isr(struct Isr* inmsg, struct Isr* outmsg);
extern void populate_partitionmetadata(struct PartitionMetadata* inmsg);
extern int test_partitionmetadata(struct PartitionMetadata* inmsg,
	struct PartitionMetadata* outmsg);
extern void populate_topicmetadata(struct TopicMetadata* inmsg);
extern int test_topicmetadata(struct TopicMetadata* inmsg,
	struct TopicMetadata* outmsg);
extern void populate_metadataresponse(struct MetadataResponse* inmsg);
extern int test_metadataresponse(struct MetadataResponse* inmsg,
	struct MetadataResponse* outmsg);
extern void populate_subsubproduceresponse(struct subSubProduceResponse* inmsg);
extern int test_subsubproduceresponse(struct subSubProduceResponse* inmsg,
	struct subSubProduceResponse* outmsg);
extern void populate_subproduceresponse(struct subProduceResponse* inmsg);
extern int test_subproduceresponse(struct subProduceResponse* inmsg,
	struct subProduceResponse* outmsg);
extern void populate_produceresponse(struct ProduceResponse* inmsg);
extern int test_produceresponse(struct ProduceResponse* inmsg,
	struct ProduceResponse* outmsg);
extern void populate_subsubfetchresponse(struct subSubFetchResponse* inmsg);
extern int test_subsubfetchresponse(struct subSubFetchResponse* inmsg,
	struct subSubFetchResponse* outmsg);
extern void populate_subfetchresponse(struct subFetchResponse* inmsg);
extern int test_subfetchresponse(struct subFetchResponse* inmsg,
	struct subFetchResponse* outmsg);
extern void populate_fetchresponse(struct FetchResponse* inmsg);
extern int test_fetchresponse(struct FetchResponse* inmsg,
	struct FetchResponse* outmsg);
extern void populate_offset(struct Offset* inmsg);
extern int test_offset(struct Offset* inmsg, struct Offset* outmsg);
extern void populate_partitionoffsets(struct PartitionOffsets* inmsg);
extern int test_partitionoffsets(struct PartitionOffsets* inmsg,
	struct PartitionOffsets* outmsg);
extern void populate_suboffsetresponse(struct subOffsetResponse* inmsg);
extern int test_suboffsetresponse(struct subOffsetResponse* inmsg,
	struct subOffsetResponse* outmsg);
extern void populate_offsetresponse(struct OffsetResponse* inmsg);
extern int test_offsetresponse(struct OffsetResponse* inmsg, struct OffsetResponse* outmsg);
extern void populate_groupcoordinatorresponse(
	struct GroupCoordinatorResponse* inmsg);
extern int test_groupcoordinatorresponse(
	struct GroupCoordinatorResponse* inmsg,
	struct GroupCoordinatorResponse* outmsg);
extern void populate_subsuboffsetcommitresponse(
	struct subSubOffsetCommitResponse* inmsg);
extern int test_subsuboffsetcommitresponse(
	struct subSubOffsetCommitResponse* inmsg,
	struct subSubOffsetCommitResponse* outmsg);
extern void populate_suboffsetcommitresponse(
	struct subOffsetCommitResponse* inmsg);
extern int test_suboffsetcommitresponse(struct subOffsetCommitResponse* inmsg,
	struct subOffsetCommitResponse* outmsg);
extern void populate_offsetcommitresponse(struct OffsetCommitResponse* inmsg);
extern int test_offsetcommitresponse(struct OffsetCommitResponse* inmsg,
	struct OffsetCommitResponse* outmsg);
extern void populate_subsuboffsetfetchresponse(
	struct subSubOffsetFetchResponse* inmsg);
extern int test_subsuboffsetfetchresponse(
	struct subSubOffsetFetchResponse* inmsg,
	struct subSubOffsetFetchResponse* outmsg);
extern void populate_suboffsetfetchresponse(
	struct subOffsetFetchResponse* inmsg);
extern int test_suboffsetfetchresponse(struct subOffsetFetchResponse* inmsg,
	struct subOffsetFetchResponse* outmsg);
extern void populate_offsetfetchresponse(struct OffsetFetchResponse* inmsg);
extern int test_offsetfetchresponse(struct OffsetFetchResponse* inmsg,
	struct OffsetFetchResponse* outmsg);
extern void populate_resmessage(union ResMessage* inmsg);
extern int test_resmessage(union ResMessage* inmsg, union ResMessage* outmsg);
extern void populate_responsemessage(struct ResponseMessage* inmsg);
extern int test_responsemessage(struct ResponseMessage* inmsg,
	struct ResponseMessage* outmsg);

#endif
