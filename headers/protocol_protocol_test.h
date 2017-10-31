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

void populate_message(struct Message* inmsg);
int test_message(struct Message* inmsg, struct Message* outmsg);
void populate_messagesetelement(struct MessageSetElement* inmsg);
int test_messagesetelement(struct MessageSetElement* inmsg, struct MessageSetElement* outmsg);
void populate_messageset(struct MessageSet* inmsg);
int test_messageset(struct MessageSet* inmsg, struct MessageSet* outmsg);
void populate_topicname(struct TopicName* inmsg);
int test_topicname(struct TopicName* inmsg, struct TopicName* outmsg);
void populate_groupcoordinatorrequest(struct GroupCoordinatorRequest* inmsg);
int test_groupcoordinatorrequest(struct GroupCoordinatorRequest* inmsg, struct GroupCoordinatorRequest* outmsg);
void populate_metadatarequest(struct MetadataRequest* inmsg);
int test_metadatarequest(struct MetadataRequest* inmsg, struct MetadataRequest* outmsg);
void populate_subsubproducerequest(struct SubSubProduceRequest* inmsg);
int test_subsubproducerequest(struct SubSubProduceRequest* inmsg, struct SubSubProduceRequest* outmsg);
void populate_subproducerequest(struct SubProduceRequest* inmsg);
int test_subproducerequest(struct SubProduceRequest* inmsg, struct SubProduceRequest* outmsg);
void populate_producerequest(struct ProduceRequest* inmsg);
int test_producerequest(struct ProduceRequest* inmsg, struct ProduceRequest* outmsg);
void populate_fetchrequest(struct FetchRequest* inmsg);
int test_fetchrequest(struct FetchRequest* inmsg, struct FetchRequest* outmsg);
void populate_offsetrequest(struct OffsetRequest* inmsg);
int test_offsetrequest(struct OffsetRequest* inmsg, struct OffsetRequest* outmsg);
void populate_offsetcommitrequest(struct OffsetCommitRequest* inmsg);
int test_offsetcommitrequest(struct OffsetCommitRequest* inmsg, struct OffsetCommitRequest* outmsg);
void populate_offsetfetchrequest(struct OffsetFetchRequest* inmsg);
int test_offsetfetchrequest(struct OffsetFetchRequest* inmsg, struct OffsetFetchRequest* outmsg);
void populate_reqmessage(union ReqMessage* inmsg);
int test_reqmessage(union ReqMessage* inmsg, union ReqMessage* outmsg);
void populate_requestmessage(struct RequestMessage* inmsg);
int test_requestmessage(struct RequestMessage* inmsg, struct RequestMessage* outmsg);
void populate_broker(struct Broker* inmsg);
int test_broker(struct Broker* inmsg, struct Broker* outmsg);
void populate_replica(struct Replica* inmsg);
int test_replica(struct Replica* inmsg, struct Replica* outmsg);
void populate_isr(struct Isr* inmsg);
int test_isr(struct Isr* inmsg, struct Isr* outmsg);
void populate_partitionmetadata(struct PartitionMetadata* inmsg);
int test_partitionmetadata(struct PartitionMetadata* inmsg, struct PartitionMetadata* outmsg);
void populate_topicmetadata(struct TopicMetadata* inmsg);
int test_topicmetadata(struct TopicMetadata* inmsg, struct TopicMetadata* outmsg);
void populate_metadataresponse(struct MetadataResponse* inmsg);
int test_metadataresponse(struct MetadataResponse* inmsg, struct MetadataResponse* outmsg);
void populate_subsubproduceresponse(struct subSubProduceResponse* inmsg);
int test_subsubproduceresponse(struct subSubProduceResponse* inmsg, struct subSubProduceResponse* outmsg);
void populate_subproduceresponse(struct subProduceResponse* inmsg);
int test_subproduceresponse(struct subProduceResponse* inmsg, struct subProduceResponse* outmsg);
void populate_produceresponse(struct ProduceResponse* inmsg);
int test_produceresponse(struct ProduceResponse* inmsg, struct ProduceResponse* outmsg);
void populate_subsubfetchresponse(struct subSubFetchResponse* inmsg);
int test_subsubfetchresponse(struct subSubFetchResponse* inmsg, struct subSubFetchResponse* outmsg);
void populate_subfetchresponse(struct subFetchResponse* inmsg);
int test_subfetchresponse(struct subFetchResponse* inmsg, struct subFetchResponse* outmsg);
void populate_fetchresponse(struct FetchResponse* inmsg);
int test_fetchresponse(struct FetchResponse* inmsg, struct FetchResponse* outmsg);
void populate_offset(struct Offset* inmsg);
int test_offset(struct Offset* inmsg, struct Offset* outmsg);
void populate_partitionoffsets(struct PartitionOffsets* inmsg);
int test_partitionoffsets(struct PartitionOffsets* inmsg, struct PartitionOffsets* outmsg);
void populate_suboffsetresponse(struct subOffsetResponse* inmsg);
int test_suboffsetresponse(struct subOffsetResponse* inmsg, struct subOffsetResponse* outmsg);
void populate_offsetresponse(struct OffsetResponse* inmsg);
int test_offsetresponse(struct OffsetResponse* inmsg, struct OffsetResponse* outmsg);
void populate_groupcoordinatorresponse(struct GroupCoordinatorResponse* inmsg);
int test_groupcoordinatorresponse(struct GroupCoordinatorResponse* inmsg, struct GroupCoordinatorResponse* outmsg);
void populate_subsuboffsetcommitresponse(struct subSubOffsetCommitResponse* inmsg);
int test_subsuboffsetcommitresponse(struct subSubOffsetCommitResponse* inmsg, struct subSubOffsetCommitResponse* outmsg);
void populate_suboffsetcommitresponse(struct subOffsetCommitResponse* inmsg);
int test_suboffsetcommitresponse(struct subOffsetCommitResponse* inmsg, struct subOffsetCommitResponse* outmsg);
void populate_offsetcommitresponse(struct OffsetCommitResponse* inmsg);
int test_offsetcommitresponse(struct OffsetCommitResponse* inmsg, struct OffsetCommitResponse* outmsg);
void populate_subsuboffsetfetchresponse(struct subSubOffsetFetchResponse* inmsg);
int test_subsuboffsetfetchresponse(struct subSubOffsetFetchResponse* inmsg, struct subSubOffsetFetchResponse* outmsg);
void populate_suboffsetfetchresponse(struct subOffsetFetchResponse* inmsg);
int test_suboffsetfetchresponse(struct subOffsetFetchResponse* inmsg, struct subOffsetFetchResponse* outmsg);
void populate_offsetfetchresponse(struct OffsetFetchResponse* inmsg);
int test_offsetfetchresponse(struct OffsetFetchResponse* inmsg, struct OffsetFetchResponse* outmsg);
void populate_resmessage(union ResMessage* inmsg);
int test_resmessage(union ResMessage* inmsg, union ResMessage* outmsg);
void populate_responsemessage(struct ResponseMessage* inmsg);
int test_responsemessage(struct ResponseMessage* inmsg, struct ResponseMessage* outmsg);
