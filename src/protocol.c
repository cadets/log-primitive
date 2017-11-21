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

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#include "protocol.h"
#include "protocol_common.h"
#include "message.h"
#include "caml_common.h"

void
build_req(struct RequestMessage* rq, enum request_type rt, int correlationId,
	char* clientId, va_list varlist)
{
	rq->APIKey = rt;
	memcpy(rq->ClientId, clientId, strlen(clientId));
	rq->CorrelationId = correlationId;

	char* topicName;

	switch (rt){
	case REQUEST_PRODUCE:
	    topicName = va_arg(varlist, char*);
	    int ms_size = va_arg(varlist, int);

	    rq->rm.produce_request.RequiredAcks = 1;
	    rq->rm.produce_request.Timeout = -1;
	    memcpy(rq->rm.produce_request.spr.TopicName.TopicName, topicName, strlen(topicName));

	    rq->rm.produce_request.spr.sspr.MessageSetSize = ms_size;
	    rq->rm.produce_request.spr.sspr.mset.NUM_ELEMS = ms_size;

	    long timestamp = time(NULL);
	    for(int i=0; i<ms_size; i++){
		char* remp = va_arg(varlist, char*);
		memcpy(rq->rm.produce_request.spr.sspr.mset.Elems[i].message.value, remp, strlen(remp));
		rq->rm.produce_request.spr.sspr.mset.Elems[i].message.timestamp = timestamp;
		rq->rm.produce_request.spr.sspr.mset.Elems[i].message.crc = get_crc(remp, strlen(remp));
	    }
	    break;
	case REQUEST_FETCH:
		topicName = va_arg(varlist, char*);
		long fetch_offset = va_arg(varlist, long);
		int maxbytes = va_arg(varlist, int);
		int minbytes = va_arg(varlist, int);
		memcpy(rq->rm.fetch_request.TopicName.TopicName, topicName,
			strlen(topicName));
		rq->rm.fetch_request.ReplicaId = -1;
		rq->rm.fetch_request.Partition = 1;
		rq->rm.fetch_request.MaxWaitTime = 100;
		rq->rm.fetch_request.MaxBytes = maxbytes;
		rq->rm.fetch_request.MinBytes = minbytes;
		rq->rm.fetch_request.FetchOffset = fetch_offset;
		break;
	case REQUEST_OFFSET:
		/* FALLTHROUGH */
	case REQUEST_OFFSET_COMMIT:
		/* FALLTHROUGH */
	case REQUEST_OFFSET_FETCH:
		/* FALLTHROUGH */
	case REQUEST_METADATA:
		/* FALLTHROUGH */
	case REQUEST_GROUP_COORDINATOR:
		/* FALLTHROUGH */
	default:
		break;
	}
}

enum response_type
match_requesttype(enum request_type rt)
{
	switch(rt){
		case REQUEST_PRODUCE:
			return RESPONSE_PRODUCE;
		case REQUEST_FETCH:
			return RESPONSE_FETCH;
		case REQUEST_OFFSET:
			return RESPONSE_OFFSET;
		case REQUEST_METADATA:
			return RESPONSE_METADATA;
		case REQUEST_OFFSET_FETCH:
			return RESPONSE_OFFSET_FETCH;
		case REQUEST_OFFSET_COMMIT:
			return RESPONSE_OFFSET_COMMIT;
		case REQUEST_GROUP_COORDINATOR:
			return RESPONSE_GROUP_COORDINATOR;
	}
	return RESPONSE_PRODUCE;
}

correlationId_t
get_corrid(char *beg)
{
	return get_int(beg, CORRELATIONID_FIELD_SIZE);
}

void
clear_fetch_responsemessage(struct FetchResponse* fr)
{
    fr->NUM_SFR = 0;
    fr->ThrottleTime = 0;
    for(int i=0; i < MAX_SUB_FETCH_SIZE; i++){
        fr->sfr[i].NUM_SSFR = 0;
        for(int j=0; j < MAX_SUB_SUB_FETCH_SIZE; j++){
            fr->sfr[i].ssfr[j].MessageSetSize= 0;
            fr->sfr[i].ssfr[j].MessageSet.NUM_ELEMS = 0;
        }
    }
}

void
clear_offset_responsemessage(struct OffsetResponse* ofr)
{
   ofr->NUM_SOR = 0;
   for(int i = 0; i < MAX_SOR; i++){
        ofr->sor[i].NUM_PARTS=0;
        for(int j = 0; j<MAX_PART_OFFSETS; j++){
            ofr->sor[i].PartitionOffsets[j].NUM_OFFSETS = 0;
        }
   }
}

void
clear_produce_responsemessage(struct ProduceResponse* pr)
{
    pr->NUM_SUB=0;
    for(int i = 0; i < MAX_SUB_SIZE; i++){
       pr->spr[i].NUM_SUBSUB = 0;
    }
}

void
clear_metadata_responsemessage(struct MetadataResponse* mr)
{
	mr->NUM_BROKERS=0;
}

void
clear_offsetfetch_responsemessage(struct OffsetFetchResponse* ofr)
{
    ofr->NUM_SUB_OFR = 0;

    for(int i = 0; i < MAX_SUB_OFR; i++){
        ofr->sofr[i].NUM_SSOFR = 0;
    }
}

void
clear_offsetcommit_responsemessage(struct OffsetCommitResponse* ocr)
{
    ocr->NUM_SUB_OCR = 0;
    for(int i = 0; i < MAX_SUB_OCR; i++){
        ocr->socr[i].NUM_SSOCR = 0;
    }
}

void
clear_group_coordinator_responsemessage(struct GroupCoordinatorResponse* gcr)
{
	gcr->CorrdinatorPort = 0;
}

void
clear_responsemessage(struct ResponseMessage* rm, enum request_type rt)
{
    switch(rt){
        case REQUEST_FETCH: clear_fetch_responsemessage(&rm->rm.fetch_response); break;
        case REQUEST_OFFSET: clear_offset_responsemessage(&rm->rm.offset_response); break;
        case REQUEST_PRODUCE: clear_produce_responsemessage(&rm->rm.produce_response); break;
        case REQUEST_METADATA: clear_metadata_responsemessage(&rm->rm.metadata_response); break;
        case REQUEST_OFFSET_FETCH: clear_offsetfetch_responsemessage(&rm->rm.offset_fetch_response); break;
        case REQUEST_OFFSET_COMMIT: clear_offsetcommit_responsemessage(&rm->rm.offset_commit_response); break;
        case REQUEST_GROUP_COORDINATOR: clear_group_coordinator_responsemessage(&rm->rm.group_coordinator_response); break;
    }
}

void clear_fetch_requestmessage(struct FetchRequest* fr){
    fr->Partition = 0;
}

void clear_offsetfetch_requestmessage(struct OffsetFetchRequest* ofr){
    ofr->Partition = 0;
}

void
clear_offset_requestmessage(struct OffsetRequest* ofr)
{
    ofr->Partition = 0;
}

void
clear_produce_requestmessage(struct ProduceRequest* pr)
{
    pr->spr.sspr.MessageSetSize = 0;
    pr->spr.sspr.mset.NUM_ELEMS = 0;
}

void
clear_metadata_requestmessage(struct MetadataRequest* mr)
{
    mr->NUM_TOPICS = 0;
}

void
clear_offsetcommit_requestmessage(struct OffsetCommitRequest* ofr)
{
    ofr->ConsumerGroupGenerationId = 0;
}

void
clear_group_coordinator_requestmessage(struct GroupCoordinatorRequest* gcr)
{
    bzero(gcr->GroupId, GROUP_ID_SIZE); 
}

void
clear_requestmessage(struct RequestMessage* rm, enum request_type rt)
{
    switch(rt){
        case REQUEST_FETCH: clear_fetch_requestmessage(&rm->rm.fetch_request); break;
        case REQUEST_OFFSET: clear_offset_requestmessage(&rm->rm.offset_request); break;
        case REQUEST_PRODUCE: clear_produce_requestmessage(&rm->rm.produce_request); break;
        case REQUEST_METADATA: clear_metadata_requestmessage(&rm->rm.metadata_request); break;
        case REQUEST_OFFSET_FETCH: clear_offsetfetch_requestmessage(&rm->rm.offset_fetch_request); break;
        case REQUEST_OFFSET_COMMIT: clear_offsetcommit_requestmessage(&rm->rm.offset_commit_request); break;
        case REQUEST_GROUP_COORDINATOR: clear_group_coordinator_requestmessage(&rm->rm.group_coordinator_request); break;
    }       
}


