#include <unistd.h>

#include "../headers/caml_client.h"
#include "../headers/caml_common.h"
#include "../headers/utils.h"
#include "../headers/protocol.h"


void on_ack(unsigned long correlationId){
    printf("Acknowledged message %lu\n", correlationId);
}

void on_response(struct RequestMessage *rm, struct ResponseMessage *rs){
    debug(PRIO_NORMAL, "Response was recieved with correlationId %d\n", rs->CorrelationId);

    switch(rm->APIKey){
        case REQUEST_PRODUCE:
            printf("Produced the following messages: \n");
            for(int i = 0; i < rm->rm.produce_request.spr.sspr.mset.NUM_ELEMS; i++){
               printf("\tMessage: %s\n", rm->rm.produce_request.spr.sspr.mset.Elems[i].Message.value); 
            }

            printf("Request answer: \n");
            for(int i = 0; i <rs->rm.produce_response.NUM_SUB; i++){
                for(int j=0; j < rs->rm.produce_response.spr[i].NUM_SUBSUB; j++){
                    struct SubSubProduceResponse *csspr = &rs->rm.produce_response.spr[i].sspr[j];
                    printf("Timestamp:\t%ld\n", csspr->Timestamp); 
                    printf("Offset:\t%ld\n", csspr->Offset); 
                    printf("ErrorCode:\t%d\n", csspr->ErrorCode); 
                    printf("Partition:\t%d\n", csspr->Partition); 
                }
            }
            break;
        case REQUEST_FETCH: break;
        case REQUEST_OFFSET: break;
        case REQUEST_OFFSET_COMMIT: break;
        case REQUEST_OFFSET_FETCH: break;
        case REQUEST_METADATA: break;
        case REQUEST_GROUP_COORDINATOR: break;
    }
}

void busywait(){
    while(1){
        sleep(20);
    }
}

int main(){

    struct client_configuration *cc = (struct client_configuration*) malloc(sizeof(struct client_configuration));
    cc->to_resend = 1;
    cc->resender_thread_sleep_length = 10;
    cc->request_notifier_thread_sleep_length = 3;
    cc->reconn_timeout = 5;
    cc->poll_timeout = 3000;
    cc->on_ack = on_ack;
    cc->on_response = on_response;

    client_busyloop("127.0.0.1", 9999, cc);
    int i = 0;

    char* my_client_name = "NAME";
    char* my_topic_name  = "Topic Name";
    int resend_timeout = 40;

    
    int maxbytes = 1000;
    int minbytes = 1;
    int wantoff = 0;
    
	while(i < 5){
        printf("I am inserting stuffs\n");
        send_request(0, REQUEST_PRODUCE, i, my_client_name, cc->to_resend, resend_timeout, my_topic_name, 3, "Test msg 1", "Test msg 2", "Test msg 3");
        i++;
    }

    sleep(5);

    while(1){
        printf("I am requesting stuffs\n");
        send_request(0, REQUEST_FETCH, i, my_client_name, cc->to_resend, resend_timeout, my_topic_name, wantoff, maxbytes, minbytes);
        i++;
        sleep(30);
    }
}
