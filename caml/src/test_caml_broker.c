#include "../headers/caml_broker.h"
#include "../headers/caml_common.h"

int main(){

    struct broker_configuration* bc = (struct broker_configuration*) malloc(sizeof(struct broker_configuration));
    bc->fsync_thread_sleep_length = 5;
    bc->processor_thread_sleep_length = 5;
    bc->val = 0;

    broker_busyloop(9999, "test_partition", bc);
}
