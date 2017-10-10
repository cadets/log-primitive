#include "../headers/caml_common.h"

void print_configuration(struct broker_configuration* bc){
    printf("Fsync thread sleep len:\t%d\nProc thread sleep len:\t%d\nVal:\t%d\n", bc->fsync_thread_sleep_length, bc->processor_thread_sleep_length, bc->val);
}
