#include <stdio.h>
#include <string.h>

#include "../headers/protocol.h"
#include "../headers/protocol_common.h"
#include "../headers/protocol_parser.h"
#include "../headers/utils.h"
#include "../headers/doubly_linked_list.h"

int main(){

    int nums = 10;
    DLL* test_dll = allocate_dlls_per_num_processors(1, nums);
    preallocate_with(test_dll, 1, nums, sizeof(int)); 


    DLLNode* krya[nums];

    for(int i = 0; i < 4; i++){
        int* ii = (int*) malloc(sizeof(int));
        memcpy(ii, &i, sizeof(int));

        krya[i] = borrow(test_dll);
        krya[i]->val = ii;
        print_dll(test_dll); 
    }

/*    for(int i = 0; i < 4; i++){
        int* ii = (int*) malloc(sizeof(int));
        memcpy(ii, &i, sizeof(int));

        krya[i] = borrow(test_dll);
        krya[i]->val = ii;
    }
*/

    returnObj(test_dll, krya[2]);
    print_dll(test_dll); 
    returnObj(test_dll, krya[3]);
    print_dll(test_dll); 
    returnObj(test_dll, krya[0]);
    print_dll(test_dll); 
    returnObj(test_dll, krya[1]);
    print_dll(test_dll); 
}
