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
