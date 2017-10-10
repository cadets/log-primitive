
#include <stdio.h>
#include <assert.h>
#include <strings.h>

#include <string.h>
#include <time.h>

#include "../headers/caml_common.h"
#include "../headers/protocol_common.h"
#include "../headers/protocol.h"
#include "../headers/protocol_parser.h"
#include "../headers/protocol_encoder.h"
#include "../headers/utils.h"

unsigned short PRIO_LOG = PRIO_HIGH; 
extern int MTU;

void gen_random_string(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}


int main(){
    
    struct Message inmsg, outmsg;

    char* out = (char*) malloc(sizeof(char) * MTU);
	gen_random_string(inmsg.key, 10);
	gen_random_string(inmsg.value, 10);

    encode_message(&inmsg, &out);

    parse_message(&outmsg, out);

    assert(inmsg.CRC == outmsg.CRC);
    assert(inmsg.Attributes == outmsg.Attributes);

    assert(strcmp(inmsg.key, outmsg.key) == 0);
    assert(strcmp(inmsg.value, outmsg.value) == 0);

    return 1;
}
