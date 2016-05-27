#include <openssl/aes.h>

typedef struct proxy_arguments {
	int in_port;
	char *keyfile;
	char *dest;
	int dest_port;
}arg_t; 

typedef struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
}ctr_state;
