#ifndef TEE_INTERFACE_H

#include "inttypes.h"

#define TEE_INTERFACE_H

#define TEE_SESSION_MAX 8

struct tee_ctx
{
    //TODO
    const char* name;
    void* context;
    void* session;
    void* destination;
    uint32_t connectionMethod;
    const void* connectionData;
    void* operation;
    uint32_t* returnOrigin;
    uint32_t commandID;
};

int tee_init(struct tee_ctx* tee_ctx);

void tee_free(struct tee_ctx* tee_ctx);


#endif // TEE_INTERFACE_H
