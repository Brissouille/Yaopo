#include "tee_interface.h"

#if 0
TEEC_Result TEEC_InitializeContext(
    const char* name,
    TEEC_Context* context)
#endif
int tee_init(struct tee_ctx* tee_ctx)
{
    int status = 1;

    return 1;
}

#if 0
void TEEC_FinalizeContext(
    TEEC_Context* context)
#endif
void tee_free(struct tee_ctx* tee_ctx)
{
}

#if 0
TEEC_Result TEEC_OpenSession (
    TEEC_Context* context,
    TEEC_Session* session,
    const TEEC_UUID* destination,
    uint32_t connectionMethod,
    const void* connectionData,
    TEEC_Operation* operation,
    uint32_t* returnOrigin)

void TEEC_CloseSession (
    TEEC_Session* session)

TEEC_Result TEEC_InvokeCommand(
    TEEC_Session* session,
    uint32_t commandID,
    TEEC_Operation* operation,
    uint32_t* returnOrigin)
#endif
