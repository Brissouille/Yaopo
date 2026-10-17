#include "tee_interface.h"
#include "stdlib.h"

struct tee_ctx
{
    void* context;
    struct {
        void* session;
        void* operation;
        uint32_t commandID;
        uint32_t* returnOrigin;
    } optee_ctx[TEE_SESSION_MAX];
};

#if 0
TEEC_Result TEEC_InitializeContext(
    const char* name, -> NULL
    TEEC_Context* context)
#endif
int tee_init(struct tee_ctx** tee_ctx)
{
    int status = 0;
    struct tee_ctx* tee_ctx_tmp = NULL;
    TEEC_Result res;
    TEEC_Context* context_tmp = NULL;

    // Allocate TEE_SESSION_MAX in the same time
    tee_ctx_tmp = calloc(1, sizeof(*tee_ctx_tmp));

    if (tee_ctx_tmp == NULL)
        return status;

    context_tmp = calloc(1, sizeof(TEEC_Context));

    if (context_tmp == NULL)
        return status;

    tee_ctx_tmp->context = (void*)context_tmp;

    res = TEEC_InitializeContext("MYSECURE_APP", (TEEC_Context*)tee_ctx_tmp->context);

    //*tee_ctx = tee_ctx_tmp;
    status = 1;

    return status;
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
#endif
int tee_open_session(struct tee_ctx* tee_ctx)
{
    // Init all the sessions
}

#if 0
void TEEC_CloseSession (
    TEEC_Session* session)
#endif
int tee_close_session(struct tee_ctx* tee_ctx)
{
    // Close and free all the sessions
}

#if 0
TEEC_Result TEEC_InvokeCommand(
    TEEC_Session* session,
    uint32_t commandID,
    TEEC_Operation* operation,
    uint32_t* returnOrigin)
#endif
int tee_command(struct tee_ctx* tee_ctx, uint32_t commandID, void* parameters)
{
}

int tee_init_parameters(void* parameters)
{
}
