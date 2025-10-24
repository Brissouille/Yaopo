#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "yaopo_err.h"

struct yaopo_ctx {
    const OSSL_CORE_HANDLE *core_handle;
    struct yaopo_err_handle *err_handle;
};

/* The yaopo functions */
static const OSSL_DISPATCH yaopo_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)yaopo_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)yaopo_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (funcptr_t)yaopo_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (funcptr_t)yaopo_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    struct yaopo_ctx *ctx = NULL;
    OSSL_DISPATCH* iterator = NULL;
    int status = 0;

    do
    {
        ctx = calloc(sizeof(*ctx), 1);

        if (ctx == NULL)
        {
            // ERROR
            status = 0;
            break;
        }

        ctx->core_handle = handle;

        //Init the error routines TODO
        ctx->err_handle = calloc(sizeof(*(ctx->err_handle)), 1);

        if (ctx->err_handle == NULL)
        {
            // ERROR
            status = 0;
            break;
        }

        for (iterator = (OSSL_DISPATCH*)in; iterator->function_id != 0; iterator++)
        {
            switch (iterator->function_id) {
                case OSSL_FUNC_CORE_NEW_ERROR:
                    ctx->err_handle->core_new_error = OSSL_FUNC_core_new_error(iterator);
                    break;
                case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
                    ctx->err_handle->core_set_error_debug = OSSL_FUNC_core_set_error_debug(iterator);
                    break;
                case OSSL_FUNC_CORE_VSET_ERROR:
                    ctx->err_handle->core_vset_error = OSSL_FUNC_core_vset_error(iterator); 
            }
        }

        // Init by the function of the provider
        *out = yaopo_functions;

        // Everything is ok
        status = 1;

    } while(0);

    // if error case, then we free the allocated variables
    if (status == 0)
    {
        if (ctx->err_handle != NULL)
        {
            free(ctx->err_handle);
            ctx->err_handle = NULL;
        }

        if (ctx != NULL)
        {
            free(ctx);
            ctx = NULL;
        }
    }

    return status;
}

