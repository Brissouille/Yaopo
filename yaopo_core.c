#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <string.h>

#include "yaopo_err.h"

struct yaopo_ctx {
    const OSSL_CORE_HANDLE *core_handle;
    struct yaopo_err_handle *err_handle;
};

typedef void (*funcptr_t)(void);

static const OSSL_ALGORITHM* yaopo_operation(void *ctx,
                                             int operation_id,
                                             int *no_cache)
{
}

static const OSSL_ITEM* yaopo_get_reason_strings(void *ctx)
{
}

static void yaopo_teardown(void *ctx)
{
    free(ctx);
}

static int yaopo_get_params(OSSL_PARAM params[])
{
    for (OSSL_PARAM *p = params; p->key != NULL; p++)
    {
        if (strcmp(p->key, "author") == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* The yaopo functions */
static const OSSL_DISPATCH yaopo_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)yaopo_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)yaopo_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (funcptr_t)yaopo_get_reason_strings },
    //{ OSSL_FUNC_PROVIDER_GET_PARAMS, (funcptr_t)yaopo_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    struct yaopo_ctx *ctx = NULL;
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

        // Init the error handle with allocation
        status = yaopo_error_init(&(ctx->err_handle), in);

        if (status == 0)
        {
            break;
        }

        // Init by the functions of the provider
        *out = yaopo_functions;

        // Everything is ok
        status = 1;

    } while(0);

    // if error case, then we free the allocated variables
    if (status == 0)
    {
        yaopo_error_free(ctx->err_handle);
        ctx->err_handle = NULL;

        if (ctx != NULL)
        {
            free(ctx);
            ctx = NULL;
        }
    }

    return status;
}

