#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

#include "yaopo_err.h"
#include "tee_interface.h"

extern const OSSL_ALGORITHM yaopo_ciphers[];

struct yaopo_ctx {
    const OSSL_CORE_HANDLE *core_handle;
    struct yaopo_err_handle *err_handle;
    struct tee_ctx *tee_ctx;
};

typedef void (*funcptr_t)(void);

static const OSSL_ALGORITHM* yaopo_operation(void *ctx,
                                             int operation_id,
                                             int *no_cache)
{
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return yaopo_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM reason_strings[] = {{ 1, "Unknown Error" },
                                           { 0, NULL }
};

static const OSSL_ITEM* yaopo_get_reason_strings(void *ctx)
{
    return reason_strings;
}

static void yaopo_teardown(void *ctx)
{
    free(ctx);
    ctx = NULL;
}

static const OSSL_PARAM yaopo_param[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *yaopo_gettable_params(const OSSL_PROVIDER *prov)
{
    return OSSL_PARAM_dup(yaopo_param);
}

#define BUILDINFO "test"
#define AUTHOR "Brissouille"
#define STATUS 1
#define VERSION "0.1"

static int yaopo_get_params(void *provctx, OSSL_PARAM params[])
{
    const char *src = NULL;
    size_t len = 0;

    // params can be NULL
    if (params == NULL)
        return 1;

    for (OSSL_PARAM *p = params; p != NULL && p->key != NULL; p++) {

        if (strcmp(p->key, OSSL_PROV_PARAM_BUILDINFO) == 0)
        {
            OSSL_PARAM_set_utf8_ptr(p, BUILDINFO);
        }
        else if (strcmp(p->key, OSSL_PROV_PARAM_NAME) == 0)
        {
            OSSL_PARAM_set_utf8_ptr(p, AUTHOR);
        }
        else if (strcmp(p->key, OSSL_PROV_PARAM_STATUS) == 0)
        {
            OSSL_PARAM_set_int(p, STATUS);
        }
        else if (strcmp(p->key, OSSL_PROV_PARAM_VERSION) == 0)
        {
            OSSL_PARAM_set_utf8_ptr(p, VERSION);
        }
        else
            continue;
    }

    return 1;
}

/* The yaopo functions */
static const OSSL_DISPATCH yaopo_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)yaopo_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (funcptr_t)yaopo_get_reason_strings },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)yaopo_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (funcptr_t)yaopo_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (funcptr_t)yaopo_get_params },
    {0, NULL }
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

        if (out == NULL)
        {
            status = 0;
            break;
        }
        // Init by the functions of the provider
        *out = yaopo_functions;

        if (provctx == NULL)
        {
            status = 0;
            break;
        }
        *provctx = ctx;

        // Everything is ok
        status = 1;

    } while(0);

    // if error case, then we free the allocated variables
    if (status == 0)
    {
        if (ctx != NULL)
        {
            yaopo_error_free(ctx->err_handle);
            ctx->err_handle = NULL;

            free(ctx);
            ctx = NULL;
        }
    }

    return status;
}

