#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <stdio.h>
#include <string.h>

struct yaopo_cipher_ctx
{
    uint8_t *key;
    uint8_t key_size;
    int enc;
};

static OSSL_FUNC_cipher_newctx_fn yaopo_cipher_newctx;
static OSSL_FUNC_cipher_dupctx_fn yaopo_cipher_dupctx;


static OSSL_FUNC_cipher_freectx_fn yaopo_cipher_freectx;

static void *yaopo_cipher_newctx(void *yaopo_ctx)
{
    struct yaopo_cipher_ctx* ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));

    return (void*)ctx;
}

static void *yaopo_cipher_dupctx(void *yc_ctx)
{
    struct yaopo_cipher_ctx* src_ctx = yc_ctx;
    struct yaopo_cipher_ctx* copy_ctx = NULL;
    uint8_t *key_copy = NULL;
    int error = 1;

    do {
        copy_ctx = calloc(1, sizeof(*copy_ctx));

        if (copy_ctx == NULL)
            break;

        key_copy = calloc(1, src_ctx->key_size);

        if (key_copy == NULL)
            break;

        memcpy(key_copy, src_ctx->key, src_ctx->key_size);

        //Perform the copy from src to copy
        copy_ctx->key = key_copy;
        copy_ctx->key_size = src_ctx->key_size;
        copy_ctx->enc = src_ctx->enc;

        error = 0;
    } while(0);

    if (error == 1)
    {
        if (key_copy != NULL)
        {
            free(key_copy);
            key_copy = NULL;
        }

        if (copy_ctx != NULL)
        {
            free(copy_ctx);
            copy_ctx = NULL;
        }
    }

    return copy_ctx;
}

static void yaopo_cipher_freectx(void *ctx)
{
    struct yaopo_cipher_ctx* yc_ctx = ctx;

    if (yc_ctx->key != NULL)
    {
        free(yc_ctx->key);
        yc_ctx->key = NULL;
    }

    if (yc_ctx != NULL)
    {
        free(yc_ctx);
        yc_ctx = NULL;
    }
}

typedef void (*funcptr_t)(void);

/* The cipher dispatch table */
static const OSSL_DISPATCH yaopo_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)yaopo_cipher_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)yaopo_cipher_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)yaopo_cipher_freectx },
#if 0
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)yaopo_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)yaopo_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)yaopo_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)yaopo_cipher_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)yaopo_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)yaopo_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)yaopo_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (funcptr_t)yaopo_cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)yaopo_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (funcptr_t)yaopo_cipher_settable_ctx_params },
#endif
    { 0, NULL }
};

const OSSL_ALGORITHM yaopo_ciphers[] = {
    { "yaopo_cipher:0.1", "x.author='Brissouille'",
      yaopo_cipher_functions },
    { NULL, NULL, NULL }
};
