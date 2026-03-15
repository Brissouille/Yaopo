#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <stdio.h>

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

static void *yaopo_cipher_dupctx(void *yaopo_ctx)
{
    printf("[%s %d]\n", __func__, __LINE__);
}

static void yaopo_cipher_freectx(void *yaopo_ctx)
{
    struct yaopo_cipher_ctx* ctx = yaopo_ctx;

    free(ctx);
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
