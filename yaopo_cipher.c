#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>

struct yaopo_cipher_ctx
{
    uint8_t *key;
    size_t key_size;
    uint8_t *iv;
    size_t iv_size;
    int enc;
};

static OSSL_FUNC_cipher_newctx_fn yaopo_cipher_newctx;
static OSSL_FUNC_cipher_dupctx_fn yaopo_cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn yaopo_cipher_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn yaopo_cipher_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn yaopo_cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn yaopo_cipher_update;
static OSSL_FUNC_cipher_final_fn yaopo_cipher_final;

static void *yaopo_cipher_newctx(void *yaopo_ctx)
{
    struct yaopo_cipher_ctx* ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));

    //Key not initialised because no value

    return (void*)ctx;
}

static void *yaopo_cipher_dupctx(void *yc_ctx)
{
    struct yaopo_cipher_ctx* src_ctx = yc_ctx;
    struct yaopo_cipher_ctx* copy_ctx = NULL;
    uint8_t *key_copy = NULL;
    uint8_t *iv_copy = NULL;
    int error = 1;

    do {
        copy_ctx = calloc(1, sizeof(*copy_ctx));

        if (copy_ctx == NULL)
            break;

        key_copy = calloc(1, src_ctx->key_size);

        if (key_copy == NULL)
            break;

        iv_copy = calloc(1, src_ctx->iv_size);

        if (iv_copy == NULL)
            break;

        memcpy(key_copy, src_ctx->key, src_ctx->key_size);
        memcpy(iv_copy, src_ctx->iv, src_ctx->iv_size);

        //Perform the copy from src to copy
        copy_ctx->key = key_copy;
        copy_ctx->key_size = src_ctx->key_size;

        copy_ctx->iv = iv_copy;
        copy_ctx->iv_size = src_ctx->iv_size;

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

        if (iv_copy != NULL)
        {
            free(iv_copy);
            iv_copy = NULL;
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

    if (yc_ctx->iv != NULL)
    {
        free(yc_ctx->iv);
        yc_ctx->iv = NULL;
    }

    if (yc_ctx != NULL)
    {
        free(yc_ctx);
        yc_ctx = NULL;
    }
}

static int yaopo_cipher_core_init(void *yc_ctx,
                                     const uint8_t *key,
                                     size_t key_size,
                                     const uint8_t *iv,
                                     size_t iv_size,
                                     const OSSL_PARAM params[])
{
    struct yaopo_cipher_ctx* yaopo_cipher_ctx = (struct yaopo_cipher_ctx*)yc_ctx;
    int status = 0;
    do {
        if (yaopo_cipher_ctx == NULL)
            break;

        if (key == NULL)
            break;

        if (iv == NULL)
            break;

        if (iv_size == 0)
            break;

        if (key_size == 0)
            break;

        // key given, the yaopo_cipher_ctx can be initialised now
        yaopo_cipher_ctx->key = calloc(1, key_size);
        memcpy(yaopo_cipher_ctx->key, key, key_size);

        yaopo_cipher_ctx->iv = calloc(1, iv_size);
        memcpy(yaopo_cipher_ctx->iv, iv, iv_size);

        status = 1;
    } while(0);

    // error 0 error, 1 success
    return status;
}

static int yaopo_cipher_encrypt_init(void *yc_ctx,
                                     const uint8_t *key,
                                     size_t key_size,
                                     const uint8_t *iv,
                                     size_t iv_size,
                                     const OSSL_PARAM params[])
{
    return yaopo_cipher_core_init(yc_ctx, key, key_size, iv, iv_size, params);
}

static int yaopo_cipher_decrypt_init(void *yc_ctx,
                                     const uint8_t *key,
                                     size_t key_size,
                                     const uint8_t *iv,
                                     size_t iv_size,
                                     const OSSL_PARAM params[])
{
    return yaopo_cipher_core_init(yc_ctx, key, key_size, iv, iv_size, params);
}

static int yaopo_cipher_update(void *yc_ctx,
                           uint8_t *out, size_t *outl, size_t outsz,
                           const uint8_t *in, size_t in_size)
{
    if (in != NULL)
        return 0;
    *out = *in;
    *outl = in_size;
    return 1;
}

static int yaopo_cipher_final(void *yc_ctx,
                          uint8_t *out, size_t *outl, size_t outsz)
{
    return 1;
}

typedef void (*funcptr_t)(void);

/* The cipher dispatch table */
static const OSSL_DISPATCH yaopo_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)yaopo_cipher_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)yaopo_cipher_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)yaopo_cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)yaopo_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)yaopo_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)yaopo_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)yaopo_cipher_final },
#if 0
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)yaopo_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)yaopo_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (funcptr_t)yaopo_cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)yaopo_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (funcptr_t)yaopo_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)yaopo_cipher_set_ctx_params },
#endif
    { 0, NULL }
};

const OSSL_ALGORITHM yaopo_ciphers[] = {
    { "yaopo_cipher_aes:0.1", "author='Brissouille'",
      yaopo_cipher_functions, "Symetric Yaopo Cipher AES functions"},
    { NULL, NULL, NULL, NULL}
};
