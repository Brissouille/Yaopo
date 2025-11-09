#include "yaopo_err.h"

int yaopo_error_init(struct yaopo_err_handle** err_handle, const OSSL_DISPATCH *in)
{
    OSSL_DISPATCH* iterator = NULL;
    struct yaopo_err_handle *err_handle_tmp = NULL;

    if(err_handle == NULL && *err_handle != NULL)
    {
        // there is a problem
        return 0;
    }

    //Init the error routines
    err_handle_tmp = calloc(sizeof(*err_handle_tmp), 1);

    if (err_handle_tmp == NULL)
    {
        // ERROR
        return 0;
    }

    for (iterator = (OSSL_DISPATCH*)in; iterator->function_id != 0; iterator++)
    {
        switch (iterator->function_id) {
            case OSSL_FUNC_CORE_NEW_ERROR:
                err_handle_tmp->core_new_error = OSSL_FUNC_core_new_error(iterator);
                break;
            case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
                err_handle_tmp->core_set_error_debug = OSSL_FUNC_core_set_error_debug(iterator);
                break;
            case OSSL_FUNC_CORE_VSET_ERROR:
                err_handle_tmp->core_vset_error = OSSL_FUNC_core_vset_error(iterator); 
        }
    }

    *err_handle = err_handle_tmp;

    // OK
    return 1;
}

void yaopo_error_free(struct yaopo_err_handle* err_handle)
{
    if (err_handle != NULL)
    {
        free(err_handle);
    }
}
