#include <openssl/core_dispatch.h>

struct yaopo_err_handle 
{
  const OSSL_CORE_HANDLE *core;
  OSSL_FUNC_core_new_error_fn *core_new_error;
  OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
  OSSL_FUNC_core_vset_error_fn *core_vset_error;
};
