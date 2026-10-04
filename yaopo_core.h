#ifndef YAOPO_CORE_H

#include "inttypes.h"

#define YAOPO_CORE_H

struct yaopo_ctx;

int yaopo_open_cipher_tee_session(struct yaopo_ctx* yc,
                                  uint8_t *key,
                                  size_t keysize,
                                  uint8_t *iv,
                                  size_t iv_size);


#endif // YAOPO_CORE_H
