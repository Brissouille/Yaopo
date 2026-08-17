#ifndef TEE_INTERFACE_H

#include "inttypes.h"

#define TEE_INTERFACE_H

#define TEE_SESSION_MAX 8

struct tee_ctx;

int tee_init(struct tee_ctx* tee_ctx);

void tee_free(struct tee_ctx* tee_ctx);

int tee_open_session(struct tee_ctx* tee_ctx);

int tee_close_session(struct tee_ctx* tee_ctx);

int tee_command(struct tee_ctx* tee_ctx, uint32_t commandID, void* parameters);

int tee_init_parameters(void* parameters);

#endif // TEE_INTERFACE_H
