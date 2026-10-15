/*
 * teesessiond_ta.c — example OP-TEE Trusted Application paired with
 * teesessiond (../src/teesessiond.c).
 *
 * Demonstrates the one property that matters for any "hardware-backed"
 * trust claim: TEE_GenerateKey() produces a TEE_ObjectHandle that lives
 * only inside this TA's secure-world session state. It is never copied
 * into a TEE_Param, so it never crosses back into the REE/host daemon.
 * Only ciphertext (via CMD_WRAP_BUFFER/CMD_UNWRAP_BUFFER) ever leaves.
 *
 * This TA has NOT been built against the real OP-TEE devkit in this
 * session (no TA_DEV_KIT_DIR available here) -- only hand-checked against
 * the GlobalPlatform TEE Internal API signatures. Build and test it
 * yourself with the optee_os/optee_examples toolchain before trusting it
 * further.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/teesessiond_ta.h"

#define AES_KEY_BITS   256
#define GCM_NONCE_LEN  12
#define GCM_TAG_LEN    16

struct session_ctx {
    TEE_ObjectHandle key; /* TEE_HANDLE_NULL until CMD_GENERATE_KEY runs */
};

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                     TEE_Param params[4],
                                     void **sess_ctx)
{
    struct session_ctx *ctx;

    (void)param_types;
    (void)params;

    ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx)
        return TEE_ERROR_OUT_OF_MEMORY;

    ctx->key = TEE_HANDLE_NULL;
    *sess_ctx = ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct session_ctx *ctx = sess_ctx;

    if (ctx->key != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->key);
    TEE_Free(ctx);
}

static TEE_Result cmd_ping(void)
{
    return TEE_SUCCESS;
}

/* Writes one byte to params[1]: 1 if a key has been generated, else 0. */
static TEE_Result cmd_get_status(struct session_ctx *ctx, uint32_t pt,
                                  TEE_Param params[4])
{
    uint8_t status;

    if (TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size < 1) {
        params[1].memref.size = 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    status = (ctx->key != TEE_HANDLE_NULL) ? 1 : 0;
    TEE_MemMove(params[1].memref.buffer, &status, 1);
    params[1].memref.size = 1;
    return TEE_SUCCESS;
}

/*
 * Generates a fresh 256-bit AES key inside the TEE and stores it in this
 * session's TEE_ObjectHandle. Replaces any previous key. The raw key
 * material is never readable from outside TEE_* Crypto API calls that
 * themselves run inside the secure world.
 */
static TEE_Result cmd_generate_key(struct session_ctx *ctx)
{
    TEE_Result res;

    if (ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BITS, &ctx->key);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_GenerateKey(ctx->key, AES_KEY_BITS, NULL, 0);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    return res;
}

/*
 * params[0] = MEMREF_INPUT  plaintext
 * params[1] = MEMREF_OUTPUT nonce(12) || ciphertext || tag(16)
 *
 * Note on param types: teesessiond's host-side TEE_IOC_INVOKE call tags
 * these as TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_INPUT/OUTPUT (kernel ioctl
 * values 8/9). The OP-TEE driver copies that user buffer into secure-world
 * shared memory before entry, so by the time it reaches this function via
 * the GP Internal API, param_types reports it as the ordinary
 * TEE_PARAM_TYPE_MEMREF_INPUT/OUTPUT (5/6) checked below. UBUF vs.
 * registered-SHM is purely a client-side choice about how the buffer was
 * handed to the kernel driver; the TA never sees that distinction.
 */
static TEE_Result cmd_wrap_buffer(struct session_ctx *ctx, uint32_t pt,
                                   TEE_Param params[4])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    uint8_t nonce[GCM_NONCE_LEN];
    uint8_t tag[GCM_TAG_LEN];
    uint32_t tag_len = GCM_TAG_LEN;
    uint32_t out_len;
    uint32_t needed;

    if (ctx->key == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE; /* caller must CMD_GENERATE_KEY first */

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    needed = GCM_NONCE_LEN + params[0].memref.size + GCM_TAG_LEN;
    if (params[1].memref.size < needed) {
        params[1].memref.size = needed;
        return TEE_ERROR_SHORT_BUFFER;
    }

    TEE_GenerateRandom(nonce, sizeof(nonce));

    res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT,
                                 AES_KEY_BITS);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, ctx->key);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_AEInit(op, nonce, sizeof(nonce), GCM_TAG_LEN * 8, 0,
                      params[0].memref.size);
    if (res != TEE_SUCCESS)
        goto out;

    out_len = params[1].memref.size - GCM_NONCE_LEN - GCM_TAG_LEN;
    res = TEE_AEEncryptFinal(op, params[0].memref.buffer,
                              params[0].memref.size,
                              (uint8_t *)params[1].memref.buffer +
                                  GCM_NONCE_LEN,
                              &out_len, tag, &tag_len);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_MemMove(params[1].memref.buffer, nonce, GCM_NONCE_LEN);
    TEE_MemMove((uint8_t *)params[1].memref.buffer + GCM_NONCE_LEN + out_len,
                tag, tag_len);
    params[1].memref.size = GCM_NONCE_LEN + out_len + tag_len;

out:
    TEE_FreeOperation(op);
    return res;
}

/*
 * params[0] = MEMREF_INPUT  nonce(12) || ciphertext || tag(16)
 * params[1] = MEMREF_OUTPUT plaintext
 *
 * Returns TEE_ERROR_MAC_INVALID if the tag doesn't verify (wrong key or
 * tampered input) -- GCM is authenticated, so this is a hard failure, not
 * a warning.
 */
static TEE_Result cmd_unwrap_buffer(struct session_ctx *ctx, uint32_t pt,
                                     TEE_Param params[4])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    uint8_t *in;
    uint32_t cipher_len;
    uint32_t out_len;

    if (ctx->key == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < GCM_NONCE_LEN + GCM_TAG_LEN)
        return TEE_ERROR_BAD_PARAMETERS;

    in = params[0].memref.buffer;
    cipher_len = params[0].memref.size - GCM_NONCE_LEN - GCM_TAG_LEN;

    if (params[1].memref.size < cipher_len) {
        params[1].memref.size = cipher_len;
        return TEE_ERROR_SHORT_BUFFER;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT,
                                 AES_KEY_BITS);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, ctx->key);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_AEInit(op, in, GCM_NONCE_LEN, GCM_TAG_LEN * 8, 0, cipher_len);
    if (res != TEE_SUCCESS)
        goto out;

    out_len = params[1].memref.size;
    res = TEE_AEDecryptFinal(op, in + GCM_NONCE_LEN, cipher_len,
                              params[1].memref.buffer, &out_len,
                              in + GCM_NONCE_LEN + cipher_len, GCM_TAG_LEN);
    if (res != TEE_SUCCESS)
        goto out;

    params[1].memref.size = out_len;

out:
    TEE_FreeOperation(op);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                       uint32_t param_types,
                                       TEE_Param params[4])
{
    struct session_ctx *ctx = sess_ctx;

    switch (cmd_id) {
    case CMD_PING:
        return cmd_ping();
    case CMD_GET_STATUS:
        return cmd_get_status(ctx, param_types, params);
    case CMD_GENERATE_KEY:
        return cmd_generate_key(ctx);
    case CMD_WRAP_BUFFER:
        return cmd_wrap_buffer(ctx, param_types, params);
    case CMD_UNWRAP_BUFFER:
        return cmd_unwrap_buffer(ctx, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
