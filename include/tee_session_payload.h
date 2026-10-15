/*
 * tee_session_payload.h — wire format for teesessiond's local control
 * socket.
 *
 * SCOPE: this struct carries requests between an arbitrary local process
 * and teesessiond, which forwards them into a Trusted Application (TA)
 * you own and have signed for your own TEE environment (OP-TEE, or a PSP
 * TA you have build/signing rights for). It is generic session plumbing.
 *
 * teesessiond never talks to a browser's Content Decryption Module and
 * has no knowledge of any DRM vendor's wire protocol. Do not repurpose
 * TEESESSIOND_EXAMPLE_TA_UUID below as a stand-in for a real DRM vendor's
 * TA UUID — it is a placeholder for whatever TA you build.
 */

#ifndef TEE_SESSION_PAYLOAD_H
#define TEE_SESSION_PAYLOAD_H

#include <stdint.h>

#define TEE_SESSION_PAYLOAD_MAGIC   0x53455354u /* "TSES" */
#define TEE_SESSION_MAX_PAYLOAD     4096u        /* TEE_MAX_ARG_SIZE headroom */
#define TEE_SESSION_CTL_SOCK_PATH   "/run/teesessiond/ctl.sock"

/*
 * Example TA UUID. This MUST be replaced with the UUID of a TA you built
 * and signed yourself (e.g. via OP-TEE's devkit, or an AMD-TEE TA you have
 * signing rights for). teesessiond will simply fail TEE_IOC_OPEN_SESSION
 * against any TEE implementation that hasn't loaded a TA with this UUID.
 */
#define TEESESSIOND_EXAMPLE_TA_UUID { \
    0x00,0x01,0x02,0x03, 0x04,0x05, 0x06,0x07, \
    0x08,0x09, 0x0a,0x0b,0x0c,0x0d,0x0e,0x0f }

/* Opcodes understood by the example TA. Extend for your own TA's ABI. */
typedef enum {
    TEE_OP_PING          = 0, /* round-trip liveness check */
    TEE_OP_GET_STATUS    = 1, /* query TA/session state */
    TEE_OP_GENERATE_KEY  = 2, /* ask the TA to derive/store a key in-enclave */
    TEE_OP_WRAP_BUFFER   = 3, /* seal in_buf -> out_buf using an in-TA key */
    TEE_OP_UNWRAP_BUFFER = 4, /* unseal in_buf -> out_buf using an in-TA key */
} tee_session_opcode_t;

/* Status codes returned to the caller over the control socket. */
typedef enum {
    TEE_SESSION_STATUS_OK            = 0,
    TEE_SESSION_STATUS_BAD_REQUEST   = 1,
    TEE_SESSION_STATUS_TA_ERROR      = 2,  /* see teec_ret/teec_origin */
    TEE_SESSION_STATUS_NO_SESSION    = 3,
    TEE_SESSION_STATUS_PAYLOAD_TOO_BIG = 4,
} tee_session_status_t;

/*
 * Fixed-size request/response record exchanged verbatim over
 * TEE_SESSION_CTL_SOCK_PATH. Kept flat and fixed-size on purpose: no
 * pointers, no variable-length trailers, so it can be read() in one shot
 * and is trivial to validate before anything touches the TEE ioctl path.
 */
typedef struct {
    uint32_t magic;             /* must equal TEE_SESSION_PAYLOAD_MAGIC */
    uint32_t opcode;            /* tee_session_opcode_t */
    uint32_t in_len;            /* valid bytes in in_buf, <= TEE_SESSION_MAX_PAYLOAD */
    uint32_t out_len;           /* in: capacity caller allows for out_buf
                                  * out: actual bytes written by the TA */
    uint32_t status;            /* tee_session_status_t, out only */
    uint32_t teec_ret;          /* raw TA/driver return code, out only */
    uint32_t teec_origin;       /* GP TEE error origin, out only */
    uint32_t _reserved;         /* keep struct size a multiple of 8 */
    uint8_t  in_buf[TEE_SESSION_MAX_PAYLOAD];
    uint8_t  out_buf[TEE_SESSION_MAX_PAYLOAD];
} tee_session_payload_t;

#endif /* TEE_SESSION_PAYLOAD_H */
