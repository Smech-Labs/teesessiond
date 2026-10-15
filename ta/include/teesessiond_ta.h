/*
 * teesessiond_ta.h — shared constants between teesessiond (REE/host, see
 * ../../src/teesessiond.c) and this TA. No shared build-time header
 * crosses the REE/TEE boundary in the OP-TEE devkit model, so these
 * values are duplicated by hand against
 * ../../include/tee_session_payload.h's tee_session_opcode_t. Keep them
 * numerically identical if either side changes.
 */

#ifndef TEESESSIOND_TA_H
#define TEESESSIOND_TA_H

#define TA_TEESESSIOND_UUID { 0x00010203, 0x0405, 0x0607, \
    { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f } }

/* Must match tee_session_opcode_t in ../../include/tee_session_payload.h */
#define CMD_PING            0
#define CMD_GET_STATUS      1
#define CMD_GENERATE_KEY    2
#define CMD_WRAP_BUFFER     3
#define CMD_UNWRAP_BUFFER   4

#endif /* TEESESSIOND_TA_H */
