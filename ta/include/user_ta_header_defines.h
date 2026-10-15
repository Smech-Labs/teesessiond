/*
 * user_ta_header_defines.h — OP-TEE TA property header.
 *
 * TA_UUID here is the byte-for-byte equivalent of
 * TEESESSIOND_EXAMPLE_TA_UUID in ../../include/tee_session_payload.h:
 * time_low=00010203, time_mid=0405, time_hi_and_version=0607,
 * clock_seq+node=08090a0b0c0d0e0f. Keep these two in sync by hand if you
 * ever change the UUID -- there's no shared header across the REE/TEE
 * boundary, by convention of how OP-TEE examples are structured.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <teesessiond_ta.h>

#define TA_UUID TA_TEESESSIOND_UUID

#define TA_FLAGS            (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE | \
                              TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE        (2 * 1024)
#define TA_DATA_SIZE         (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
      "teesessiond example TA (AES-GCM wrap/unwrap demo)" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /* USER_TA_HEADER_DEFINES_H */
