# Standard optee_examples-style TA makefile. Build with:
#   make -C ta TA_DEV_KIT_DIR=<path-to-optee_os>/out/arm/export-ta_arm64 \
#              CROSS_COMPILE_ta=aarch64-linux-gnu-
#
# Output filename must equal the UUID in string form (see
# include/teesessiond_ta.h's TA_TEESESSIOND_UUID): the devkit uses it as
# the .ta file's name, which is how the OP-TEE supplicant/driver looks it
# up by UUID at TEE_IOC_OPEN_SESSION time.

CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY = 00010203-0405-0607-0809-0a0b0c0d0e0f

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
