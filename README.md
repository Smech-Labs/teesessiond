# teesessiond

A standalone userspace client/daemon for the Linux kernel's generic TEE
(Trusted Execution Environment) subsystem (`/dev/teeN`,
[`linux/tee.h`](https://www.kernel.org/doc/html/latest/driver-api/tee.html)),
plus an example [OP-TEE](https://optee.readthedocs.io/) Trusted Application
(TA) to pair it with.

## What this is

`teesessiond` opens a session against a TA using the raw
`TEE_IOC_OPEN_SESSION`/`TEE_IOC_INVOKE` ioctls and exposes that session to
local processes over a Unix-domain control socket. It contains no
vendor-specific code — it works unmodified against any backend the kernel's
generic TEE subsystem supports (OP-TEE/TrustZone, AMD-TEE/PSP, TS-TEE,
QTEE), because that's precisely what the generic subsystem is for.

The companion TA (`ta/teesessiond_ta.c`) demonstrates the one property that
actually matters for a "hardware-backed" trust claim: it generates an AES
key with `TEE_GenerateKey()` that lives only in that session's secure-world
object and is never copied into a parameter the host can read. Only
ciphertext (via AES-GCM wrap/unwrap) ever crosses back out.

## What this is not

This project does not talk to a browser, a Content Decryption Module, or
any DRM vendor's protocol, and makes no attempt to satisfy a DRM vendor's
hardware-attestation/provisioning check. A real TEE session only succeeds
against a TA that the TEE's actual signing authority (OP-TEE's own devkit
for a TA you built, or AMD for an AMD-signed TA) has already vouched for —
this project doesn't and can't change who that authority is or what it has
agreed to trust.

## Layout

```
include/   tee_session_payload.h  — host<->daemon control-socket wire format
src/       teesessiond.c          — the daemon
systemd/   teesessiond.service    — hardened unit (DynamicUser, DeviceAllow
                                    scoped to one node, empty capability set)
ta/        teesessiond_ta.c       — example OP-TEE TA (AES-GCM wrap/unwrap)
           Makefile, sub.mk       — standard optee_examples-style devkit build
```

## Building the daemon

```sh
cd src
gcc -Wall -Wextra -O2 -std=gnu11 -I../include -o teesessiond teesessiond.c
```

Requires `linux/tee.h` (ships with `kernel-headers`/`linux-libc-dev`). No
other dependencies.

## Building the TA

Needs an [OP-TEE](https://optee.readthedocs.io/) devkit build
(`TA_DEV_KIT_DIR`), e.g. from `optee_os`'s QEMUv8 target:

```sh
cd ta
make TA_DEV_KIT_DIR=<optee_os>/out/arm/export-ta_arm64 \
     CROSS_COMPILE_ta=aarch64-linux-gnu-
```

`TEESESSIOND_EXAMPLE_TA_UUID` in `include/tee_session_payload.h` (and its
copy in `ta/include/teesessiond_ta.h`) is a placeholder. Replace it with
the UUID of a TA you build and sign yourself before using this for
anything beyond the bundled example.

## Status

The daemon compiles clean (`-Wall -Wextra`, zero warnings) against current
kernel UAPI headers and correctly detects when no TEE driver is bound. The
TA is written to the GlobalPlatform TEE Internal API but has not yet been
built against a real OP-TEE devkit — do that yourself before relying on it.

## License

MIT, see [LICENSE](LICENSE).
