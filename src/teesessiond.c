/*
 * teesessiond.c — generic GP TEE Client daemon.
 *
 * Opens a session against a Trusted Application (TA) behind the Linux
 * kernel's generic TEE subsystem (/dev/teeN, see Documentation/tee.txt and
 * uapi/linux/tee.h) using the raw TEE_IOC_* ioctls, and exposes that
 * session to local processes over a Unix-domain control socket using the
 * fixed record format in tee_session_payload.h.
 *
 * SCOPE: this is standalone TEE client plumbing. It does not talk to any
 * browser, any Content Decryption Module, or any DRM vendor's protocol.
 * It will only ever succeed against a TEE implementation that has already
 * loaded a TA matching TEESESSIOND_EXAMPLE_TA_UUID (or whatever UUID you
 * put in its place) — i.e. a TA *you* built and *your* TEE environment
 * trusts. It has no path to, and makes no attempt at, satisfying a DRM
 * vendor's hardware attestation/provisioning check for a device that
 * vendor hasn't provisioned.
 *
 * Build:  gcc -Wall -Wextra -O2 -o teesessiond teesessiond.c -I../include
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/tee.h>

#include "tee_session_payload.h"

#ifndef TEE_IOCTL_LOGIN_PUBLIC
#define TEE_IOCTL_LOGIN_PUBLIC 0
#endif

static const char *DEFAULT_TEE_DEV = "/dev/tee0";
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void logmsg(int prio, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio, fmt, ap);
    va_end(ap);

    /* also echo to stderr for interactive/dev use */
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ---- GP TEEC well-known return codes (GlobalPlatform TEE Client API) --- */

static const char *teec_ret_str(uint32_t ret)
{
    switch (ret) {
    case 0x00000000u: return "TEEC_SUCCESS";
    case 0xFFFF0000u: return "TEEC_ERROR_GENERIC";
    case 0xFFFF0001u: return "TEEC_ERROR_ACCESS_DENIED";
    case 0xFFFF0002u: return "TEEC_ERROR_CANCEL";
    case 0xFFFF0003u: return "TEEC_ERROR_ACCESS_CONFLICT";
    case 0xFFFF0004u: return "TEEC_ERROR_EXCESS_DATA";
    case 0xFFFF0005u: return "TEEC_ERROR_BAD_FORMAT";
    case 0xFFFF0006u: return "TEEC_ERROR_BAD_PARAMETERS";
    case 0xFFFF0007u: return "TEEC_ERROR_BAD_STATE";
    case 0xFFFF0008u: return "TEEC_ERROR_ITEM_NOT_FOUND";
    case 0xFFFF0009u: return "TEEC_ERROR_NOT_IMPLEMENTED";
    case 0xFFFF000Au: return "TEEC_ERROR_NOT_SUPPORTED";
    case 0xFFFF000Bu: return "TEEC_ERROR_NO_DATA";
    case 0xFFFF000Cu: return "TEEC_ERROR_OUT_OF_MEMORY";
    case 0xFFFF000Du: return "TEEC_ERROR_BUSY";
    case 0xFFFF000Eu: return "TEEC_ERROR_COMMUNICATION";
    case 0xFFFF000Fu: return "TEEC_ERROR_SECURITY";
    case 0xFFFF0010u: return "TEEC_ERROR_SHORT_BUFFER";
    case 0xFFFF3024u: return "TEEC_ERROR_TARGET_DEAD";
    default:          return "TEEC_ERROR_(unknown)";
    }
}

static const char *teec_origin_str(uint32_t origin)
{
    switch (origin) {
    case 1: return "TEEC_ORIGIN_API";
    case 2: return "TEEC_ORIGIN_COMMS";
    case 3: return "TEEC_ORIGIN_TEE";
    case 4: return "TEEC_ORIGIN_TRUSTED_APP";
    default: return "TEEC_ORIGIN_(unknown)";
    }
}

static const char *impl_id_str(uint32_t id)
{
    switch (id) {
    case TEE_IMPL_ID_OPTEE:  return "OP-TEE";
    case TEE_IMPL_ID_AMDTEE: return "AMD-TEE (PSP)";
    case TEE_IMPL_ID_TSTEE:  return "TS-TEE";
    case TEE_IMPL_ID_QTEE:   return "QTEE";
    default:                 return "unknown";
    }
}

/* ------------------------------- TEE client ------------------------------ */

typedef struct {
    int      fd;        /* /dev/teeN file descriptor */
    uint32_t session;    /* open session id, valid when session_open */
    bool     session_open;
} tee_client_t;

/*
 * Opens the TEE device node, retrying on EBUSY (enclave/driver momentarily
 * locked by another privileged client) with capped exponential backoff.
 * EACCES/EPERM and ENOENT are treated as non-retryable: they mean "this
 * driver/node isn't usable here", not "try again".
 */
static int tee_open_device(const char *path)
{
    const int max_attempts = 5;
    int delay_ms = 100;

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0)
            return fd;

        switch (errno) {
        case EBUSY:
            logmsg(LOG_WARNING,
                   "%s busy (attempt %d/%d), backing off %dms",
                   path, attempt, max_attempts, delay_ms);
            usleep((useconds_t)delay_ms * 1000);
            delay_ms = (delay_ms * 2 > 2000) ? 2000 : delay_ms * 2;
            continue;
        case EACCES:
        case EPERM:
            logmsg(LOG_ERR,
                   "%s: permission denied -- check device-node ownership "
                   "or systemd DeviceAllow policy; not retrying", path);
            return -1;
        case ENOENT:
            logmsg(LOG_ERR,
                   "%s does not exist -- no TEE driver (amdtee/optee) is "
                   "currently bound on this kernel; not retrying", path);
            return -1;
        default:
            logmsg(LOG_ERR, "open(%s) failed: %s", path, strerror(errno));
            return -1;
        }
    }

    logmsg(LOG_ERR, "%s still busy after %d attempts, giving up",
           path, max_attempts);
    return -1;
}

static bool tee_query_version(int fd)
{
    struct tee_ioctl_version_data vers = {0};

    if (ioctl(fd, TEE_IOC_VERSION, &vers) < 0) {
        logmsg(LOG_ERR, "TEE_IOC_VERSION failed: %s", strerror(errno));
        return false;
    }

    logmsg(LOG_INFO,
           "TEE implementation: %s (impl_id=%u impl_caps=0x%x gen_caps=0x%x)",
           impl_id_str(vers.impl_id), vers.impl_id, vers.impl_caps,
           vers.gen_caps);
    return true;
}

/*
 * Opens a session with the TA identified by `uuid`. On failure, decodes and
 * logs the GP TEEC ret/ret_origin so the caller can tell "TA not present"
 * from "TA present but refused us" from "driver/comms problem".
 */
static bool tee_open_session(tee_client_t *tc, const uint8_t uuid[TEE_IOCTL_UUID_LEN])
{
    struct tee_ioctl_open_session_arg arg = {0};
    struct tee_ioctl_buf_data buf = {0};

    memcpy(arg.uuid, uuid, TEE_IOCTL_UUID_LEN);
    arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
    arg.num_params = 0; /* this example TA takes no open-time params */

    buf.buf_ptr = (uintptr_t)&arg;
    buf.buf_len = sizeof(arg); /* + 0 * sizeof(struct tee_ioctl_param) */

    if (ioctl(tc->fd, TEE_IOC_OPEN_SESSION, &buf) < 0) {
        logmsg(LOG_ERR, "TEE_IOC_OPEN_SESSION ioctl failed: %s",
               strerror(errno));
        return false;
    }

    if (arg.ret != 0) {
        logmsg(LOG_ERR,
               "TA refused session: ret=0x%08x (%s) origin=%u (%s)",
               arg.ret, teec_ret_str(arg.ret),
               arg.ret_origin, teec_origin_str(arg.ret_origin));
        return false;
    }

    tc->session = arg.session;
    tc->session_open = true;
    logmsg(LOG_INFO, "opened TEE session %u", tc->session);
    return true;
}

static void tee_close_session(tee_client_t *tc)
{
    if (!tc->session_open)
        return;

    struct tee_ioctl_close_session_arg arg = { .session = tc->session };
    if (ioctl(tc->fd, TEE_IOC_CLOSE_SESSION, &arg) < 0)
        logmsg(LOG_WARNING, "TEE_IOC_CLOSE_SESSION failed: %s",
               strerror(errno));

    tc->session_open = false;
}

/*
 * Invokes `func` in the TA with up to two UBUF parameters: an input buffer
 * and an output buffer. UBUF params reference caller memory directly (no
 * TEE_IOC_SHM_ALLOC dance needed) -- the simplest correct choice for a
 * one-shot request/response daemon like this one.
 */
static bool tee_invoke(tee_client_t *tc, uint32_t func,
                        const uint8_t *in_buf, uint32_t in_len,
                        uint8_t *out_buf, uint32_t *out_len /* in/out */,
                        uint32_t *teec_ret, uint32_t *teec_origin)
{
    struct {
        struct tee_ioctl_invoke_arg arg;
        struct tee_ioctl_param params[2];
    } req = {0};
    struct tee_ioctl_buf_data buf = {0};

    if (!tc->session_open) {
        logmsg(LOG_ERR, "tee_invoke called with no open session");
        return false;
    }

    req.arg.func = func;
    req.arg.session = tc->session;
    req.arg.num_params = 2;

    req.params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_INPUT;
    req.params[0].a = (uint64_t)(uintptr_t)in_buf;
    req.params[0].b = in_len;

    req.params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT;
    req.params[1].a = (uint64_t)(uintptr_t)out_buf;
    req.params[1].b = *out_len; /* capacity in, actual bytes out */

    buf.buf_ptr = (uintptr_t)&req;
    buf.buf_len = sizeof(req);

    if (ioctl(tc->fd, TEE_IOC_INVOKE, &buf) < 0) {
        logmsg(LOG_ERR, "TEE_IOC_INVOKE ioctl failed: %s", strerror(errno));
        return false;
    }

    *teec_ret = req.arg.ret;
    *teec_origin = req.arg.ret_origin;
    *out_len = (uint32_t)req.params[1].b;

    if (req.arg.ret != 0) {
        logmsg(LOG_WARNING,
               "TA invoke func=%u returned ret=0x%08x (%s) origin=%u (%s)",
               func, req.arg.ret, teec_ret_str(req.arg.ret),
               req.arg.ret_origin, teec_origin_str(req.arg.ret_origin));
        return false;
    }

    return true;
}

/* ------------------------------ control socket ---------------------------- */

static int open_control_socket(const char *path)
{
    struct sockaddr_un addr = {0};
    int fd;

    unlink(path); /* stale socket from a previous run */

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        logmsg(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg(LOG_ERR, "bind(%s) failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    /* local control socket: owner (and group, if systemd sets one up) only */
    chmod(path, 0660);

    if (listen(fd, 8) < 0) {
        logmsg(LOG_ERR, "listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (char *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break; /* peer closed early */
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static void handle_client(tee_client_t *tc, int cfd)
{
    tee_session_payload_t req;

    ssize_t n = read_full(cfd, &req, sizeof(req));
    if (n != (ssize_t)sizeof(req)) {
        logmsg(LOG_WARNING, "short/failed read from client (%zd bytes)", n);
        close(cfd);
        return;
    }

    if (req.magic != TEE_SESSION_PAYLOAD_MAGIC) {
        logmsg(LOG_WARNING, "bad magic 0x%08x from client", req.magic);
        req.status = TEE_SESSION_STATUS_BAD_REQUEST;
        req.out_len = 0;
        write_full(cfd, &req, sizeof(req));
        close(cfd);
        return;
    }

    if (req.in_len > TEE_SESSION_MAX_PAYLOAD || req.out_len > TEE_SESSION_MAX_PAYLOAD) {
        req.status = TEE_SESSION_STATUS_PAYLOAD_TOO_BIG;
        req.out_len = 0;
        write_full(cfd, &req, sizeof(req));
        close(cfd);
        return;
    }

    if (!tc->session_open) {
        req.status = TEE_SESSION_STATUS_NO_SESSION;
        req.out_len = 0;
        write_full(cfd, &req, sizeof(req));
        close(cfd);
        return;
    }

    uint32_t out_cap = req.out_len; /* caller-declared capacity */
    uint32_t teec_ret = 0, teec_origin = 0;

    bool ok = tee_invoke(tc, req.opcode,
                         req.in_buf, req.in_len,
                         req.out_buf, &out_cap,
                         &teec_ret, &teec_origin);

    req.out_len = ok ? out_cap : 0;
    req.status = ok ? TEE_SESSION_STATUS_OK : TEE_SESSION_STATUS_TA_ERROR;
    req.teec_ret = teec_ret;
    req.teec_origin = teec_origin;

    write_full(cfd, &req, sizeof(req));
    close(cfd);
}

/* ---------------------------------- main ---------------------------------- */

int main(int argc, char **argv)
{
    const char *dev_path = (argc > 1) ? argv[1] : DEFAULT_TEE_DEV;
    const uint8_t ta_uuid[TEE_IOCTL_UUID_LEN] = TEESESSIOND_EXAMPLE_TA_UUID;
    tee_client_t tc = {0};
    int ctl_fd;

    openlog("teesessiond", LOG_PID | LOG_PERROR, LOG_DAEMON);

    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    logmsg(LOG_INFO, "teesessiond starting, TEE device=%s", dev_path);

    tc.fd = tee_open_device(dev_path);
    if (tc.fd < 0) {
        logmsg(LOG_ERR, "could not open TEE device, exiting");
        return 1;
    }

    if (!tee_query_version(tc.fd)) {
        close(tc.fd);
        return 1;
    }

    if (!tee_open_session(&tc, ta_uuid)) {
        logmsg(LOG_ERR,
               "no session: either no TA with this UUID is loaded in the "
               "TEE, or it refused us. This is expected until you build "
               "and load your own TA -- see include/tee_session_payload.h.");
        close(tc.fd);
        return 1;
    }

    ctl_fd = open_control_socket(TEE_SESSION_CTL_SOCK_PATH);
    if (ctl_fd < 0) {
        tee_close_session(&tc);
        close(tc.fd);
        return 1;
    }

    logmsg(LOG_INFO, "listening on %s", TEE_SESSION_CTL_SOCK_PATH);

    while (!g_stop) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctl_fd, &rfds);

        int r = select(ctl_fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            logmsg(LOG_ERR, "select() failed: %s", strerror(errno));
            break;
        }
        if (r == 0)
            continue; /* timeout, re-check g_stop */

        int cfd = accept4(ctl_fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno != EINTR)
                logmsg(LOG_WARNING, "accept() failed: %s", strerror(errno));
            continue;
        }

        handle_client(&tc, cfd);
    }

    logmsg(LOG_INFO, "shutting down");
    close(ctl_fd);
    unlink(TEE_SESSION_CTL_SOCK_PATH);
    tee_close_session(&tc);
    close(tc.fd);
    closelog();
    return 0;
}
