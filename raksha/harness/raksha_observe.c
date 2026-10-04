/*
 * raksha_observe.c — B12 behavioural observation shim (LD_PRELOAD), the observing sibling of
 * raksha_interpose.c.
 *
 * For each file open, socket connect and process spawn the target makes, one tab-separated record
 * is appended to the log named by $RAKSHA_OBSERVE_LOG:
 *
 *     open\t<path>\t<r|w>        connect\t<ip:port | unix:path>        exec\t<path or command>
 *
 * Files are opened for real (a target must read its own data to behave normally). connect() and
 * the exec family are recorded and then NOT performed: connect returns -1/ECONNREFUSED and an exec
 * ends the process with status 98. Observation must never become the attack it is watching for.
 *
 * The log is written with raw syscalls (no stdio, no allocation) so the wrappers never re-enter
 * themselves. Build: gcc -shared -fPIC -O2 -o raksha_observe.so raksha_observe.c -ldl
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static int raksha_log_fd = -2;

static int raksha_fd(void) {
    if (raksha_log_fd == -2) {
        const char *p = getenv("RAKSHA_OBSERVE_LOG");
        raksha_log_fd = p && p[0]
            ? (int)syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600)
            : -1;
    }
    return raksha_log_fd;
}

static void raksha_record(const char *kind, const char *what, const char *mode) {
    int fd = raksha_fd();
    if (fd < 0) return;
    char line[1100];
    size_t n = 0;
    #define PUT(s) do { const char *_p = (s); while (_p && *_p && n + 2 < sizeof(line)) { \
        char _c = *_p++; line[n++] = (_c == '\t' || _c == '\n') ? ' ' : _c; } } while (0)
    PUT(kind); line[n++] = '\t'; PUT(what ? what : "?");
    if (mode) { line[n++] = '\t'; PUT(mode); }
    #undef PUT
    line[n++] = '\n';
    syscall(SYS_write, fd, line, n);
}

static const char *raksha_mode(int flags) {
    return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) ? "w" : "r";
}

/* ------------------------------------------------------------------------------ file opens */

#define REAL(name) static __typeof__(name) *real_##name; \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

int open(const char *path, int flags, ...) {
    REAL(open);
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap); }
    raksha_record("open", path, raksha_mode(flags));
    return real_open(path, flags, m);
}

int open64(const char *path, int flags, ...) {
    REAL(open64);
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap); }
    raksha_record("open", path, raksha_mode(flags));
    return real_open64(path, flags, m);
}

int openat(int dirfd, const char *path, int flags, ...) {
    REAL(openat);
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap); }
    raksha_record("open", path, raksha_mode(flags));
    return real_openat(dirfd, path, flags, m);
}

int openat64(int dirfd, const char *path, int flags, ...) {
    REAL(openat64);
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = (mode_t)va_arg(ap, int); va_end(ap); }
    raksha_record("open", path, raksha_mode(flags));
    return real_openat64(dirfd, path, flags, m);
}

FILE *fopen(const char *path, const char *mode) {
    REAL(fopen);
    raksha_record("open", path, (mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'))) ? "w" : "r");
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    REAL(fopen64);
    raksha_record("open", path, (mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'))) ? "w" : "r");
    return real_fopen64(path, mode);
}

/* ------------------------------------------------------------- network: recorded, not made */

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    char buf[200] = "?";
    (void)fd; (void)len;
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        char ip[64]; inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        snprintf(buf, sizeof(buf), "%s:%u", ip, (unsigned)ntohs(a->sin_port));
    } else if (addr && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        char ip[80]; inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
        snprintf(buf, sizeof(buf), "[%s]:%u", ip, (unsigned)ntohs(a->sin6_port));
    } else if (addr && addr->sa_family == AF_UNIX) {
        snprintf(buf, sizeof(buf), "unix:%s", ((const struct sockaddr_un *)addr)->sun_path);
    }
    raksha_record("connect", buf, NULL);
    errno = ECONNREFUSED;
    return -1;
}

/* ------------------------------------------------------- processes: recorded, never spawned */

static void raksha_exec(const char *what) __attribute__((noreturn));
static void raksha_exec(const char *what) {
    raksha_record("exec", what, NULL);
    _exit(98);
}

int system(const char *cmd) { raksha_exec(cmd); }
FILE *popen(const char *cmd, const char *type) { (void)type; raksha_exec(cmd); }
int execve(const char *p, char *const a[], char *const e[]) { (void)a; (void)e; raksha_exec(p); }
int execv(const char *p, char *const a[]) { (void)a; raksha_exec(p); }
int execvp(const char *f, char *const a[]) { (void)a; raksha_exec(f); }
int execl(const char *p, const char *a, ...) { (void)a; raksha_exec(p); }
int execlp(const char *f, const char *a, ...) { (void)a; raksha_exec(f); }
