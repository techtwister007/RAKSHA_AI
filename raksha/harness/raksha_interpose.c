/*
 * raksha_interpose.c — B11 sink interposition for COMPILED targets with no source.
 *
 * The sink-invariant idea behind raksha/harness/sinkguard.py (abort at a dangerous operation
 * instead of hoping for a crash) extended to a native binary we cannot recompile. This is a small
 * LD_PRELOAD shim: the dynamic linker resolves the target's calls to the libc entry points a
 * defender treats as off-limits for an untrusted input — system / execve / execl / execlp / execv /
 * execvp / popen, and optionally connect — to the wrappers below.
 *
 * WHAT IT DOES, precisely: when the target under test reaches one of these sinks, the wrapper writes
 * a detectable banner to stderr
 *
 *     === RAKSHA INTERPOSE: <sink> ===
 *     RAKSHA INTERPOSE: blocked sink '<sink>' before it executed; ...
 *
 * and exits non-zero (99) *BEFORE* the real call runs. It BLOCKS — it does NOT perform the
 * operation. We are feeding adversarial input to the target; we will not actually spawn a shell or
 * open a socket to prove the sink was reachable. Reaching the sink at all during an untrusted-input
 * run is the detection. (InterposeOracle in raksha/harness/interpose.py parses the banner into one
 * CWE-78 / CWE-918 finding; a clean run never prints the banner, so the oracle is silent.)
 *
 * exec-family/system/popen are blocked UNCONDITIONALLY — blocking them is the whole point. connect() is
 * different: ordinary programs connect for benign reasons, so it is interposed only when
 * RAKSHA_INTERPOSE_CONNECT=1 is set in the environment; otherwise connect() is forwarded to the real
 * libc symbol via dlsym(RTLD_NEXT, ...) and nothing changes. The shim touches only the process it is
 * preloaded into — no global state, no files written, no network.
 *
 * Build:  gcc -shared -fPIC -O2 -o raksha_interpose.so raksha_interpose.c -ldl
 * Use:    LD_PRELOAD=/path/to/raksha_interpose.so <target-binary> < input
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Append a sanitised, bounded excerpt of the attempted command/argument to the banner. Only
 * printable ASCII is copied (control characters, quotes and newlines are replaced with '.') so the
 * banner stays single-line and cannot be used to forge a second banner. */
static size_t raksha_sanitise(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    if (!src || cap == 0) return 0;
    for (; src[i] != '\0' && i + 1 < cap && i < 160; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\n') ? (char)c : '.';
    }
    dst[i] = '\0';
    return i;
}

/* Write the banner directly with write(2) + _exit(2): async-signal-safe, no stdio buffering and no
 * allocation, because we may be interposing at an awkward moment and must not re-enter libc. */
static void raksha_block(const char *sink, const char *arg) __attribute__((noreturn));
static void raksha_block(const char *sink, const char *arg) {
    char excerpt[192];
    char line[512];
    size_t n = 0;

    excerpt[0] = '\0';
    if (arg) raksha_sanitise(excerpt, sizeof(excerpt), arg);

    /* Hand-rolled, allocation-free concatenation so this is safe inside an interposer. */
    #define APPEND(s) do { const char *_p = (s); while (*_p && n + 1 < sizeof(line)) line[n++] = *_p++; } while (0)
    APPEND("=== RAKSHA INTERPOSE: ");
    APPEND(sink);
    APPEND(" ===\n");
    APPEND("RAKSHA INTERPOSE: blocked sink '");
    APPEND(sink);
    APPEND("' before it executed");
    if (excerpt[0]) { APPEND("; arg=\""); APPEND(excerpt); APPEND("\""); }
    APPEND("\n");
    #undef APPEND

    { ssize_t w = write(2, line, n); (void)w; }
    _exit(99);
}

/* ------------------------------------------------------------------ shell / exec / popen sinks */

int system(const char *command) {
    raksha_block("system", command);
}

FILE *popen(const char *command, const char *type) {
    (void)type;
    raksha_block("popen", command);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    (void)argv; (void)envp;
    raksha_block("execve", path);
}

int execv(const char *path, char *const argv[]) {
    (void)argv;
    raksha_block("execv", path);
}

int execvp(const char *file, char *const argv[]) {
    (void)argv;
    raksha_block("execvp", file);
}

int execl(const char *path, const char *arg, ...) {
    (void)arg;
    raksha_block("execl", path);
}

int execlp(const char *file, const char *arg, ...) {
    (void)arg;
    raksha_block("execlp", file);
}

/* ------------------------------------------------------------------------- optional network sink */

static int raksha_connect_enabled(void) {
    const char *v = getenv("RAKSHA_INTERPOSE_CONNECT");
    return v && v[0] && strcmp(v, "0") != 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (raksha_connect_enabled()) {
        raksha_block("connect", NULL);
    }
    /* Disabled: forward to the real connect so benign networking is unaffected. */
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_connect) {
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    }
    if (!real_connect) return -1;
    return real_connect(sockfd, addr, addrlen);
}
