/* c-binsink — a compiled demo target for B11 sink interposition.
 *
 * It ships only as source here, but the defender's scenario is a BINARY with no source: RAKSHA runs
 * it under the raksha_interpose.so LD_PRELOAD shim and treats any reach of a shell sink as a
 * controlled abort. There is no fuzz harness and no bound-checking cleverness — the point is purely
 * to exercise the interposer.
 *
 * Behaviour, driven by stdin:
 *   - first byte == 0x42 ('B', the "magic" / attacker-influenced trigger): shell out via system()
 *     to `touch` a sentinel file whose path is taken from $RAKSHA_BINSINK_SENTINEL (default
 *     "raksha_binsink_sentinel"). This is the command-injection-style sink.
 *   - any other first byte: benign — print "benign" and exit 0, touching no sink.
 *
 * Under the shim the system() call is BLOCKED before it runs, so the sentinel is never created: that
 * absent file is how the test proves the operation was blocked, not merely detected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char buf[256];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) {
        printf("empty\n");
        return 0;
    }
    buf[n] = '\0';

    if (buf[0] == 0x42) {
        const char *sentinel = getenv("RAKSHA_BINSINK_SENTINEL");
        if (!sentinel || !sentinel[0]) sentinel = "raksha_binsink_sentinel";
        char cmd[512];
        /* attacker-influenced data reaching a shell sink */
        snprintf(cmd, sizeof(cmd), "touch '%s'", sentinel);
        int rc = system(cmd);   (void)rc; /* <- controlled sink: the shim aborts here, before touch runs */
        printf("executed\n");
        return 0;
    }

    printf("benign\n");
    return 0;
}
